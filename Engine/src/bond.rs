//! Multipath IP scheduling primitives. Time is monotonic milliseconds supplied
//! by the runtime, allowing deterministic failure/recovery tests without sleeps.
//! Path ACKs measure delivered tunnel bytes, not application-level TCP goodput.
use crate::ReplayWindow;
use anyhow::{Result, ensure};
use serde::Serialize;
use std::collections::{BTreeMap, VecDeque};

pub const BOND_MTU: usize = 1200;
/// Wire IDs support 256 distinct adapter paths per device session. Allocation
/// is dynamic; ordinary multi-adapter Macs do not pay for unused path slots.
pub const MAX_PATHS: usize = 256;
pub const MAX_PENDING: usize = 4096;
const PROBE_MS: u64 = 20;
const PACKET_TTL_MS: u64 = 1000;
const FRAME_HEADER: usize = 18;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, clap::ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum Policy {
    Smart,
    Performance,
    Continuity,
    DataSaver,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Kind {
    Join = 1,
    Probe = 2,
    Pong = 3,
    Data = 4,
    Ack = 5,
    Close = 6,
}

#[derive(Clone, Debug)]
pub struct Frame {
    pub kind: Kind,
    pub path: u8,
    pub id: u64,
    pub stamp: u64,
    pub body: Vec<u8>,
}
impl Frame {
    pub fn control(kind: Kind, path: u8, id: u64, stamp: u64) -> Self {
        Self {
            kind,
            path,
            id,
            stamp,
            body: Vec::new(),
        }
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(FRAME_HEADER + self.body.len());
        bytes.extend_from_slice(&[self.kind as u8, self.path]);
        bytes.extend_from_slice(&self.id.to_be_bytes());
        bytes.extend_from_slice(&self.stamp.to_be_bytes());
        bytes.extend_from_slice(&self.body);
        bytes
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(
            (FRAME_HEADER..=FRAME_HEADER + BOND_MTU).contains(&bytes.len()),
            "invalid multipath frame size"
        );
        ensure!(usize::from(bytes[1]) < MAX_PATHS, "invalid path ID");
        let kind = match bytes[0] {
            1 => Kind::Join,
            2 => Kind::Probe,
            3 => Kind::Pong,
            4 => Kind::Data,
            5 => Kind::Ack,
            6 => Kind::Close,
            _ => anyhow::bail!("invalid multipath frame type"),
        };
        ensure!(
            if kind == Kind::Data {
                bytes.len() >= FRAME_HEADER + 20
            } else {
                bytes.len() == FRAME_HEADER
            },
            "invalid multipath payload"
        );
        Ok(Self {
            kind,
            path: bytes[1],
            id: u64::from_be_bytes(bytes[2..10].try_into()?),
            stamp: u64::from_be_bytes(bytes[10..18].try_into()?),
            body: bytes[18..].to_vec(),
        })
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Path {
    pub id: u8,
    pub name: String,
    pub metered: bool,
    pub enabled: bool,
    pub state: &'static str,
    pub rtt_ms: Option<f64>,
    pub jitter_ms: f64,
    pub minimum_rtt_ms: f64,
    pub acknowledged_bytes: u64,
    pub sent_bytes: u64,
    pub received_bytes: u64,
    pub delivery_bps: f64,
    pub in_flight: usize,
    pub congestion_window: usize,
    pub timeouts: u64,
    #[serde(skip)]
    last_response: Option<u64>,
    #[serde(skip)]
    good_samples: u8,
    #[serde(skip)]
    next_send: f64,
    #[serde(skip)]
    rate_started: u64,
    #[serde(skip)]
    rate_bytes: u64,
}
impl Path {
    fn new(id: u8, name: String, metered: bool) -> Self {
        Self {
            id,
            name,
            metered,
            enabled: true,
            state: "discovering",
            rtt_ms: None,
            jitter_ms: 0.0,
            minimum_rtt_ms: f64::MAX,
            acknowledged_bytes: 0,
            sent_bytes: 0,
            received_bytes: 0,
            delivery_bps: 0.0,
            in_flight: 0,
            congestion_window: 16 * BOND_MTU,
            timeouts: 0,
            last_response: None,
            good_samples: 0,
            next_send: 0.0,
            rate_started: 0,
            rate_bytes: 0,
        }
    }
    pub fn failure_ms(&self) -> u64 {
        (self.rtt_ms.unwrap_or(30.0) + 4.0 * self.jitter_ms).clamp(35.0, 70.0) as u64
    }
    pub fn ready(&self, now: u64) -> bool {
        self.enabled
            && self.good_samples >= 3
            && self
                .last_response
                .is_some_and(|last| now.saturating_sub(last) <= self.failure_ms())
    }
    fn observe(&mut self, now: u64, stamp: u64) {
        if stamp > now {
            return;
        }
        let sample = now.saturating_sub(stamp).max(1) as f64;
        if let Some(previous) = self.rtt_ms {
            self.jitter_ms = 0.75 * self.jitter_ms + 0.25 * (previous - sample).abs();
            self.rtt_ms = Some(0.875 * previous + 0.125 * sample);
        } else {
            self.rtt_ms = Some(sample);
            self.jitter_ms = sample / 2.0;
        }
        self.minimum_rtt_ms = self.minimum_rtt_ms.min(sample);
        self.last_response = Some(now);
        self.good_samples = self.good_samples.saturating_add(1);
        self.state = if self.good_samples < 3 {
            "recovering"
        } else if self.rtt_ms.unwrap_or(sample) - self.minimum_rtt_ms > 15.0 {
            "degraded"
        } else {
            "healthy"
        };
    }
    fn estimated_bytes_per_ms(&self) -> f64 {
        // Congestion-window/RTT pacing allows discovery without treating a
        // previous quiet flow's delivery rate as a permanent capacity cap.
        (self.congestion_window as f64 / self.rtt_ms.unwrap_or(30.0).max(1.0)).max(1.0)
    }
}

struct Pending {
    body: Vec<u8>,
    born: u64,
    attempts: BTreeMap<usize, u64>,
    last_repair: u64,
}

#[derive(Default, Serialize)]
pub struct Counters {
    pub delivered_packets: u64,
    pub delivered_bytes: u64,
    pub duplicates: u64,
    pub repairs: u64,
    pub protection_copies: u64,
    pub queue_drops: u64,
    pub expired_packets: u64,
    pub path_failures: u64,
}

pub struct Scheduler {
    pub paths: Vec<Path>,
    pub policy: Policy,
    pub counters: Counters,
    pending: BTreeMap<u64, Pending>,
    queued: VecDeque<Vec<u8>>,
    received: ReplayWindow,
    next_id: u64,
    last_probe: Option<u64>,
}
impl Scheduler {
    pub fn new(names: Vec<(String, bool)>, policy: Policy) -> Result<Self> {
        ensure!(
            !names.is_empty() && names.len() <= MAX_PATHS,
            "one to 256 paths required"
        );
        let paths = names
            .into_iter()
            .enumerate()
            .map(|(index, (name, metered))| Path::new(index as u8, name, metered))
            .collect();
        Ok(Self {
            paths,
            policy,
            counters: Counters::default(),
            pending: BTreeMap::new(),
            queued: VecDeque::new(),
            received: ReplayWindow::new(16384),
            next_id: 0,
            last_probe: None,
        })
    }
    pub fn enqueue(&mut self, ip: Vec<u8>) {
        if ip.len() > BOND_MTU
            || ip.len() < 20
            || self.queued.len() + self.pending.len() >= MAX_PENDING
        {
            self.counters.queue_drops += 1;
        } else {
            self.queued.push_back(ip);
        }
    }
    pub fn add_path(&mut self, name: String, metered: bool) -> Result<usize> {
        if let Some(index) = self.paths.iter().position(|path| path.name == name) {
            self.paths[index].enabled = true;
            self.paths[index].metered = metered;
            return Ok(index);
        }
        ensure!(
            self.paths.len() < MAX_PATHS,
            "device session has exhausted its path IDs"
        );
        let index = self.paths.len();
        self.paths.push(Path::new(index as u8, name, metered));
        Ok(index)
    }
    pub fn remove_path(&mut self, index: usize) {
        self.fail_path(index);
        if let Some(path) = self.paths.get_mut(index) {
            path.enabled = false;
            path.state = "removed";
        }
    }
    pub fn pending_packets(&self) -> usize {
        self.pending.len()
    }
    pub fn fail_path(&mut self, path: usize) {
        let Some(path) = self.paths.get_mut(path) else {
            return;
        };
        if path.state != "failed" {
            self.counters.path_failures += 1;
        }
        path.state = "failed";
        path.good_samples = 0;
        path.last_response = None;
        path.congestion_window = (path.congestion_window / 2).max(2 * BOND_MTU);
    }
    pub fn receive(&mut self, frame: &Frame, now: u64) -> (Option<Vec<u8>>, Vec<Frame>) {
        let index = usize::from(frame.path);
        if index >= self.paths.len() {
            return (None, Vec::new());
        }
        match frame.kind {
            Kind::Join | Kind::Probe => (
                None,
                vec![Frame::control(
                    Kind::Pong,
                    frame.path,
                    frame.id,
                    frame.stamp,
                )],
            ),
            Kind::Pong => {
                self.paths[index].observe(now, frame.stamp);
                (None, Vec::new())
            }
            Kind::Ack => {
                if !self
                    .pending
                    .get(&frame.id)
                    .is_some_and(|packet| packet.attempts.get(&index) == Some(&frame.stamp))
                {
                    return (None, Vec::new());
                }
                if let Some(pending) = self.pending.remove(&frame.id) {
                    // Attribute delivery only once; redundancy never inflates goodput.
                    if pending.attempts.get(&index) == Some(&frame.stamp) {
                        let path = &mut self.paths[index];
                        path.observe(now, frame.stamp);
                        path.acknowledged_bytes += pending.body.len() as u64;
                        path.rate_bytes += pending.body.len() as u64;
                        path.congestion_window = (path.congestion_window
                            + BOND_MTU * pending.body.len() / path.congestion_window.max(1))
                        .min(4 * 1024 * 1024);
                        let elapsed = now.saturating_sub(path.rate_started);
                        if elapsed >= 250 {
                            let sample = path.rate_bytes as f64 * 8000.0 / elapsed as f64;
                            path.delivery_bps = if path.delivery_bps == 0.0 {
                                sample
                            } else {
                                0.7 * path.delivery_bps + 0.3 * sample
                            };
                            path.rate_started = now;
                            path.rate_bytes = 0;
                        }
                    }
                    self.release_flight(&pending);
                }
                (None, Vec::new())
            }
            Kind::Data => {
                self.paths[index].received_bytes += frame.body.len() as u64;
                let ack = Frame::control(Kind::Ack, frame.path, frame.id, frame.stamp);
                if self.received.contains(frame.id) {
                    self.counters.duplicates += 1;
                    return (None, vec![ack]);
                }
                self.received.mark(frame.id);
                self.counters.delivered_packets += 1;
                self.counters.delivered_bytes += frame.body.len() as u64;
                (Some(frame.body.clone()), vec![ack])
            }
            Kind::Close => (None, Vec::new()),
        }
    }
    fn release_flight(&mut self, packet: &Pending) {
        for &index in packet.attempts.keys() {
            if index < self.paths.len() {
                self.paths[index].in_flight = self.paths[index]
                    .in_flight
                    .saturating_sub(packet.body.len());
            }
        }
    }
    fn targets(&self, bytes: usize, interactive: bool, now: u64) -> Vec<usize> {
        let mut ready: Vec<_> = self
            .paths
            .iter()
            .enumerate()
            .filter(|(_, path)| path.ready(now))
            .map(|(index, _)| index)
            .collect();
        if self.policy == Policy::DataSaver && ready.iter().any(|&index| !self.paths[index].metered)
        {
            ready.retain(|&index| !self.paths[index].metered);
        }
        ready.sort_by(|&a, &b| {
            self.paths[a]
                .rtt_ms
                .unwrap_or(f64::MAX)
                .total_cmp(&self.paths[b].rtt_ms.unwrap_or(f64::MAX))
        });
        if let Some(&fastest) = ready.first() {
            let floor = self.paths[fastest].rtt_ms.unwrap_or(30.0);
            if !interactive && self.policy != Policy::Performance {
                ready.retain(|&index| self.paths[index].rtt_ms.unwrap_or(30.0) - floor <= 10.0);
            }
        }
        ready.retain(|&index| {
            let path = &self.paths[index];
            path.in_flight + bytes <= path.congestion_window && path.next_send <= now as f64
        });
        if !interactive {
            ready.sort_by(|&a, &b| {
                let cost = |index: usize| {
                    let p = &self.paths[index];
                    p.rtt_ms.unwrap_or(30.0) / 2.0
                        + (p.in_flight + bytes) as f64 / p.estimated_bytes_per_ms()
                };
                cost(a).total_cmp(&cost(b))
            });
        }
        ready
    }
    fn send_copy(&mut self, packet: &mut Pending, id: u64, path: usize, now: u64) -> Frame {
        if !packet.attempts.contains_key(&path) {
            self.paths[path].in_flight += packet.body.len();
        }
        packet.attempts.insert(path, now);
        self.paths[path].sent_bytes += packet.body.len() as u64;
        self.paths[path].next_send = (self.paths[path].next_send.max(now as f64))
            + packet.body.len() as f64 / self.paths[path].estimated_bytes_per_ms();
        Frame {
            kind: Kind::Data,
            path: path as u8,
            id,
            stamp: now,
            body: packet.body.clone(),
        }
    }
    pub fn tick(&mut self, now: u64) -> Vec<Frame> {
        let mut output = Vec::new();
        for index in 0..self.paths.len() {
            if self.paths[index]
                .last_response
                .is_some_and(|last| now.saturating_sub(last) > self.paths[index].failure_ms())
            {
                self.fail_path(index);
            }
        }
        if self
            .last_probe
            .is_none_or(|last| now.saturating_sub(last) >= PROBE_MS)
        {
            self.last_probe = Some(now);
            for path in self.paths.iter().filter(|path| path.enabled) {
                output.push(Frame::control(Kind::Probe, path.id, now, now));
            }
        }
        let due: Vec<_> = self
            .pending
            .iter()
            .filter(|(_, packet)| now.saturating_sub(packet.last_repair) >= 25)
            .map(|(&id, _)| id)
            .take(64)
            .collect();
        for id in due {
            let mut packet = self.pending.remove(&id).expect("collected pending ID");
            if now.saturating_sub(packet.born) > PACKET_TTL_MS {
                self.release_flight(&packet);
                self.counters.expired_packets += 1;
                continue;
            }
            let candidates = self.targets(packet.body.len(), true, now);
            let target = candidates
                .iter()
                .find(|&&index| !packet.attempts.contains_key(&index))
                .copied()
                .or_else(|| {
                    candidates.first().copied().filter(|&index| {
                        now.saturating_sub(*packet.attempts.get(&index).unwrap_or(&0)) >= 70
                    })
                });
            if let Some(target) = target {
                // Congestion responses are bounded and applied on the original
                // path, while repair uses the surviving path's own pacing.
                for &index in packet.attempts.keys() {
                    if index < self.paths.len() && index != target {
                        self.paths[index].timeouts += 1;
                        self.paths[index].congestion_window =
                            (self.paths[index].congestion_window / 2).max(2 * BOND_MTU);
                    }
                }
                output.push(self.send_copy(&mut packet, id, target, now));
                self.counters.repairs += 1;
            }
            packet.last_repair = now;
            self.pending.insert(id, packet);
        }
        for _ in 0..32 {
            let Some(body) = self.queued.front() else {
                break;
            };
            let interactive = body.get(9) != Some(&6) || body.len() < 600;
            let targets = self.targets(body.len(), interactive, now);
            let Some(&primary) = targets.first() else {
                break;
            };
            let body = self.queued.pop_front().expect("checked queue");
            let id = self.next_id;
            let Some(next) = id.checked_add(1) else {
                self.counters.queue_drops += 1;
                break;
            };
            self.next_id = next;
            let mut packet = Pending {
                body,
                born: now,
                attempts: BTreeMap::new(),
                last_repair: now,
            };
            output.push(self.send_copy(&mut packet, id, primary, now));
            if interactive && let Some(&alternate) = targets.get(1) {
                let recovery = self.paths[primary].failure_ms() as f64
                    + self.paths[alternate].rtt_ms.unwrap_or(100.0)
                    + (self.paths[alternate].in_flight + packet.body.len()) as f64
                        / self.paths[alternate].estimated_bytes_per_ms();
                if self.policy == Policy::Continuity
                    || recovery >= 100.0
                    || self.paths[primary].state == "degraded"
                {
                    output.push(self.send_copy(&mut packet, id, alternate, now));
                    self.counters.protection_copies += 1;
                }
            }
            self.pending.insert(id, packet);
        }
        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn scheduler(policy: Policy) -> Scheduler {
        let mut scheduler = Scheduler::new(
            vec![("wifi".into(), false), ("ethernet".into(), false)],
            policy,
        )
        .unwrap();
        for now in [10, 20, 30] {
            for path in 0..2 {
                scheduler.receive(&Frame::control(Kind::Pong, path, now, now - 5), now);
            }
        }
        scheduler
    }
    fn packet() -> Vec<u8> {
        let mut p = vec![0; 100];
        p[0] = 0x45;
        p[3] = 100;
        p[9] = 17;
        p
    }
    #[test]
    fn frame_bounds_and_control_shape() {
        let frame = Frame::control(Kind::Probe, 0, 9, 8);
        assert_eq!(Frame::decode(&frame.encode()).unwrap().id, 9);
        let mut bytes = frame.encode();
        bytes.push(0);
        assert!(Frame::decode(&bytes).is_err());
        bytes.truncate(18);
        bytes[0] = 0;
        assert!(Frame::decode(&bytes).is_err());
        assert!(Frame::decode(&[0; 17]).is_err());
    }
    #[test]
    fn alternate_repairs_preserve_identity_and_deduplicate() {
        let mut tx = scheduler(Policy::Smart);
        let mut rx = scheduler(Policy::Smart);
        tx.enqueue(packet());
        let first = tx
            .tick(31)
            .into_iter()
            .find(|frame| frame.kind == Kind::Data)
            .unwrap();
        tx.fail_path(first.path as usize);
        let repair = tx
            .tick(56)
            .into_iter()
            .find(|frame| frame.kind == Kind::Data)
            .unwrap();
        assert_eq!(first.id, repair.id);
        assert_ne!(first.path, repair.path);
        assert!(rx.receive(&repair, 60).0.is_some());
        assert!(rx.receive(&first, 61).0.is_none());
        assert_eq!(rx.counters.delivered_bytes, 100);
        assert_eq!(rx.counters.duplicates, 1);
    }
    #[test]
    fn recovery_requires_multiple_good_samples() {
        let mut scheduler = scheduler(Policy::Smart);
        scheduler.fail_path(0);
        scheduler.receive(&Frame::control(Kind::Pong, 0, 40, 35), 40);
        assert!(!scheduler.paths[0].ready(40));
        for now in [50, 60] {
            scheduler.receive(&Frame::control(Kind::Pong, 0, now, now - 5), now);
        }
        assert!(scheduler.paths[0].ready(60));
    }
    #[test]
    fn silence_marks_path_failed_and_ack_releases_all_copies() {
        let mut scheduler = scheduler(Policy::Continuity);
        scheduler.enqueue(packet());
        let sent: Vec<_> = scheduler
            .tick(31)
            .into_iter()
            .filter(|frame| frame.kind == Kind::Data)
            .collect();
        assert_eq!(sent.len(), 2);
        scheduler.receive(
            &Frame::control(Kind::Ack, sent[1].path, sent[1].id, sent[1].stamp),
            36,
        );
        assert_eq!(scheduler.pending_packets(), 0);
        assert!(scheduler.paths.iter().all(|path| path.in_flight == 0));
        scheduler.tick(200);
        assert!(scheduler.paths.iter().all(|path| path.state == "failed"));
    }
    #[test]
    fn queues_remain_bounded_when_all_paths_fail() {
        let mut scheduler = scheduler(Policy::Smart);
        scheduler.fail_path(0);
        scheduler.fail_path(1);
        for _ in 0..MAX_PENDING + 10 {
            scheduler.enqueue(packet());
        }
        assert_eq!(scheduler.queued.len(), MAX_PENDING);
        assert_eq!(scheduler.counters.queue_drops, 10);
        assert!(
            !scheduler
                .tick(100)
                .iter()
                .any(|frame| frame.kind == Kind::Data)
        );
    }
    #[test]
    fn data_saver_avoids_metered_when_unmetered_is_healthy() {
        let mut scheduler = scheduler(Policy::DataSaver);
        scheduler.paths[0].metered = true;
        scheduler.enqueue(packet());
        assert!(
            scheduler
                .tick(31)
                .iter()
                .filter(|frame| frame.kind == Kind::Data)
                .all(|frame| frame.path == 1)
        );
    }

    #[test]
    fn extra_lan_adapters_join_leave_and_rejoin_without_changing_session_packets() {
        let mut scheduler = scheduler(Policy::Performance);
        scheduler.enqueue(packet());
        scheduler.tick(31);
        let pending = scheduler.pending_packets();
        for index in 2..20 {
            assert_eq!(
                scheduler.add_path(format!("en{index}"), false).unwrap(),
                index
            );
        }
        assert_eq!(scheduler.paths.len(), 20);
        assert_eq!(scheduler.pending_packets(), pending);
        scheduler.remove_path(7);
        assert!(!scheduler.paths[7].enabled);
        assert!(!scheduler.tick(32).iter().any(|frame| frame.path == 7));
        assert_eq!(scheduler.add_path("en7".into(), false).unwrap(), 7);
        assert!(scheduler.paths[7].enabled);
        assert!(!scheduler.paths[7].ready(32));
        assert_eq!(scheduler.paths.len(), 20);
    }
}
