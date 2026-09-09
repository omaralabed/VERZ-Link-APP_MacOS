//! Multipath IP scheduling primitives. Time is monotonic milliseconds supplied
//! by the runtime, allowing deterministic failure/recovery tests without sleeps.
//! Path ACKs measure delivered tunnel bytes, not application-level TCP goodput.
use crate::ReplayWindow;
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, VecDeque};

pub const BOND_MTU: usize = 1200;
/// Wire IDs support 256 distinct adapter paths per device session. Allocation
/// is dynamic; ordinary multi-adapter Macs do not pay for unused path slots.
pub const MAX_PATHS: usize = 256;
pub const MAX_PENDING: usize = 4096;
pub const FEATURE_ACK_BATCH: u64 = 512;
const PROBE_MS: u64 = 20;
pub const LATENCY_CUTOFF_MS: f64 = 75.0;
const PACKET_TTL_MS: u64 = 1000;
const FRAME_HEADER: usize = 18;

pub fn handshake(
    secret: &[u8; 32],
    session: &[u8; 16],
    initiator: bool,
) -> Result<snow::HandshakeState> {
    let mut prologue = b"VERZ Link multipath v1 / authenticated IPv4 lease / MTU1200 / ".to_vec();
    prologue.extend_from_slice(session);
    let builder = snow::Builder::new("Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s".parse()?)
        .psk(0, secret)?
        .prologue(&prologue)?;
    Ok(if initiator {
        builder.build_initiator()?
    } else {
        builder.build_responder()?
    })
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, clap::ValueEnum)]
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
    AckBatch = 7,
    JoinAck = 8,
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
            7 => Kind::AckBatch,
            8 => Kind::JoinAck,
            _ => anyhow::bail!("invalid multipath frame type"),
        };
        ensure!(
            if kind == Kind::Data {
                bytes.len() >= FRAME_HEADER + 20
            } else if kind == Kind::AckBatch {
                bytes.len() >= FRAME_HEADER && (bytes.len() - FRAME_HEADER).is_multiple_of(16)
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

/// Coalesce path-local ACKs, preserving every packet ID and original timestamp.
/// The runtime flushes partial batches on its 2 ms tick. Negotiation is required
/// so clients/relays predating AckBatch continue using ordinary ACK frames.
#[derive(Default)]
pub struct AckBatcher {
    pending: BTreeMap<u8, Vec<Frame>>,
}
impl AckBatcher {
    pub fn push(&mut self, frame: Frame) -> Option<Frame> {
        if frame.kind != Kind::Ack {
            return Some(frame);
        }
        let pending = self.pending.entry(frame.path).or_default();
        pending.push(frame);
        (pending.len() >= 16).then(|| Self::batch(std::mem::take(pending)))
    }
    pub fn drain(&mut self) -> Vec<Frame> {
        self.pending
            .values_mut()
            .filter(|items| !items.is_empty())
            .map(|items| Self::batch(std::mem::take(items)))
            .collect()
    }
    fn batch(mut frames: Vec<Frame>) -> Frame {
        let mut first = frames.remove(0);
        // Even a partial one-entry flush needs a distinct kind, otherwise the
        // runtime's send path would enqueue it again instead of transmitting.
        first.kind = Kind::AckBatch;
        for frame in frames {
            first.body.extend_from_slice(&frame.id.to_be_bytes());
            first.body.extend_from_slice(&frame.stamp.to_be_bytes());
        }
        first
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
    pub slow_start_threshold: usize,
    pub timeouts: u64,
    pub latency_excluded: bool,
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
    #[serde(skip)]
    last_congestion: Option<u64>,
    #[serde(skip)]
    growth_credit: usize,
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
            slow_start_threshold: 4 * 1024 * 1024,
            timeouts: 0,
            latency_excluded: false,
            last_response: None,
            good_samples: 0,
            next_send: 0.0,
            rate_started: 0,
            rate_bytes: 0,
            last_congestion: None,
            growth_credit: 0,
        }
    }
    pub fn failure_ms(&self) -> u64 {
        // Probes are continuous: detect missing replies, not a high RTT.
        // Protection/repair is separate from declaring the entire path dead.
        (3.0 * PROBE_MS as f64 + 4.0 * self.jitter_ms).clamp(60.0, 1000.0) as u64
    }
    fn repair_ms(&self) -> u64 {
        (self.rtt_ms.unwrap_or(30.0) + 4.0 * self.jitter_ms + 20.0).max(70.0) as u64
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
        if self.rtt_ms.unwrap_or(sample) >= LATENCY_CUTOFF_MS {
            self.latency_excluded = true;
        } else if self.rtt_ms.unwrap_or(sample) < 65.0 && self.good_samples >= 3 {
            self.latency_excluded = false;
        }
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

    fn acknowledge_capacity(&mut self, bytes: usize) {
        if self.congestion_window < self.slow_start_threshold {
            // Discover available capacity in RTTs, not tens of seconds of
            // fixed additive growth from the initial 19 KB window.
            self.congestion_window += bytes;
        } else {
            // Retain fractional additive growth instead of rounding every ACK
            // down to zero once the window exceeds one MSS squared.
            self.growth_credit += bytes;
            while self.growth_credit >= self.congestion_window {
                self.growth_credit -= self.congestion_window;
                self.congestion_window += BOND_MTU;
            }
        }
        self.congestion_window = self.congestion_window.min(4 * 1024 * 1024);
    }

    fn congestion_loss(&mut self, now: u64) {
        if self
            .last_congestion
            .is_some_and(|last| now.saturating_sub(last) < self.repair_ms())
        {
            return;
        }
        self.timeouts += 1;
        self.last_congestion = Some(now);
        self.slow_start_threshold = (self.congestion_window / 2).max(2 * BOND_MTU);
        self.congestion_window = self.slow_start_threshold;
        self.growth_credit = 0;
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
    /// New packets refused before acknowledgement; the sender may retry them.
    pub receive_backpressure: u64,
    pub socket_backpressure: u64,
    pub expired_packets: u64,
    pub path_failures: u64,
}

pub struct Scheduler {
    pub paths: Vec<Path>,
    pub policy: Policy,
    pub counters: Counters,
    pending: BTreeMap<u64, Pending>,
    queued: VecDeque<Vec<u8>>,
    urgent: VecDeque<Vec<u8>>,
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
            urgent: VecDeque::new(),
            received: ReplayWindow::new(16384),
            next_id: 0,
            last_probe: None,
        })
    }
    pub fn enqueue(&mut self, ip: Vec<u8>) {
        let limit = if interactive(&ip) {
            MAX_PENDING
        } else {
            MAX_PENDING - 64
        };
        if ip.len() > BOND_MTU
            || ip.len() < 20
            || self.queued.len() + self.urgent.len() + self.pending.len() >= limit
        {
            self.counters.queue_drops += 1;
        } else {
            if interactive(&ip) {
                self.urgent.push_back(ip);
            } else {
                self.queued.push_back(ip);
            }
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
    pub fn has_received(&self, id: u64) -> bool {
        self.received.contains(id)
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
        path.next_send = 0.0;
        // Liveness controls eligibility immediately, but a quiet path's probe
        // gap is not evidence that its data capacity has halved. Actual pending
        // data repairs still apply congestion backoff in tick().
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
            Kind::Pong | Kind::JoinAck => {
                self.paths[index].observe(now, frame.stamp);
                (None, Vec::new())
            }
            Kind::Ack => {
                if !self.pending.get(&frame.id).is_some_and(|packet| {
                    frame.stamp >= packet.born
                        && packet
                            .attempts
                            .get(&index)
                            .is_some_and(|&last| frame.stamp <= last)
                }) {
                    return (None, Vec::new());
                }
                if let Some(pending) = self.pending.remove(&frame.id) {
                    // Attribute delivery only once; redundancy never inflates goodput.
                    {
                        let path = &mut self.paths[index];
                        // Accept an original copy's ACK after a resend without
                        // using an ambiguous RTT measurement.
                        if pending.attempts.get(&index) == Some(&frame.stamp) {
                            path.observe(now, frame.stamp);
                        }
                        path.acknowledged_bytes += pending.body.len() as u64;
                        path.rate_bytes += pending.body.len() as u64;
                        path.acknowledge_capacity(pending.body.len());
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
            Kind::AckBatch => {
                self.receive(
                    &Frame::control(Kind::Ack, frame.path, frame.id, frame.stamp),
                    now,
                );
                for ack in frame.body.chunks_exact(16) {
                    self.receive(
                        &Frame::control(
                            Kind::Ack,
                            frame.path,
                            u64::from_be_bytes(ack[..8].try_into().expect("ACK ID")),
                            u64::from_be_bytes(ack[8..].try_into().expect("ACK timestamp")),
                        ),
                        now,
                    );
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
    pub fn data_paths(&self, now: u64) -> Vec<usize> {
        let mut ready: Vec<_> = self
            .paths
            .iter()
            .enumerate()
            .filter(|(_, path)| path.ready(now))
            .map(|(index, _)| index)
            .collect();
        ready.sort_by(|&a, &b| {
            self.paths[a]
                .rtt_ms
                .unwrap_or(f64::MAX)
                .total_cmp(&self.paths[b].rtt_ms.unwrap_or(f64::MAX))
        });
        if ready
            .iter()
            .any(|&index| !self.paths[index].latency_excluded)
        {
            ready.retain(|&index| !self.paths[index].latency_excluded);
        } else {
            // If every link is above the limit, preserve basic connectivity
            // over the best one rather than silently blackholing the Mac.
            ready.truncate(1);
        }
        if self.policy == Policy::DataSaver && ready.iter().any(|&index| !self.paths[index].metered)
        {
            ready.retain(|&index| !self.paths[index].metered);
        }
        ready
    }
    fn targets(&self, bytes: usize, interactive: bool, now: u64) -> Vec<usize> {
        let mut ready = self.data_paths(now);
        // No relative-RTT cutoff: a 40 ms difference still adds capacity when
        // both links remain below the explicit 75 ms ceiling.
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
        // Permit bounded catch-up between runtime ticks; otherwise a 2 ms
        // timer accidentally caps every path at one packet per 2 ms (~4.8 Mbps).
        self.paths[path].next_send = (self.paths[path].next_send.max(now.saturating_sub(4) as f64))
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
        let data_paths = self.data_paths(now);
        let due: Vec<_> = self
            .pending
            .iter()
            .filter(|(_, packet)| {
                now.saturating_sub(packet.last_repair) >= 2
                    && packet.attempts.iter().all(|(&index, &stamp)| {
                        !data_paths.contains(&index)
                            || now.saturating_sub(stamp) >= self.paths[index].repair_ms()
                    })
            })
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
            let mut candidates = self.targets(packet.body.len(), true, now);
            // A resend on the same path does not add in-flight bytes. An
            // exhausted congestion window must not deadlock its own repairs.
            for &index in packet.attempts.keys() {
                let path = &self.paths[index];
                if data_paths.contains(&index)
                    && path.next_send <= now as f64
                    && !candidates.contains(&index)
                {
                    candidates.push(index);
                }
            }
            let target = candidates
                .iter()
                .find(|&&index| !packet.attempts.contains_key(&index))
                .copied()
                .or_else(|| {
                    candidates.first().copied().filter(|&index| {
                        now.saturating_sub(*packet.attempts.get(&index).unwrap_or(&0))
                            >= self.paths[index].repair_ms()
                    })
                });
            if let Some(target) = target {
                // Congestion responses are bounded and applied on the original
                // path, while repair uses the surviving path's own pacing.
                for &index in packet.attempts.keys() {
                    if index < self.paths.len() {
                        self.paths[index].congestion_loss(now);
                    }
                }
                output.push(self.send_copy(&mut packet, id, target, now));
                self.counters.repairs += 1;
            }
            packet.last_repair = now;
            self.pending.insert(id, packet);
        }
        // Bounded work per reactor turn, without a ~154 Mbps aggregate cap
        // imposed by 32 packets at a 2 ms tick.
        for _ in 0..128 {
            let queue = if self.urgent.is_empty() {
                &self.queued
            } else {
                &self.urgent
            };
            let Some(body) = queue.front() else {
                break;
            };
            let is_interactive = interactive(body);
            let targets = self.targets(body.len(), is_interactive, now);
            let Some(&primary) = targets.first() else {
                break;
            };
            let body = if self.urgent.is_empty() {
                self.queued.pop_front()
            } else {
                self.urgent.pop_front()
            }
            .expect("checked queue");
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
            if is_interactive && let Some(&alternate) = targets.get(1) {
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

fn interactive(ip: &[u8]) -> bool {
    // Large UDP/QUIC transfers are bulk too. Treating every UDP packet as
    // interactive duplicated downloads and consumed the capacity being bonded.
    ip.len() < 600 || ip.get(9) == Some(&1)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn unequal_latency() -> Scheduler {
        let mut s = scheduler(Policy::Smart);
        for (p, rtt) in s.paths.iter_mut().zip([20.0, 60.0]) {
            p.rtt_ms = Some(rtt);
            p.minimum_rtt_ms = rtt;
            p.jitter_ms = 0.0;
            p.last_response = Some(100);
        }
        s
    }
    #[test]
    fn seventy_five_ms_path_is_probe_only_until_stable_recovery() {
        let mut s = unequal_latency();
        s.paths[1].rtt_ms = Some(75.0);
        s.receive(&Frame::control(Kind::Pong, 1, 100, 25), 100);
        assert_eq!(s.data_paths(100), vec![0]);
        assert!(
            s.tick(100)
                .iter()
                .any(|f| f.kind == Kind::Probe && f.path == 1)
        );
        for now in 101..120 {
            s.receive(&Frame::control(Kind::Pong, 1, now, now - 40), now);
        }
        assert!(s.data_paths(120).contains(&1));
    }
    #[test]
    fn all_high_latency_keeps_best_last_resort_instead_of_blackholing() {
        let mut s = unequal_latency();
        for p in &mut s.paths {
            p.latency_excluded = true;
        }
        assert_eq!(s.data_paths(100), vec![0]);
    }
    fn bulk() -> Vec<u8> {
        let mut p = vec![0; 1200];
        p[0] = 0x45;
        p[9] = 6;
        p
    }
    #[test]
    fn large_quic_packets_do_not_consume_protection_capacity() {
        let mut p = bulk();
        p[9] = 17;
        assert!(!interactive(&p));
        let mut s = unequal_latency();
        s.enqueue(p);
        assert_eq!(
            s.tick(100).iter().filter(|f| f.kind == Kind::Data).count(),
            1
        );
    }

    #[test]
    fn ack_batches_release_each_packet_once_and_preserve_timestamps() {
        let mut s = unequal_latency();
        s.remove_path(1);
        s.paths[0].congestion_window = 1024 * 1024;
        for _ in 0..16 {
            s.enqueue(bulk());
        }
        let packets: Vec<_> = s
            .tick(100)
            .into_iter()
            .filter(|f| f.kind == Kind::Data)
            .collect();
        assert_eq!(packets.len(), 16);
        let mut batcher = AckBatcher::default();
        let mut batches = Vec::new();
        for packet in &packets {
            batches.extend(batcher.push(Frame::control(
                Kind::Ack,
                packet.path,
                packet.id,
                packet.stamp,
            )));
        }
        assert_eq!(batches.len(), 1);
        assert!(batcher.drain().is_empty());
        let decoded = Frame::decode(&batches[0].encode()).unwrap();
        assert_eq!(decoded.kind, Kind::AckBatch);
        s.receive(&decoded, 120);
        s.receive(&decoded, 121);
        assert_eq!(s.pending_packets(), 0);
        assert_eq!(s.paths[0].in_flight, 0);
        assert_eq!(s.paths[0].acknowledged_bytes, 16 * BOND_MTU as u64);
    }

    #[test]
    fn partial_ack_batches_flush_once_and_do_not_mix_paths() {
        let mut batcher = AckBatcher::default();
        assert!(batcher.push(Frame::control(Kind::Ack, 0, 10, 50)).is_none());
        assert!(batcher.push(Frame::control(Kind::Ack, 1, 11, 51)).is_none());
        let frames = batcher.drain();
        assert_eq!(frames.len(), 2);
        for frame in frames {
            assert_eq!(frame.kind, Kind::AckBatch);
            assert!(Frame::decode(&frame.encode()).is_ok());
            assert!(batcher.push(frame).is_some());
        }
        assert!(batcher.drain().is_empty());
        let mut invalid = Frame::control(Kind::AckBatch, 0, 1, 1).encode();
        invalid.push(0);
        assert!(Frame::decode(&invalid).is_err());
    }
    #[test]
    fn smart_uses_bulk_capacity_with_forty_ms_rtt_difference() {
        let mut s = unequal_latency();
        for _ in 0..100 {
            s.enqueue(bulk());
        }
        let sent = s.tick(100);
        for path in [0, 1] {
            assert!(
                sent.iter()
                    .any(|frame| frame.kind == Kind::Data && frame.path == path)
            );
        }
    }
    #[test]
    fn healthy_slower_path_is_not_penalized_before_its_rtt() {
        let mut s = unequal_latency();
        s.fail_path(0);
        s.enqueue(bulk());
        let frame = s
            .tick(100)
            .into_iter()
            .find(|f| f.kind == Kind::Data)
            .unwrap();
        assert_eq!(frame.path, 1);
        s.tick(140);
        assert_eq!(s.counters.repairs, 0);
        assert_eq!(s.paths[1].timeouts, 0);
        s.receive(&Frame::control(Kind::Ack, 1, frame.id, frame.stamp), 160);
        assert_eq!(s.pending_packets(), 0);
    }
    #[test]
    fn full_surviving_window_can_retransmit_instead_of_deadlocking() {
        let mut s = unequal_latency();
        s.fail_path(0);
        s.paths[1].congestion_window = BOND_MTU;
        s.enqueue(bulk());
        s.tick(100);
        assert_eq!(s.paths[1].in_flight, BOND_MTU);
        s.paths[1].last_response = Some(180);
        assert!(
            s.tick(181)
                .iter()
                .any(|f| f.kind == Kind::Data && f.path == 1)
        );
    }

    #[test]
    fn idle_probe_failure_does_not_destroy_learned_capacity() {
        let mut s = unequal_latency();
        s.paths[0].congestion_window = 400_000;
        s.fail_path(0);
        assert!(!s.paths[0].ready(101));
        assert_eq!(s.paths[0].congestion_window, 400_000);
        s.paths[0].congestion_loss(200);
        assert_eq!(s.paths[0].congestion_window, 200_000);
        s.paths[0].congestion_loss(201);
        assert_eq!(s.paths[0].congestion_window, 200_000);
    }

    #[test]
    fn capacity_discovery_grows_quickly_then_backs_off_on_real_loss() {
        let mut path = Path::new(0, "en0".into(), false);
        for _ in 0..512 {
            path.acknowledge_capacity(BOND_MTU);
        }
        assert_eq!(path.congestion_window, 528 * BOND_MTU);
        path.congestion_loss(100);
        let reduced = path.congestion_window;
        assert_eq!(reduced, 264 * BOND_MTU);
        for _ in 0..264 {
            path.acknowledge_capacity(BOND_MTU);
        }
        assert_eq!(path.congestion_window, reduced + BOND_MTU);
        path.congestion_window = 2 * 1024 * 1024;
        path.slow_start_threshold = path.congestion_window;
        for _ in 0..2000 {
            path.acknowledge_capacity(BOND_MTU);
        }
        assert!(path.congestion_window > 2 * 1024 * 1024);
    }
    #[test]
    fn removed_low_latency_link_repairs_over_slower_link_immediately() {
        let mut s = unequal_latency();
        s.enqueue(bulk());
        let first = s
            .tick(100)
            .into_iter()
            .find(|f| f.kind == Kind::Data)
            .unwrap();
        assert_eq!(first.path, 0);
        s.remove_path(0);
        assert!(
            s.tick(102)
                .iter()
                .any(|f| f.kind == Kind::Data && f.path == 1 && f.id == first.id)
        );
    }
    #[test]
    fn original_ack_after_resend_still_releases_pending_packet() {
        let mut scheduler = scheduler(Policy::Smart);
        scheduler.enqueue(packet());
        let original = scheduler
            .tick(31)
            .into_iter()
            .find(|frame| frame.kind == Kind::Data)
            .unwrap();
        scheduler
            .pending
            .get_mut(&original.id)
            .unwrap()
            .attempts
            .insert(original.path as usize, 101);
        scheduler.receive(
            &Frame::control(Kind::Ack, original.path, original.id, original.stamp),
            150,
        );
        assert_eq!(scheduler.pending_packets(), 0);
        assert_eq!(
            scheduler.paths[original.path as usize].acknowledged_bytes,
            100
        );
    }
    #[test]
    fn interactive_packets_do_not_wait_behind_queued_bulk() {
        let mut scheduler = scheduler(Policy::Smart);
        let mut bulk = vec![0; 1200];
        bulk[0] = 0x45;
        bulk[9] = 6;
        for _ in 0..100 {
            scheduler.enqueue(bulk.clone());
        }
        scheduler.enqueue(packet());
        let first = scheduler
            .tick(31)
            .into_iter()
            .find(|frame| frame.kind == Kind::Data)
            .unwrap();
        assert_eq!(first.body.len(), 100);
    }
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
        assert_eq!(scheduler.queued.len() + scheduler.urgent.len(), MAX_PENDING);
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
