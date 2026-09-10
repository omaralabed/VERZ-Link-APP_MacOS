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
    #[serde(skip)]
    last_delay_adjust: Option<u64>,
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
            // 300 Mbps at 3 ms LAN RTT needs ~112 KB in flight to fill; the
            // previous 16 MTU (~19 KB) start capped throughput to ~50 Mbps
            // for the first many RTTs before growth caught up.
            congestion_window: 32 * BOND_MTU,
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
            last_delay_adjust: None,
        }
    }
    pub fn failure_ms(&self) -> u64 {
        // Probes are continuous: detect missing replies, not a high RTT.
        // Protection/repair is separate from declaring the entire path dead.
        // A residential LAN can pause 100-200 ms during ARP refresh or Wi-Fi
        // roam without being "failed"; require several missed probes plus
        // jitter headroom before ejecting a path.
        (8.0 * PROBE_MS as f64 + 4.0 * self.jitter_ms).clamp(250.0, 2000.0) as u64
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
        let rtt = self.rtt_ms.unwrap_or(sample);
        // 10 ms was pathological on LAN (min 3 ms): a single BDP worth of
        // packets in flight already pushes rtt past 13 ms, so cwnd was halved
        // on every growth attempt and stuck at ~5 MTUs. A 30 ms threshold
        // still catches queue building on any link, including satellite.
        const DELAY_SLACK_MS: f64 = 30.0;
        if rtt - self.minimum_rtt_ms > DELAY_SLACK_MS
            && self
                .last_delay_adjust
                .is_none_or(|last| now.saturating_sub(last) as f64 >= rtt)
        {
            // Softer backoff (0.75..0.95): cutting cwnd in half whenever a
            // couple of packets queue prevented steady-state throughput near
            // capacity even after growth reached the BDP.
            let ratio = ((self.minimum_rtt_ms + DELAY_SLACK_MS) / rtt).clamp(0.75, 0.95);
            self.congestion_window =
                ((self.congestion_window as f64 * ratio) as usize).max(4 * BOND_MTU);
            self.slow_start_threshold = self.congestion_window;
            self.growth_credit = 0;
            self.last_delay_adjust = Some(now);
        }
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
        // Match the delay-based backoff threshold so growth pauses only when
        // backoff would also trigger, not on any transient queue.
        if self
            .rtt_ms
            .is_some_and(|rtt| rtt - self.minimum_rtt_ms > 30.0)
        {
            return;
        }
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
        // Distinguish random wireless loss from real congestion. On Wi-Fi and
        // cellular, isolated losses come from radio noise and MAC retries with
        // no queue growth, so halving cwnd on every timeout collapses the
        // window and the whole flow stalls. Kernel TCP CUBIC survives Wi-Fi
        // by only reducing on a delay signal; mirror that: require RTT to be
        // meaningfully above the minimum before treating this as congestion.
        let elevated = self
            .rtt_ms
            .zip(Some(self.minimum_rtt_ms))
            .is_some_and(|(rtt, min)| min.is_finite() && rtt - min > 15.0);
        if !elevated {
            return;
        }
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
    streaming: VecDeque<Vec<u8>>,
    received: ReplayWindow,
    next_id: u64,
    last_probe: Option<u64>,
    realtime_advice: BTreeMap<String, u32>,
    advice_until: u64,
    // Bulk UDP flows (SRT, RTMP-over-UDP, WebRTC video, games) suffer badly
    // when consecutive packets are sprayed across paths of unequal RTT.
    // Pin each 5-tuple to one path and only migrate on path failure.
    flow_paths: BTreeMap<u128, (usize, u64)>,
    last_flow_prune: u64,
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
            streaming: VecDeque::new(),
            received: ReplayWindow::new(16384),
            next_id: 0,
            last_probe: None,
            realtime_advice: BTreeMap::new(),
            advice_until: 0,
            flow_paths: BTreeMap::new(),
            last_flow_prune: 0,
        })
    }
    pub fn set_realtime_advice(&mut self, weights: BTreeMap<String, u32>, until: u64) {
        self.realtime_advice = weights;
        self.advice_until = until;
    }
    pub fn enqueue(&mut self, ip: Vec<u8>) {
        let limit = if interactive(&ip) {
            MAX_PENDING
        } else {
            MAX_PENDING - 64
        };
        if ip.len() > BOND_MTU
            || ip.len() < 20
            || self.queued.len() + self.urgent.len() + self.streaming.len() + self.pending.len()
                >= limit
        {
            self.counters.queue_drops += 1;
        } else {
            if interactive(&ip) {
                self.urgent.push_back(ip);
            } else if streaming(&ip) {
                self.streaming.push_back(ip);
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
        let failing = path;
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
        // Drop pinned UDP flows on the failing path so the next packet re-picks.
        self.flow_paths.retain(|_, (index, _)| *index != failing);
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
        if self.policy == Policy::DataSaver && ready.iter().any(|&index| !self.paths[index].metered)
        {
            ready.retain(|&index| !self.paths[index].metered);
        }
        ready
    }
    fn targets(&self, bytes: usize, interactive: bool, now: u64) -> Vec<usize> {
        let mut ready = self.data_paths(now);
        // 75 ms is now a latency-sensitive placement rule, not a blanket
        // capacity cutoff. Keep all responsive bulk paths, but keep calls and
        // recognized streams on low-delay paths when possible.
        if interactive {
            if ready.iter().any(|&i| !self.paths[i].latency_excluded) {
                ready.retain(|&i| !self.paths[i].latency_excluded);
            } else {
                ready.truncate(1);
            }
        }
        ready.retain(|&index| {
            let path = &self.paths[index];
            let reserve = if interactive {
                0
            } else {
                (4 * BOND_MTU)
                    .min(path.congestion_window / 4)
                    .min(path.congestion_window.saturating_sub(bytes))
            };
            path.in_flight + bytes <= path.congestion_window.saturating_sub(reserve)
                && path.next_send <= now as f64
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
        } else if now < self.advice_until {
            ready.sort_by(|&a, &b| {
                let cost = |i: usize| {
                    let p = &self.paths[i];
                    // Remote advice is only a bounded tie-break/bias. Local
                    // readiness, 75 ms policy, pacing and windows win first.
                    let weight = self
                        .realtime_advice
                        .get(&p.name)
                        .copied()
                        .unwrap_or(16)
                        .clamp(1, 64);
                    (p.rtt_ms.unwrap_or(30.0) + 4.0 * p.jitter_ms)
                        / (weight as f64 / 16.0).sqrt().clamp(0.5, 2.0)
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
        if now.saturating_sub(self.last_flow_prune) >= 1000 {
            self.last_flow_prune = now;
            self.flow_paths
                .retain(|_, (_, last_seen)| now.saturating_sub(*last_seen) < 30_000);
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
            let mut candidates = self.targets(
                packet.body.len(),
                interactive(&packet.body) || streaming(&packet.body),
                now,
            );
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
                if self.streaming.is_empty() {
                    &self.queued
                } else {
                    &self.streaming
                }
            } else {
                &self.urgent
            };
            let Some(body) = queue.front() else {
                break;
            };
            let is_interactive = interactive(body);
            let targets = self.targets(body.len(), is_interactive || streaming(body), now);
            let Some(&first) = targets.first() else {
                break;
            };
            // For bulk UDP flows, keep the whole 5-tuple on one path. Spraying
            // consecutive SRT/RTMP/WebRTC packets across paths of unequal RTT
            // reorders them and collapses effective throughput to the slowest
            // path. If the pinned path is dead, fall back to the fresh pick.
            // Only bulk packets create a pin; smaller companion packets (SRT
            // ACKs/NAKs, RTP marker, etc.) look up an existing pin so their
            // 5-tuple stays on the same path and does not get duplicated.
            let insert_key = bulk_udp_flow_key(body);
            let lookup_key = insert_key.or_else(|| udp_flow_key(body));
            let pinned_primary = lookup_key
                .and_then(|key| self.flow_paths.get(&key).map(|&(pinned, _)| pinned))
                .filter(|&pinned| {
                    self.paths
                        .get(pinned)
                        .is_some_and(|p| p.enabled && p.state != "failed")
                });
            let primary = pinned_primary.unwrap_or(first);
            let body = if self.urgent.is_empty() {
                if self.streaming.is_empty() {
                    self.queued.pop_front()
                } else {
                    self.streaming.pop_front()
                }
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
            if let Some(key) = insert_key {
                self.flow_paths.insert(key, (primary, now));
            }
            let mut packet = Pending {
                body,
                born: now,
                attempts: BTreeMap::new(),
                last_repair: now,
            };
            output.push(self.send_copy(&mut packet, id, primary, now));
            // A UDP packet that belongs to a pinned bulk flow (SRT/RTMP/etc.)
            // travels with the flow: duplicating its control packets across
            // paths burns bandwidth without helping the media stream.
            let follows_pin = pinned_primary.is_some();
            if is_interactive && !follows_pin && let Some(&alternate) = targets.get(1) {
                // Detection-time budget for interactive protection, held
                // independent of the (much wider) failure eviction window so
                // that longer failure_ms values do not silently opt every
                // small packet into duplication.
                let recovery = 3.0 * PROBE_MS as f64
                    + self.paths[alternate].rtt_ms.unwrap_or(100.0)
                    + (self.paths[alternate].in_flight + packet.body.len()) as f64
                        / self.paths[alternate].estimated_bytes_per_ms();
                if self.policy == Policy::Continuity
                    || (self.policy != Policy::DataSaver && is_realtime_media(&packet.body))
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
    // Bare TCP ACKs are also skipped: TCP already tolerates ACK loss via the
    // next cumulative ACK, and duplicating them halved each path's usable
    // bandwidth during bulk transfers.
    if bare_tcp_ack(ip) {
        return false;
    }
    ip.len() < 600 || ip.get(9) == Some(&1) || ip.get(1).is_some_and(|v| v >> 2 == 46)
}

fn bare_tcp_ack(ip: &[u8]) -> bool {
    if ip.first().is_none_or(|v| v >> 4 != 4) || ip.get(9) != Some(&6) {
        return false;
    }
    let iph = usize::from(ip[0] & 15) * 4;
    if iph < 20 || ip.len() < iph + 20 {
        return false;
    }
    let tcph = usize::from(ip[iph + 12] >> 4) * 4;
    tcph >= 20 && ip.len() == iph + tcph
}

// Small UDP packets carry realtime media (RTP, WebRTC audio/video, game state,
// Zoom/Teams/Discord). Duplicate them proactively so a link drop mid-call does
// not lose audio. Bulk QUIC and non-media UDP (DNS, NTP, DHCP, IKE) are excluded.
fn is_realtime_media(ip: &[u8]) -> bool {
    if ip.first().is_none_or(|v| v >> 4 != 4) || ip.get(9) != Some(&17) {
        return false;
    }
    let iph = usize::from(ip[0] & 15) * 4;
    if iph < 20 || ip.len() < iph + 8 || ip.len() >= 500 {
        return false;
    }
    let dst_port = u16::from_be_bytes([ip[iph + 2], ip[iph + 3]]);
    !matches!(dst_port, 53 | 67 | 68 | 123 | 137 | 138 | 500 | 4500 | 5353)
}

// Sizable UDP flows (SRT/RTMP-over-UDP, WebRTC video, gaming) reorder badly
// when consecutive packets take paths of unequal RTT. Return a 5-tuple key so
// the scheduler can pin each such flow to a single path. Small realtime UDP
// (VoIP, RTP audio, tiny game state) is intentionally excluded so that the
// proactive duplication path in tick() still protects it.
fn bulk_udp_flow_key(ip: &[u8]) -> Option<u128> {
    if ip.first().is_none_or(|v| v >> 4 != 4) || ip.get(9) != Some(&17) {
        return None;
    }
    let iph = usize::from(ip[0] & 15) * 4;
    if iph < 20 || ip.len() < iph + 8 || ip.len() < 500 {
        return None;
    }
    let dst_port = u16::from_be_bytes([ip[iph + 2], ip[iph + 3]]);
    if matches!(dst_port, 53 | 67 | 68 | 123 | 500 | 4500 | 5353) {
        return None;
    }
    let src_ip = u32::from_be_bytes(ip[12..16].try_into().ok()?);
    let dst_ip = u32::from_be_bytes(ip[16..20].try_into().ok()?);
    let src_port = u16::from_be_bytes([ip[iph], ip[iph + 1]]);
    Some(
        (u128::from(src_ip) << 96)
            | (u128::from(dst_ip) << 64)
            | (u128::from(src_port) << 48)
            | (u128::from(dst_port) << 32),
    )
}

// Any UDP 5-tuple, used only to *look up* an existing pin so that ACK/NAK/
// control packets in an ongoing media flow ride with the bulk stream instead
// of being duplicated as if they were an independent VoIP call.
fn udp_flow_key(ip: &[u8]) -> Option<u128> {
    if ip.first().is_none_or(|v| v >> 4 != 4) || ip.get(9) != Some(&17) {
        return None;
    }
    let iph = usize::from(ip[0] & 15) * 4;
    if iph < 20 || ip.len() < iph + 8 {
        return None;
    }
    let dst_port = u16::from_be_bytes([ip[iph + 2], ip[iph + 3]]);
    if matches!(dst_port, 53 | 67 | 68 | 123 | 500 | 4500 | 5353) {
        return None;
    }
    let src_ip = u32::from_be_bytes(ip[12..16].try_into().ok()?);
    let dst_ip = u32::from_be_bytes(ip[16..20].try_into().ok()?);
    let src_port = u16::from_be_bytes([ip[iph], ip[iph + 1]]);
    Some(
        (u128::from(src_ip) << 96)
            | (u128::from(dst_ip) << 64)
            | (u128::from(src_port) << 48)
            | (u128::from(dst_port) << 32),
    )
}

fn streaming(ip: &[u8]) -> bool {
    // Honor explicit video DSCP and recognizable RTMP/RTSP endpoints. Large
    // unmarked UDP/QUIC is not guessed to be video and is never duplicated.
    if ip
        .get(1)
        .is_some_and(|v| matches!(v >> 2, 34 | 36 | 38 | 40))
    {
        return true;
    }
    let Some(&version) = ip.first() else {
        return false;
    };
    if version >> 4 != 4
        || ip.get(9) != Some(&6)
        || ip.get(6).is_none_or(|v| v & 0x1f != 0)
        || ip.get(7) != Some(&0)
    {
        return false;
    }
    let header = usize::from(version & 15) * 4;
    if header < 20 || ip.len() < header + 4 {
        return false;
    }
    [
        u16::from_be_bytes([ip[header], ip[header + 1]]),
        u16::from_be_bytes([ip[header + 2], ip[header + 3]]),
    ]
    .iter()
    .any(|p| matches!(p, 554 | 1935))
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
    fn seventy_five_ms_path_remains_bulk_only_until_stable_recovery() {
        let mut s = unequal_latency();
        s.paths[1].rtt_ms = Some(75.0);
        s.receive(&Frame::control(Kind::Pong, 1, 100, 25), 100);
        assert_eq!(s.data_paths(100), vec![0, 1]);
        assert_eq!(s.targets(100, true, 100), vec![0]);
        assert!(s.targets(1200, false, 100).contains(&1));
        assert!(
            s.tick(100)
                .iter()
                .any(|f| f.kind == Kind::Probe && f.path == 1)
        );
        for now in 101..120 {
            s.receive(&Frame::control(Kind::Pong, 1, now, now - 40), now);
        }
        assert!(s.targets(100, true, 120).contains(&1));
    }
    #[test]
    fn all_high_latency_keeps_best_last_resort_instead_of_blackholing() {
        let mut s = unequal_latency();
        for p in &mut s.paths {
            p.latency_excluded = true;
        }
        assert_eq!(s.data_paths(100), vec![0, 1]);
        assert_eq!(s.targets(100, true, 100), vec![0]);
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
    fn voice_precedes_marked_stream_and_stream_precedes_bulk_without_video_duplication() {
        let mut s = unequal_latency();
        let mut video = bulk();
        video[1] = 34 << 2;
        let mut voice = packet();
        voice[1] = 46 << 2;
        s.enqueue(bulk());
        s.enqueue(video.clone());
        s.enqueue(voice.clone());
        let frames: Vec<_> = s
            .tick(100)
            .into_iter()
            .filter(|f| f.kind == Kind::Data)
            .collect();
        assert_eq!(frames[0].body, voice);
        let video_index = frames.iter().position(|f| f.body == video).unwrap();
        let bulk_index = frames.iter().position(|f| f.body == bulk()).unwrap();
        assert!(video_index < bulk_index);
        assert_eq!(frames.iter().filter(|f| f.body == video).count(), 1);
        let mut rtmp = bulk();
        rtmp[22..24].copy_from_slice(&1935_u16.to_be_bytes());
        assert!(streaming(&rtmp));
    }

    #[test]
    fn bulk_reserves_window_space_for_voice() {
        let mut s = unequal_latency();
        s.paths[0].congestion_window = 16 * BOND_MTU;
        s.paths[0].in_flight = 12 * BOND_MTU;
        s.paths[1].latency_excluded = true;
        assert!(!s.targets(BOND_MTU, false, 100).contains(&0));
        assert!(s.targets(200, true, 100).contains(&0));
    }

    #[test]
    fn brain_realtime_bias_expires_and_cannot_revive_failed_paths() {
        let mut s = unequal_latency();
        s.paths[1].rtt_ms = Some(25.0);
        s.set_realtime_advice(
            BTreeMap::from([("wifi".into(), 1), ("ethernet".into(), 64)]),
            110,
        );
        assert_eq!(s.targets(100, true, 100)[0], 1);
        assert_eq!(s.targets(100, true, 111)[0], 0);
        s.remove_path(1);
        assert_eq!(s.targets(100, true, 100), vec![0]);
    }

    #[test]
    fn added_queue_delay_reduces_bulk_window_but_high_baseline_rtt_does_not() {
        let mut p = Path::new(0, "wifi".into(), false);
        p.congestion_window = 1_000_000;
        p.observe(500, 300); // 200 ms baseline is not congestion.
        assert_eq!(p.congestion_window, 1_000_000);
        for now in 501..520 {
            p.observe(now, now - 240);
        }
        assert!(p.congestion_window < 1_000_000);
        let window = p.congestion_window;
        p.acknowledge_capacity(1200);
        assert_eq!(p.congestion_window, window);
        assert_eq!(p.timeouts, 0); // Do not label queue-delay backoff packet loss.
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
        // Loss with an elevated RTT is treated as real congestion and halves
        // the window; a second event inside repair_ms is folded into the first.
        s.paths[0].minimum_rtt_ms = 20.0;
        s.paths[0].rtt_ms = Some(60.0);
        s.paths[0].congestion_loss(200);
        assert_eq!(s.paths[0].congestion_window, 200_000);
        s.paths[0].congestion_loss(201);
        assert_eq!(s.paths[0].congestion_window, 200_000);
    }

    #[test]
    fn random_wifi_loss_does_not_collapse_the_window() {
        // A Wi-Fi path can lose a few percent of packets to radio noise while
        // keeping RTT flat. Kernel TCP CUBIC would ignore that; so must we,
        // otherwise cwnd shrinks to the floor and OBS collapses to <1 Mbps.
        let mut path = Path::new(0, "en0".into(), false);
        path.minimum_rtt_ms = 12.0;
        path.rtt_ms = Some(12.5);
        path.congestion_window = 400_000;
        path.slow_start_threshold = 400_000;
        let mut now = 100_u64;
        for _ in 0..50 {
            path.congestion_loss(now);
            now += path.repair_ms() + 1;
        }
        assert_eq!(
            path.congestion_window, 400_000,
            "isolated loss with flat RTT must not shrink the window"
        );
        // Once RTT climbs (real queue building), the next loss halves normally.
        path.rtt_ms = Some(60.0);
        now += path.repair_ms() + 1;
        path.congestion_loss(now);
        assert_eq!(path.congestion_window, 200_000);
    }

    #[test]
    fn capacity_discovery_grows_quickly_then_backs_off_on_real_loss() {
        let mut path = Path::new(0, "en0".into(), false);
        for _ in 0..512 {
            path.acknowledge_capacity(BOND_MTU);
        }
        assert_eq!(path.congestion_window, 544 * BOND_MTU);
        // Simulate a congestion signal, not radio noise: RTT is well above
        // the observed minimum, so the window halves per AIMD.
        path.minimum_rtt_ms = 10.0;
        path.rtt_ms = Some(40.0);
        path.congestion_loss(100);
        let reduced = path.congestion_window;
        assert_eq!(reduced, 272 * BOND_MTU);
        for _ in 0..272 {
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
    fn low_latency_link_grows_past_bdp_and_bare_tcp_acks_are_not_duplicated() {
        // Deployed relay telemetry 2026-09-09: LAN min RTT 3 ms was seeing
        // ~15 ms loaded, and the old 10 ms slack pinned cwnd to ~5 MTUs so a
        // single flow through the tunnel capped at ~9 Mbps. Under load the
        // window must reach several BDPs, not sit at the initial size.
        let mut path = Path::new(0, "en0".into(), false);
        path.rtt_ms = Some(3.0);
        path.minimum_rtt_ms = 3.0;
        for _ in 0..200 {
            path.observe(2, 0); // stays within delay slack, growth continues
            path.acknowledge_capacity(BOND_MTU);
        }
        assert!(
            path.congestion_window >= 200 * BOND_MTU,
            "cwnd only reached {} MTUs",
            path.congestion_window / BOND_MTU
        );

        // Empty TCP segment (bare ACK) must not be treated as interactive.
        let mut ack = vec![0_u8; 40];
        ack[0] = 0x45; // IPv4, IHL 5
        ack[9] = 6; // TCP
        ack[32] = 0x50; // TCP data offset 5 (20-byte TCP header)
        assert!(bare_tcp_ack(&ack));
        assert!(!interactive(&ack));
        // A short RTP packet still counts as interactive.
        let mut rtp = vec![0_u8; 200];
        rtp[0] = 0x45;
        rtp[9] = 17; // UDP
        assert!(interactive(&rtp));
    }

    #[test]
    fn realtime_media_classifier_matches_rtp_and_excludes_bulk_and_infra() {
        let mut rtp = vec![0_u8; 200];
        rtp[0] = 0x45;
        rtp[9] = 17;
        rtp[22..24].copy_from_slice(&8801_u16.to_be_bytes()); // Zoom media port
        assert!(is_realtime_media(&rtp));

        let mut dns = vec![0_u8; 90];
        dns[0] = 0x45;
        dns[9] = 17;
        dns[22..24].copy_from_slice(&53_u16.to_be_bytes());
        assert!(!is_realtime_media(&dns));

        let mut big_quic = vec![0_u8; 1200];
        big_quic[0] = 0x45;
        big_quic[9] = 17;
        big_quic[22..24].copy_from_slice(&443_u16.to_be_bytes());
        assert!(!is_realtime_media(&big_quic));

        let mut tcp = vec![0_u8; 200];
        tcp[0] = 0x45;
        tcp[9] = 6;
        assert!(!is_realtime_media(&tcp));
    }

    #[test]
    fn smart_duplicates_small_udp_media_before_any_degradation() {
        let mut s = scheduler(Policy::Smart);
        let mut voice = vec![0_u8; 200];
        voice[0] = 0x45;
        voice[9] = 17;
        voice[22..24].copy_from_slice(&8801_u16.to_be_bytes());
        s.enqueue(voice);
        let sent: Vec<_> = s
            .tick(31)
            .into_iter()
            .filter(|f| f.kind == Kind::Data)
            .collect();
        assert_eq!(
            sent.len(),
            2,
            "voice must ride both links so a link drop is invisible"
        );
        assert_ne!(sent[0].path, sent[1].path);
    }

    #[test]
    fn smart_does_not_duplicate_bulk_or_dns_under_realtime_rule() {
        let mut s = scheduler(Policy::Smart);
        let mut dns = vec![0_u8; 90];
        dns[0] = 0x45;
        dns[9] = 17;
        dns[22..24].copy_from_slice(&53_u16.to_be_bytes());
        s.enqueue(dns);
        assert_eq!(
            s.tick(31).iter().filter(|f| f.kind == Kind::Data).count(),
            1
        );

        let mut s = scheduler(Policy::Smart);
        let mut big = vec![0_u8; 1200];
        big[0] = 0x45;
        big[9] = 17;
        big[22..24].copy_from_slice(&443_u16.to_be_bytes());
        s.enqueue(big);
        assert_eq!(
            s.tick(31).iter().filter(|f| f.kind == Kind::Data).count(),
            1
        );
    }

    #[test]
    fn data_saver_never_duplicates_even_realtime_media() {
        let mut s = scheduler(Policy::DataSaver);
        let mut voice = vec![0_u8; 200];
        voice[0] = 0x45;
        voice[9] = 17;
        voice[22..24].copy_from_slice(&8801_u16.to_be_bytes());
        s.enqueue(voice);
        assert_eq!(
            s.tick(31).iter().filter(|f| f.kind == Kind::Data).count(),
            1
        );
    }
    fn srt_packet(sport: u16, dport: u16, seed: u8) -> Vec<u8> {
        let mut p = vec![seed; 1200];
        p[0] = 0x45;
        p[9] = 17; // UDP
        p[12..16].copy_from_slice(&[10, 0, 0, 2]);
        p[16..20].copy_from_slice(&[69, 164, 208, 201]);
        p[20..22].copy_from_slice(&sport.to_be_bytes());
        p[22..24].copy_from_slice(&dport.to_be_bytes());
        p
    }
    #[test]
    fn bulk_udp_flow_key_ignores_small_udp_and_infra_ports() {
        assert!(bulk_udp_flow_key(&srt_packet(50000, 9000, 0)).is_some());
        let mut small = srt_packet(50000, 9000, 0);
        small.truncate(300);
        assert!(bulk_udp_flow_key(&small).is_none());
        let mut dns = srt_packet(50000, 53, 0);
        assert!(bulk_udp_flow_key(&dns).is_none());
        dns[22..24].copy_from_slice(&123_u16.to_be_bytes());
        assert!(bulk_udp_flow_key(&dns).is_none());
        let mut tcp = srt_packet(50000, 9000, 0);
        tcp[9] = 6;
        assert!(bulk_udp_flow_key(&tcp).is_none());
    }
    #[test]
    fn bulk_udp_flow_pins_every_packet_to_the_first_chosen_path() {
        let mut s = unequal_latency();
        for seed in 0..8_u8 {
            s.enqueue(srt_packet(50000, 9000, seed));
        }
        let paths: Vec<u8> = s
            .tick(120)
            .into_iter()
            .filter(|f| f.kind == Kind::Data)
            .map(|f| f.path)
            .collect();
        assert_eq!(paths.len(), 8);
        assert!(
            paths.iter().all(|&p| p == paths[0]),
            "SRT flow was sprayed across paths: {paths:?}"
        );
    }
    #[test]
    fn distinct_udp_flows_pin_independently() {
        let mut s = unequal_latency();
        s.enqueue(srt_packet(50000, 9000, 1));
        let first = s
            .tick(120)
            .into_iter()
            .find(|f| f.kind == Kind::Data)
            .unwrap()
            .path;
        // Even if a second flow lands on the same (best) path, it must not be
        // pinned to the first flow's slot: force the best path to look busier
        // and check the second flow can still take a different path.
        s.paths[first as usize].in_flight = s.paths[first as usize].congestion_window - 500;
        s.enqueue(srt_packet(50001, 9100, 2));
        let second = s
            .tick(122)
            .into_iter()
            .find(|f| f.kind == Kind::Data)
            .unwrap()
            .path;
        assert_ne!(second, first);
    }
    #[test]
    fn pinned_udp_flow_migrates_when_pinned_path_fails() {
        let mut s = unequal_latency();
        s.enqueue(srt_packet(50000, 9000, 1));
        let first = s
            .tick(120)
            .into_iter()
            .find(|f| f.kind == Kind::Data)
            .unwrap()
            .path;
        s.fail_path(first as usize);
        s.enqueue(srt_packet(50000, 9000, 2));
        let second = s
            .tick(122)
            .into_iter()
            .find(|f| f.kind == Kind::Data)
            .unwrap()
            .path;
        assert_ne!(second, first);
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
        // Bulk TCP so duplication is not triggered; the repair path is what is under test.
        let mut tx = scheduler(Policy::Smart);
        let mut rx = scheduler(Policy::Smart);
        tx.enqueue(bulk());
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
        assert_eq!(rx.counters.delivered_bytes, 1200);
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
        scheduler.tick(400);
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
