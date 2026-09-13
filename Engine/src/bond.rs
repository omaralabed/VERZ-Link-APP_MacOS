//! Multipath IP scheduling primitives. Time is monotonic milliseconds supplied
//! by the runtime, allowing deterministic failure/recovery tests without sleeps.
//! Path ACKs measure delivered tunnel bytes, not application-level TCP goodput.
use crate::ReplayWindow;
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

#[cfg(test)]
#[path = "tcp_scheduler_tests.rs"]
mod tcp_scheduler_tests;

// Inner IP MTU, not the encrypted UDP datagram size. QUIC needs at least a
// 1,200-byte UDP payload PLUS IP/UDP headers. 1,280 supports that minimum;
// the framing/encryption overhead is budgeted separately by transport().
pub const BOND_MTU: usize = crate::tunnel::MTU;
/// Wire IDs support 256 distinct adapter paths per device session. Allocation
/// is dynamic; ordinary multi-adapter Macs do not pay for unused path slots.
pub const MAX_PATHS: usize = 256;
pub const MAX_PENDING: usize = 4096;
const MAX_FLOW_PINS: usize = 4096;
pub const FEATURE_ACK_BATCH: u64 = 512;
pub const FEATURE_UDP_LANE: u64 = 1024;
/// Negotiates authenticated path-loss notifications. This is deliberately a
/// separate ready message instead of relying on JoinAck echoing an unknown bit,
/// so a new client never mistakes an older relay for a capable peer.
pub const FEATURE_PATH_FAILURE: u64 = 2048;
pub const UDP_ENVELOPE: usize = verz_link_core::HEADER + verz_link_core::TAG;
const PROBE_MS: u64 = 20;
// Once another path is answering, stop placing new traffic on a silent path
// soon enough to leave delivery headroom inside the 100 ms failover gate.
const FAST_SILENCE_MS: u64 = 60;
pub const LATENCY_CUTOFF_MS: f64 = 75.0;
const PACKET_TTL_MS: u64 = 1000;
const UDP_FLOW_TTL_MS: u64 = 30_000;
const SRT_FLOW_TTL_MS: u64 = 120_000;
const FRAGMENT_FLOW_TTL_MS: u64 = 2_000;
// A cable can report carrier and DHCP before its route/NAT path has settled.
// Keep a returning, previously-used adapter probe-only until it has answered
// continuously for REJOIN_STABLE_MS (no response gap above FAST_SILENCE_MS),
// and never longer than REJOIN_PROBATION_MS. The macOS app additionally waits
// for a DHCP lease to be BOUND before offering the adapter at all.
const REJOIN_PROBATION_MS: u64 = 5_000;
const REJOIN_STABLE_MS: u64 = 1_500;
// The first protection copy to be acknowledged completes delivery, but the
// later acknowledgement from the other path is still valuable evidence that
// the standby path can carry traffic. Keep a bounded, short-lived ledger so
// both paths learn their real RTT/capacity without retaining delivered packets
// in the repair queue.
const RECENT_ACK_TTL_MS: u64 = 1_000;
const MAX_RECENT_ACKS: usize = 32_768;
const FAST_ACK_THRESHOLD: u8 = 2;
// RACK-style same-path evidence for paced traffic: if a packet sent at least
// this much later is delivered on the same UDP subflow, the earlier hole can
// be repaired without waiting for the coarse loss deadline. Packets emitted
// in the same scheduler burst still require FAST_ACK_THRESHOLD later ACKs.
const FAST_ACK_SEND_DELTA_MS: u64 = 10;
const FAST_ACK_SCAN: usize = 8;
// Continuity duplicates low-rate TCP before a failure, because retransmission
// can never make an already-lost segment arrive with zero delay. The shared
// token bucket caps extra wire traffic at about 2 Mbps with a short burst;
// high-rate TCP therefore keeps essentially all capacity for normal bonding.
const TCP_CONTINUITY_BYTES_PER_MS: u64 = 256;
const TCP_CONTINUITY_BURST_BYTES: u64 = (64 * BOND_MTU) as u64;
// A standing queue keeps every RTT sample elevated. A Wi-Fi radio that goes
// off-channel (AWDL slots, roaming/full-band scans after an IPv4 change)
// delays a burst instead: when it returns, the last packets sent before the
// return arrive with near-minimum RTT within the same burst. Only an
// uninterrupted run of elevated samples at least this long counts as queueing.
const QUEUE_PERSIST_MS: u64 = 100;
// Recent longest silence between authenticated responses on a path. Physical
// evidence 2026-09-12: 65-73 ms holes every ~0.5 s and 100-200 ms scan dwells
// on a lone Wi-Fi survivor produced hundreds of repairs of packets that then
// arrived anyway. The repair deadline must cover the pauses actually observed.
const PAUSE_BUCKET_MS: u64 = 1000;
const PAUSE_BUCKETS: usize = 4;
const MAX_PAUSE_REPAIR_MS: u64 = 300;
const FRAME_HEADER: usize = 18;

pub fn handshake(
    secret: &[u8; 32],
    session: &[u8; 16],
    initiator: bool,
) -> Result<snow::HandshakeState> {
    let mut prologue =
        format!("VERZ Link multipath v2 / authenticated IPv4 lease / MTU{BOND_MTU} / ")
            .into_bytes();
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

/// Both peers must use the matching authenticated MTU/framing version.
pub fn transport(
    session: [u8; 16],
    noise: snow::HandshakeState,
) -> Result<crate::tunnel::Transport> {
    crate::tunnel::Transport::with_payload_limit(
        session,
        noise,
        FRAME_HEADER + BOND_MTU + UDP_ENVELOPE,
    )
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
    Udp = 9,
    UdpReady = 10,
    PathFailureReady = 11,
    PathDown = 12,
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
            (FRAME_HEADER..=FRAME_HEADER + BOND_MTU + UDP_ENVELOPE).contains(&bytes.len()),
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
            9 => Kind::Udp,
            10 => Kind::UdpReady,
            11 => Kind::PathFailureReady,
            12 => Kind::PathDown,
            _ => anyhow::bail!("invalid multipath frame type"),
        };
        ensure!(
            if kind == Kind::Udp {
                bytes.len() >= FRAME_HEADER + UDP_ENVELOPE
            } else if kind == Kind::Data {
                (FRAME_HEADER + 20..=FRAME_HEADER + BOND_MTU).contains(&bytes.len())
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

#[derive(Clone, Debug, Default, Serialize)]
pub struct WindowControl {
    pub delay_reductions: u64,
    pub loss_reductions: u64,
    pub idle_delay_observations: u64,
    pub app_limited_delay_observations: u64,
    pub app_limited_growth_acks: u64,
    pub growth_paused_acks: u64,
    pub last_reduction: Option<WindowReduction>,
}

#[derive(Clone, Debug, Serialize)]
pub struct WindowReduction {
    pub reason: &'static str,
    pub at_ms: u64,
    pub before_bytes: usize,
    pub after_bytes: usize,
    pub in_flight_bytes: usize,
    pub rtt_ms: Option<f64>,
    pub minimum_rtt_ms: f64,
    pub jitter_ms: f64,
}

/// Peak of a value over the most recent PAUSE_BUCKETS time buckets.
#[derive(Clone, Debug, Default)]
struct RecentPeak {
    start: u64,
    values: [u64; PAUSE_BUCKETS],
}
impl RecentPeak {
    fn push(&mut self, now: u64, value: u64) {
        let elapsed = (now.saturating_sub(self.start) / PAUSE_BUCKET_MS) as usize;
        if elapsed > 0 {
            let shift = elapsed.min(PAUSE_BUCKETS);
            self.values.rotate_right(shift);
            self.values[..shift].fill(0);
            self.start = self
                .start
                .saturating_add(elapsed as u64 * PAUSE_BUCKET_MS);
        }
        self.values[0] = self.values[0].max(value);
    }
    fn peak(&self) -> u64 {
        self.values.iter().copied().max().unwrap_or(0)
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
    /// True only after an uninterrupted QUEUE_PERSIST_MS run of samples above
    /// the delay slack; transient radio holes never set it.
    pub queue_persistent: bool,
    /// Longest recent gap between responses, in ms; extends the repair deadline.
    pub response_pause_ms: u64,
    pub acknowledged_bytes: u64,
    pub sent_bytes: u64,
    pub received_bytes: u64,
    pub delivery_bps: f64,
    /// Unique, first-ACKed bulk TCP tunnel bytes during a loaded sample.
    /// Not application goodput, and never includes late duplicate ACKs.
    pub tcp_delivery_bps: f64,
    #[serde(skip)]
    tcp_rate: TcpRate,
    pub in_flight: usize,
    pub congestion_window: usize,
    pub slow_start_threshold: usize,
    pub timeouts: u64,
    pub latency_excluded: bool,
    pub window_control: WindowControl,
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
    #[serde(skip)]
    capacity_used_until: Option<u64>,
    #[serde(skip)]
    probation_until: Option<u64>,
    #[serde(skip)]
    probation_stable_since: Option<u64>,
    #[serde(skip)]
    elevated_since: Option<u64>,
    #[serde(skip)]
    pauses: RecentPeak,
    // Every physical/socket re-admission is a new path incarnation. Pending
    // packets from an older incarnation must never release or train the new
    // incarnation's congestion state when their delayed ACKs arrive.
    #[serde(skip)]
    generation: u64,
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
            queue_persistent: false,
            response_pause_ms: 0,
            acknowledged_bytes: 0,
            sent_bytes: 0,
            received_bytes: 0,
            delivery_bps: 0.0,
            tcp_delivery_bps: 0.0,
            tcp_rate: TcpRate::default(),
            in_flight: 0,
            // 300 Mbps at 3 ms LAN RTT needs ~112 KB in flight to fill; the
            // previous 16 MTU (~19 KB) start capped throughput to ~50 Mbps
            // for the first many RTTs before growth caught up.
            congestion_window: 32 * BOND_MTU,
            slow_start_threshold: 4 * 1024 * 1024,
            timeouts: 0,
            latency_excluded: false,
            window_control: WindowControl::default(),
            last_response: None,
            good_samples: 0,
            next_send: 0.0,
            rate_started: 0,
            rate_bytes: 0,
            last_congestion: None,
            growth_credit: 0,
            last_delay_adjust: None,
            capacity_used_until: None,
            probation_until: None,
            probation_stable_since: None,
            elevated_since: None,
            pauses: RecentPeak::default(),
            generation: 0,
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
        let jitter_based =
            (self.rtt_ms.unwrap_or(30.0) + 4.0 * self.jitter_ms + 20.0).max(70.0) as u64;
        // A packet sent just before a radio hole is not lost until the hole
        // is over. Same-path fast-ACK evidence still repairs real loss sooner.
        let pause_based = self
            .response_pause_ms
            .saturating_add(20)
            .min(MAX_PAUSE_REPAIR_MS);
        jitter_based.max(pause_based)
    }
    fn recently_responding(&self, now: u64) -> bool {
        // Continuous probes should produce a response every 20 ms even on a
        // high-baseline-RTT path once the pipeline is established. ACKs also
        // refresh this clock while the path is carrying traffic. When another
        // path is fresh, historical jitter must not stretch failover to
        // seconds. Do not blackhole the only usable path; data_paths() retains
        // it until the wider failure deadline when no fresh alternate exists.
        let grace = FAST_SILENCE_MS.min(self.failure_ms());
        self.last_response
            .is_some_and(|last| now.saturating_sub(last) <= grace)
    }
    // How far above minimum RTT a sample must sit before we call it queueing.
    // Cellular RAN scheduling routinely adds 20-40 ms above the minimum with
    // low measured jitter (samples cluster), so a jitter-only slack is not
    // enough. Scale with the link's baseline latency as well: LAN keeps a
    // tight 15 ms floor; hotspot links (min RTT ~15-30 ms) get room to
    // breathe without any of that being read as congestion.
    fn queue_slack_ms(&self, floor: f64) -> f64 {
        let baseline = self.minimum_rtt_ms.clamp(0.0, 15.0) * 2.0;
        // 4x jitter (was 3x): iPhone hotspot scheduling swings 20-40 ms above
        // min RTT with ~10 ms jitter samples; 3x under-covered the tail.
        floor.max(4.0 * self.jitter_ms).max(baseline)
    }
    pub fn ready(&self, now: u64) -> bool {
        self.enabled
            && self.probation_until.is_none()
            && self.good_samples >= 3
            && self
                .last_response
                .is_some_and(|last| now.saturating_sub(last) <= self.failure_ms())
    }
    fn observe(&mut self, now: u64, stamp: u64) {
        if stamp > now {
            return;
        }
        self.note_capacity_use(now);
        let pause = self.last_response.map(|last| now.saturating_sub(last));
        match self.probation_until {
            // u64::MAX means the adapter has rejoined but has not returned its
            // first authenticated response yet. Start the hold from that
            // response, not from a potentially early macOS carrier event.
            Some(u64::MAX) => {
                self.probation_until = Some(now.saturating_add(REJOIN_PROBATION_MS));
                self.probation_stable_since = Some(now);
            }
            Some(until) if now >= until => {
                self.probation_until = None;
                self.probation_stable_since = None;
            }
            Some(_) => {
                if pause.is_some_and(|pause| pause > FAST_SILENCE_MS) {
                    self.probation_stable_since = Some(now);
                }
                let since = *self.probation_stable_since.get_or_insert(now);
                if now.saturating_sub(since) >= REJOIN_STABLE_MS {
                    self.probation_until = None;
                    self.probation_stable_since = None;
                }
            }
            None => {}
        }
        if let Some(pause) = pause {
            self.pauses.push(now, pause);
            self.response_pause_ms = self.pauses.peak();
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
        // Scale by observed jitter so cellular scheduling swings (routinely
        // 20-40 ms above min RTT on iPhone hotspots) are not misread as
        // queue growth and made to shrink cwnd.
        const DELAY_SLACK_MS: f64 = 30.0;
        let delay_slack = self.queue_slack_ms(DELAY_SLACK_MS);
        if sample - self.minimum_rtt_ms > delay_slack {
            let since = *self.elevated_since.get_or_insert(now);
            self.queue_persistent = now.saturating_sub(since) >= QUEUE_PERSIST_MS;
        } else {
            self.elevated_since = None;
            self.queue_persistent = false;
        }
        if self.queue_persistent
            && self
                .last_delay_adjust
                .is_none_or(|last| now.saturating_sub(last) as f64 >= rtt)
        {
            if self.in_flight == 0 {
                // Heartbeats measure reachability/RTT, not the capacity used
                // by a data transfer. With no data outstanding they must not
                // repeatedly reduce cwnd and end slow start before it begins.
                // Do not increase cwnd here either. Actual sends remain paced,
                // and active-transfer delay/loss responses are preserved.
                self.window_control.idle_delay_observations += 1;
            } else if !self.delay_sample_is_loaded(now) {
                // A probe or tiny ACK tail cannot have built a large queue.
                // Recent historical load alone is insufficient: hot-plug and
                // event-loop delay otherwise cut a survivor's validated TCP
                // window while only a few bytes are actually outstanding.
                // RTT/liveness/pacing still update on these samples.
                self.window_control.app_limited_delay_observations += 1;
            } else {
                let before = self.congestion_window;
                let ratio = ((self.minimum_rtt_ms + delay_slack) / rtt).clamp(0.75, 0.95);
                // A floor for delay reduction must not increase a window that
                // a previous loss response already reduced below that floor.
                self.congestion_window = ((before as f64 * ratio) as usize)
                    .max(16 * BOND_MTU)
                    .min(before);
                self.slow_start_threshold = self.congestion_window;
                self.growth_credit = 0;
                self.last_delay_adjust = Some(now);
                self.record_window_reduction("rtt_delay", before, now);
            }
        }
        self.last_response = Some(now);
        self.good_samples = self.good_samples.saturating_add(1);
        if self.rtt_ms.unwrap_or(sample) >= LATENCY_CUTOFF_MS {
            self.latency_excluded = true;
        } else if self.rtt_ms.unwrap_or(sample) < 65.0 && self.good_samples >= 3 {
            self.latency_excluded = false;
        }
        self.state = if self.good_samples < 3 || self.probation_until.is_some() {
            "recovering"
        } else if self.rtt_ms.unwrap_or(sample) - self.minimum_rtt_ms > self.queue_slack_ms(15.0) {
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

    fn tcp_bytes_per_ms(&self, now: u64) -> f64 {
        let window_rate = self.estimated_bytes_per_ms();
        if self
            .tcp_rate
            .sampled_at
            .is_some_and(|at| now.saturating_sub(at) <= 1000)
            && self.tcp_delivery_bps > 0.0
        {
            // Loaded delivery is a better ordering estimate than an inflated
            // cwnd. Leave 25% exploration headroom; this does NOT cap pacing
            // or cwnd growth. Quiet/old samples must not pin a path to a low rate.
            window_rate
                .min(self.tcp_delivery_bps / 8000.0 * 1.25)
                .max(1.0)
        } else {
            window_rate
        }
    }

    fn tcp_sent(&mut self, now: u64) {
        if self
            .tcp_rate
            .started
            .is_none_or(|start| now.saturating_sub(start) > 1000)
        {
            self.tcp_rate.started = Some(now);
            self.tcp_rate.bytes = 0;
            self.tcp_rate.loaded = false;
        }
        self.tcp_rate.loaded |= self.capacity_recently_used(now);
    }

    fn tcp_acked(&mut self, bytes: usize, now: u64) {
        let Some(start) = self.tcp_rate.started else {
            return;
        };
        self.tcp_rate.bytes += bytes as u64;
        self.tcp_rate.loaded |= self.capacity_recently_used(now);
        let elapsed = now.saturating_sub(start);
        let window = (2.0 * self.rtt_ms.unwrap_or(30.0)).clamp(50.0, 500.0) as u64;
        if elapsed >= window {
            if elapsed <= 1000
                && self.tcp_rate.loaded
                && self.tcp_rate.bytes >= (8 * BOND_MTU) as u64
            {
                let sample = self.tcp_rate.bytes as f64 * 8000.0 / elapsed as f64;
                self.tcp_delivery_bps = if self.tcp_delivery_bps == 0.0 {
                    sample
                } else {
                    0.75 * self.tcp_delivery_bps + 0.25 * sample
                };
                self.tcp_rate.sampled_at = Some(now);
            }
            self.tcp_rate.started = Some(now);
            self.tcp_rate.bytes = 0;
            self.tcp_rate.loaded = false;
        }
    }

    fn tcp_forward_ms(&self, now: u64, bytes: usize) -> f64 {
        self.rtt_ms.unwrap_or(30.0) / 2.0
            + self.jitter_ms
            + bytes as f64 / self.tcp_bytes_per_ms(now)
    }

    fn tcp_send_wait_ms(&self, bytes: usize, now: u64) -> f64 {
        let paced = (self.next_send - now as f64).max(0.0);
        // ECF-style conservative window wait. The bounded per-flow hold
        // below prevents continuously answering probes from creating a deadlock.
        if self.in_flight.saturating_add(bytes) > self.send_window_limit(bytes, false) {
            paced.max(self.rtt_ms.unwrap_or(30.0))
        } else {
            paced
        }
    }

    fn note_capacity_use(&mut self, now: u64) {
        if self.in_flight.saturating_mul(2) >= self.congestion_window {
            // Retain utilization for delayed tail ACKs, not just the current
            // shrinking flight. Expire it promptly after traffic goes quiet.
            let horizon = (2.0 * self.rtt_ms.unwrap_or(30.0)).clamp(20.0, 1000.0) as u64;
            self.capacity_used_until = Some(now.saturating_add(horizon));
        }
    }

    fn capacity_recently_used(&self, now: u64) -> bool {
        self.in_flight.saturating_mul(2) >= self.congestion_window
            || self.capacity_used_until.is_some_and(|until| now <= until)
    }

    fn delay_sample_is_loaded(&self, now: u64) -> bool {
        let minimum_flight = (self.congestion_window / 8).clamp(4 * BOND_MTU, 64 * BOND_MTU);
        self.in_flight >= minimum_flight && self.capacity_recently_used(now)
    }

    fn send_budget_allows(&self, bytes: usize, interactive: bool, now: u64) -> bool {
        self.in_flight.saturating_add(bytes) <= self.send_window_limit(bytes, interactive)
            && self.next_send <= now as f64
    }

    fn send_window_limit(&self, bytes: usize, interactive: bool) -> usize {
        let reserve = if interactive {
            0
        } else {
            (4 * BOND_MTU)
                .min(self.congestion_window / 4)
                .min(self.congestion_window.saturating_sub(bytes))
        };
        self.congestion_window.saturating_sub(reserve)
    }

    fn acknowledge_capacity(&mut self, bytes: usize) {
        // Pause growth only when backoff would also trigger, not on any
        // transient queue.
        if self.queue_persistent {
            self.window_control.growth_paused_acks += 1;
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

    fn repair_timeout(&mut self, now: u64, allow_window_backoff: bool) {
        if self
            .last_congestion
            .is_some_and(|last| now.saturating_sub(last) < self.repair_ms())
        {
            return;
        }
        self.timeouts += 1;
        self.last_congestion = Some(now);
        // When this is the only responsive copy/path, a missing tunnel ACK is
        // not enough to distinguish radio loss, a short host scheduling pause,
        // or real congestion. Keep recording and repairing the loss, but let
        // the continuously measured RTT/queue delay control the window. This
        // prevents failover from destroying the sole surviving path's capacity.
        if !allow_window_backoff {
            return;
        }
        // Distinguish random wireless loss from real congestion. On Wi-Fi and
        // cellular, isolated losses come from radio noise and MAC retries with
        // no queue growth, so halving cwnd on every timeout collapses the
        // window and the whole flow stalls. This experimental delay-gated
        // policy is NOT TCP CUBIC (which responds to loss). Its loss-only
        // congestion behavior still needs controlled load/fairness validation.
        // A loss during a persistent queue is congestion; a repair fired
        // because a radio hole delayed the ACK is not.
        if !self.queue_persistent {
            return;
        }
        let before = self.congestion_window;
        self.slow_start_threshold = (self.congestion_window / 2).max(8 * BOND_MTU);
        self.congestion_window = self.slow_start_threshold;
        self.growth_credit = 0;
        self.record_window_reduction("loss_timeout", before, now);
    }

    fn record_window_reduction(&mut self, reason: &'static str, before: usize, now: u64) {
        if self.congestion_window >= before {
            return;
        }
        if reason == "rtt_delay" {
            self.window_control.delay_reductions += 1;
        } else {
            self.window_control.loss_reductions += 1;
        }
        self.window_control.last_reduction = Some(WindowReduction {
            reason,
            at_ms: now,
            before_bytes: before,
            after_bytes: self.congestion_window,
            in_flight_bytes: self.in_flight,
            rtt_ms: self.rtt_ms,
            minimum_rtt_ms: self.minimum_rtt_ms,
            jitter_ms: self.jitter_ms,
        });
    }
}

#[derive(Clone, Debug, Default)]
struct TcpRate {
    started: Option<u64>,
    bytes: u64,
    loaded: bool,
    sampled_at: Option<u64>,
}

#[derive(Default)]
struct TcpFlowSchedule {
    waiting_since: Option<u64>,
    last_arrival: f64,
    touched: u64,
}

struct Pending {
    body: Vec<u8>,
    born: u64,
    attempts: BTreeMap<usize, Attempt>,
    last_repair: u64,
    // A second healthy path may be paced/window-limited on the first tick.
    // Keep only its index: reuse the bounded pending packet's existing body.
    protection_path: Option<usize>,
    tcp_early_repair_deferred: bool,
    // Uniquely delivered higher packet IDs from this same inner TCP flow and
    // outer path are selective loss evidence. Other flows and paths never
    // contribute, because their independent timing is expected to differ.
    fast_ack_evidence: BTreeMap<usize, u8>,
    fast_repair_path: Option<usize>,
    repaired: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Attempt {
    stamp: u64,
    generation: u64,
}

struct RecentAttempt {
    bytes: usize,
    born: u64,
    stamp: u64,
    generation: u64,
    expires: u64,
}

#[derive(Default, Serialize)]
pub struct Counters {
    pub delivered_packets: u64,
    pub delivered_bytes: u64,
    pub duplicates: u64,
    pub repairs: u64,
    pub protection_copies: u64,
    pub protection_deferred: u64,
    pub protection_deferred_sent: u64,
    pub queue_drops: u64,
    pub queue_scans: u64,
    pub budget_blocked_turns: u64,
    pub tcp_path_waits: u64,
    pub tcp_bounded_wait_fallbacks: u64,
    pub tcp_same_path_repairs: u64,
    pub tcp_fast_ack_repairs: u64,
    /// Unique TCP packets whose placement-only exclusion would have caused
    /// an early repair. Counts decisions, not lost bytes or useful throughput.
    pub tcp_early_repairs_deferred: u64,
    /// Deferred packets ACKed before any repair was sent. This distinguishes
    /// avoided retransmissions from merely delaying a necessary recovery.
    pub tcp_early_deferrals_acked: u64,
    pub tcp_deadline_repairs: u64,
    pub tcp_unavailable_path_repairs: u64,
    /// New packets refused before acknowledgement; the sender may retry them.
    pub receive_backpressure: u64,
    pub socket_backpressure: u64,
    pub expired_packets: u64,
    pub path_failures: u64,
    pub path_down_notices_sent: u64,
    pub path_down_notices_received: u64,
}

pub struct Scheduler {
    pub paths: Vec<Path>,
    pub policy: Policy,
    pub counters: Counters,
    pending: BTreeMap<u64, Pending>,
    // Attempts on redundant paths whose packet was already acknowledged by a
    // different path. A late ACK trains the path that actually delivered the
    // standby copy; it must not be discarded merely because delivery already
    // completed through the faster path.
    recent_attempts: BTreeMap<(u64, usize), RecentAttempt>,
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
    // SRT has no fixed port. Learn it from authenticated SRT control headers,
    // then protect every packet in that UDP 5-tuple on a second live path.
    srt_flows: BTreeMap<u128, u64>,
    // Inner UDP packets may be fragmented to preserve the outer tunnel MTU.
    // Associate each IPv4 fragment ID with its first fragment's UDP 5-tuple so
    // every fragment retains both flow placement and continuity treatment.
    fragment_flows: BTreeMap<u128, (u128, u64)>,
    tcp_flows: BTreeMap<[u8; 12], TcpFlowSchedule>,
    // Local failures are announced by the runtime over every surviving path.
    // A set makes repeated carrier/socket observations idempotent.
    path_failure_notices: BTreeSet<usize>,
    tcp_continuity_tokens: u64,
    tcp_continuity_refill_at: u64,
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
            recent_attempts: BTreeMap::new(),
            queued: VecDeque::new(),
            urgent: VecDeque::new(),
            streaming: VecDeque::new(),
            received: ReplayWindow::new(16384),
            next_id: 0,
            last_probe: None,
            realtime_advice: BTreeMap::new(),
            advice_until: 0,
            flow_paths: BTreeMap::new(),
            srt_flows: BTreeMap::new(),
            fragment_flows: BTreeMap::new(),
            tcp_flows: BTreeMap::new(),
            path_failure_notices: BTreeSet::new(),
            tcp_continuity_tokens: TCP_CONTINUITY_BURST_BYTES,
            tcp_continuity_refill_at: 0,
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
            let path = &mut self.paths[index];
            if !path.enabled || path.state == "failed" || path.state == "removed" {
                let previously_used =
                    path.sent_bytes > 0 || path.received_bytes > 0 || path.acknowledged_bytes > 0;
                // A returned interface must rediscover capacity. Reusing its
                // pre-failure multi-megabyte window releases a burst large
                // enough to overflow the relay TUN queue and stall live SRT.
                path.state = "discovering";
                path.rtt_ms = None;
                path.jitter_ms = 0.0;
                path.minimum_rtt_ms = f64::MAX;
                path.delivery_bps = 0.0;
                path.tcp_delivery_bps = 0.0;
                path.tcp_rate = TcpRate::default();
                path.in_flight = 0;
                path.congestion_window = 32 * BOND_MTU;
                path.slow_start_threshold = 4 * 1024 * 1024;
                path.last_response = None;
                path.good_samples = 0;
                path.next_send = 0.0;
                path.rate_started = 0;
                path.rate_bytes = 0;
                path.last_congestion = None;
                path.growth_credit = 0;
                path.last_delay_adjust = None;
                path.capacity_used_until = None;
                path.queue_persistent = false;
                path.elevated_since = None;
                path.response_pause_ms = 0;
                path.pauses = RecentPeak::default();
                path.probation_until = previously_used.then_some(u64::MAX);
                path.probation_stable_since = None;
                path.generation = path.generation.wrapping_add(1);
            }
            path.enabled = true;
            path.metered = metered;
            // A real Join/re-add supersedes any unsent failure notice from the
            // previous incarnation of this path.
            self.path_failure_notices.remove(&index);
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
    pub fn queued_packets(&self) -> usize {
        self.urgent.len() + self.streaming.len() + self.queued.len()
    }
    pub fn has_received(&self, id: u64) -> bool {
        self.received.contains(id)
    }
    pub fn fail_path(&mut self, path: usize) {
        self.mark_path_failed(path, true);
    }
    /// Apply an authenticated failure learned from the peer. Never announce it
    /// again: echoing PathDown would create a control loop during rejoin.
    pub fn fail_path_remote(&mut self, path: usize) -> bool {
        let changed = self.mark_path_failed(path, false);
        if changed {
            self.counters.path_down_notices_received += 1;
        }
        changed
    }
    fn mark_path_failed(&mut self, path: usize, announce: bool) -> bool {
        let failing = path;
        let Some(path) = self.paths.get_mut(path) else {
            return false;
        };
        let changed = path.state != "failed";
        if changed {
            self.counters.path_failures += 1;
            if announce {
                self.path_failure_notices.insert(failing);
            }
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
        changed
    }
    /// Build three tiny authenticated notifications on every live survivor.
    /// If capability negotiation failed, discard them for compatibility. If no
    /// survivor is ready yet, retain them until a later tick can deliver them.
    pub fn path_failure_notices(&mut self, negotiated: bool, now: u64) -> Vec<Frame> {
        if !negotiated {
            self.path_failure_notices.clear();
            return Vec::new();
        }
        let survivors = self.data_paths(now);
        if survivors.is_empty() {
            return Vec::new();
        }
        let failed = std::mem::take(&mut self.path_failure_notices);
        let mut output = Vec::with_capacity(failed.len() * survivors.len() * 3);
        for failed_path in failed {
            for &survivor in &survivors {
                for _ in 0..3 {
                    output.push(Frame::control(
                        Kind::PathDown,
                        survivor as u8,
                        failed_path as u64,
                        now,
                    ));
                }
            }
        }
        self.counters.path_down_notices_sent += output.len() as u64;
        output
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
                if let Some(pending) = self.pending.get(&frame.id) {
                    let Some(&attempt) = pending.attempts.get(&index) else {
                        return (None, Vec::new());
                    };
                    if frame.stamp < pending.born
                        || attempt.generation != self.paths[index].generation
                        || frame.stamp > attempt.stamp
                    {
                        return (None, Vec::new());
                    }
                    let pending = self.pending.remove(&frame.id).expect("known pending ID");
                    let acknowledged_tcp_flow = tcp_flow_key(&pending.body);
                    if pending.tcp_early_repair_deferred && !pending.repaired {
                        self.counters.tcp_early_deferrals_acked += 1;
                    }
                    let exact = attempt.stamp == frame.stamp;
                    if pending.body.len() >= 600 && tcp_flow_key(&pending.body).is_some() {
                        self.paths[index].tcp_acked(pending.body.len(), now);
                    }
                    self.acknowledge_path(index, pending.body.len(), frame.stamp, exact, now);
                    // Delivery is complete on the first ACK. Preserve only the
                    // other paths' acknowledgement metadata so their actual
                    // successful standby deliveries continue training them.
                    for (&attempted_path, &attempt) in &pending.attempts {
                        if attempted_path != index {
                            if self.recent_attempts.len() >= MAX_RECENT_ACKS {
                                self.recent_attempts.pop_first();
                            }
                            self.recent_attempts.insert(
                                (frame.id, attempted_path),
                                RecentAttempt {
                                    bytes: pending.body.len(),
                                    born: pending.born,
                                    stamp: attempt.stamp,
                                    generation: attempt.generation,
                                    expires: now.saturating_add(RECENT_ACK_TTL_MS),
                                },
                            );
                        }
                    }
                    self.release_flight(&pending);
                    self.note_higher_ack(index, frame.id, frame.stamp, acknowledged_tcp_flow);
                } else if let Some(attempt) = self.recent_attempts.remove(&(frame.id, index)) {
                    if attempt.generation != self.paths[index].generation
                        || frame.stamp < attempt.born
                        || frame.stamp > attempt.stamp
                    {
                        return (None, Vec::new());
                    }
                    self.acknowledge_path(
                        index,
                        attempt.bytes,
                        frame.stamp,
                        frame.stamp == attempt.stamp,
                        now,
                    );
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
            Kind::Close | Kind::Udp | Kind::UdpReady | Kind::PathFailureReady | Kind::PathDown => {
                (None, Vec::new())
            }
        }
    }
    fn release_flight(&mut self, packet: &Pending) {
        for (&index, &attempt) in &packet.attempts {
            if self
                .paths
                .get(index)
                .is_some_and(|path| path.generation == attempt.generation)
            {
                self.paths[index].in_flight = self.paths[index]
                    .in_flight
                    .saturating_sub(packet.body.len());
            }
        }
    }
    fn acknowledge_path(&mut self, index: usize, bytes: usize, stamp: u64, exact: bool, now: u64) {
        let path = &mut self.paths[index];
        // Accept an original copy's ACK after a resend without using an
        // ambiguous RTT measurement.
        if exact {
            path.observe(now, stamp);
        }
        path.acknowledged_bytes += bytes as u64;
        path.rate_bytes += bytes as u64;
        if path.capacity_recently_used(now) {
            path.acknowledge_capacity(bytes);
        } else {
            // Light traffic must neither grow an untested window nor shrink
            // it due solely to unrelated RTT fluctuations.
            path.window_control.app_limited_growth_acks += 1;
        }
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
    fn note_higher_ack(
        &mut self,
        path: usize,
        acknowledged_id: u64,
        acknowledged_stamp: u64,
        acknowledged_tcp_flow: Option<[u8; 12]>,
    ) {
        let Some(acknowledged_tcp_flow) = acknowledged_tcp_flow else {
            return;
        };
        let candidates: Vec<_> =
            self.pending
                .range(..acknowledged_id)
                .rev()
                .filter(|(_, packet)| {
                    packet.fast_repair_path.is_none()
                        && tcp_flow_key(&packet.body) == Some(acknowledged_tcp_flow)
                        && packet.attempts.get(&path).is_some_and(|attempt| {
                            attempt.generation == self.paths[path].generation
                        })
                })
                .take(FAST_ACK_SCAN)
                .map(|(&id, _)| id)
                .collect();
        for id in candidates {
            let packet = self.pending.get_mut(&id).expect("known fast-ACK candidate");
            let sent = packet.attempts[&path].stamp;
            let evidence = packet.fast_ack_evidence.entry(path).or_default();
            *evidence = evidence.saturating_add(1).min(FAST_ACK_THRESHOLD);
            if *evidence == FAST_ACK_THRESHOLD
                || acknowledged_stamp.saturating_sub(sent) >= FAST_ACK_SEND_DELTA_MS
            {
                packet.fast_repair_path = Some(path);
            }
        }
    }
    fn reserve_tcp_continuity(&mut self, bytes: usize, now: u64) -> bool {
        let elapsed = now.saturating_sub(self.tcp_continuity_refill_at);
        self.tcp_continuity_tokens = self
            .tcp_continuity_tokens
            .saturating_add(elapsed.saturating_mul(TCP_CONTINUITY_BYTES_PER_MS))
            .min(TCP_CONTINUITY_BURST_BYTES);
        self.tcp_continuity_refill_at = now;
        let bytes = bytes as u64;
        if self.tcp_continuity_tokens < bytes {
            return false;
        }
        self.tcp_continuity_tokens -= bytes;
        true
    }
    pub fn data_paths(&self, now: u64) -> Vec<usize> {
        let mut ready: Vec<_> = self
            .paths
            .iter()
            .enumerate()
            .filter(|(_, path)| path.ready(now))
            .map(|(index, _)| index)
            .collect();
        if ready
            .iter()
            .any(|&index| self.paths[index].recently_responding(now))
        {
            ready.retain(|&index| self.paths[index].recently_responding(now));
        }
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
    fn placement_paths(&self, interactive: bool, now: u64) -> Vec<usize> {
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
        ready
    }

    fn targets(&self, bytes: usize, interactive: bool, now: u64) -> Vec<usize> {
        let mut ready = self.placement_paths(interactive, now);
        ready.retain(|&index| self.paths[index].send_budget_allows(bytes, interactive, now));
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

    /// TCP-only completion/blocking estimate. Unlike targets(), a temporarily
    /// paced/full fast path participates in the decision. Backlog is PER FLOW:
    /// unrelated transfers must not justify putting this flow's early segment
    /// on a path whose propagation delay exceeds its entire fast-path transfer.
    fn tcp_target(
        &mut self,
        key: [u8; 12],
        bytes: usize,
        backlog: usize,
        now: u64,
    ) -> Option<usize> {
        let all = self.data_paths(now);
        let &fast = all.first()?;
        let candidate = all
            .iter()
            .copied()
            .filter(|&i| self.paths[i].send_budget_allows(bytes, false, now))
            .min_by(|&a, &b| {
                let cost = |i: usize| {
                    self.paths[i].tcp_forward_ms(now, bytes)
                        + self.paths[i].in_flight as f64 / self.paths[i].tcp_bytes_per_ms(now)
                };
                cost(a).total_cmp(&cost(b))
            })?;
        // Capacity exhaustion must not allocate unbounded flow state. Unknown
        // flows still progress using ordinary eligible-path selection.
        if !self.tcp_flows.contains_key(&key) && self.tcp_flows.len() >= MAX_FLOW_PINS {
            return Some(candidate);
        }
        let flow = self.tcp_flows.entry(key).or_default();
        flow.touched = now;
        let p = &self.paths[fast];
        let fast_finish =
            (now as f64 + p.tcp_send_wait_ms(bytes, now) + p.tcp_forward_ms(now, bytes))
                .max(flow.last_arrival)
                + backlog.saturating_sub(bytes) as f64 / p.tcp_bytes_per_ms(now);
        let slow_arrival =
            (now as f64 + self.paths[candidate].tcp_forward_ms(now, bytes)).max(flow.last_arrival);
        if candidate != fast && fast_finish + 0.25 < slow_arrival {
            if p.send_budget_allows(bytes, false, now) {
                flow.waiting_since = None;
                return Some(fast);
            }
            let since = *flow.waiting_since.get_or_insert(now);
            // At most one RTT, capped at 20 ms; no permanent waiting for a
            // preferred adapter. Failed paths disappear from `all` immediately.
            let limit = p.rtt_ms.unwrap_or(20.0).ceil().clamp(2.0, 20.0) as u64;
            if now.saturating_sub(since) < limit {
                self.counters.tcp_path_waits += 1;
                return None;
            }
            self.counters.tcp_bounded_wait_fallbacks += 1;
        }
        flow.waiting_since = None;
        Some(candidate)
    }

    fn note_tcp_placement(&mut self, key: [u8; 12], path: usize, bytes: usize, now: u64) {
        if let Some(flow) = self.tcp_flows.get_mut(&key) {
            // This is predicted receiver ordering, NOT an application ACK.
            // It expires with time, without waiting for receiver feedback.
            flow.last_arrival = flow
                .last_arrival
                .max(now as f64 + self.paths[path].tcp_forward_ms(now, bytes));
            flow.touched = now;
        }
    }

    // A backup may be slower than the preferred realtime primary and still
    // be the only surviving carrier. Do not apply the primary RTT cutoff to
    // UDP protection, but retain the same liveness, cwnd and pacing limits.
    fn udp_protection_targets(&self, bytes: usize, now: u64) -> Vec<usize> {
        self.data_paths(now)
            .into_iter()
            .filter(|&index| {
                let path = &self.paths[index];
                path.in_flight + bytes <= path.congestion_window && path.next_send <= now as f64
            })
            .collect()
    }

    // TCP continuity chooses a backup from every live data path, even when
    // that path is temporarily paced or window-limited. The packet keeps the
    // backup reservation in `protection_path` and tick() emits it as soon as
    // the path's normal bulk-TCP budget permits. This prevents a one-tick
    // pacing decision from silently removing failover protection.
    fn tcp_protection_targets(&self, bytes: usize, now: u64) -> Vec<usize> {
        self.data_paths(now)
            .into_iter()
            .filter(|&index| self.paths[index].send_budget_allows(bytes, false, now))
            .collect()
    }

    fn send_copy(&mut self, packet: &mut Pending, id: u64, path: usize, now: u64) -> Frame {
        if packet.protection_path == Some(path) {
            packet.protection_path = None;
        }
        let generation = self.paths[path].generation;
        let current_attempt = packet
            .attempts
            .get(&path)
            .is_some_and(|attempt| attempt.generation == generation);
        if !current_attempt {
            self.paths[path].in_flight += packet.body.len();
        }
        self.paths[path].note_capacity_use(now);
        if packet.body.len() >= 600 && tcp_flow_key(&packet.body).is_some() {
            self.paths[path].tcp_sent(now);
        }
        packet.attempts.insert(
            path,
            Attempt {
                stamp: now,
                generation,
            },
        );
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

    fn classify_udp_flow(&mut self, ip: &[u8], now: u64) -> (Option<u128>, bool) {
        let fragment = udp_fragment_key(ip);
        let tuple = udp_tuple_key(ip);
        if let (Some(fragment), Some(tuple)) = (fragment, tuple) {
            self.fragment_flows.insert(fragment, (tuple, now));
        }
        let logical = tuple.or_else(|| {
            fragment.and_then(|key| {
                self.fragment_flows.get_mut(&key).map(|(flow, last_seen)| {
                    *last_seen = now;
                    *flow
                })
            })
        });
        let Some(flow) = logical else {
            return (None, false);
        };
        if is_srt_control_packet(ip) {
            self.srt_flows.insert(flow, now);
        }
        let srt = self.srt_flows.get_mut(&flow).is_some_and(|last_seen| {
            *last_seen = now;
            true
        });
        (Some(flow), srt)
    }

    pub fn tick(&mut self, now: u64) -> Vec<Frame> {
        let mut output = Vec::new();
        self.recent_attempts
            .retain(|_, attempt| now <= attempt.expires);
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
            self.flow_paths.retain(|key, (_, last_seen)| {
                // Fragment IDs change per datagram, unlike connection tuples.
                let ttl = if key & 1 != 0 {
                    PACKET_TTL_MS
                } else {
                    UDP_FLOW_TTL_MS
                };
                now.saturating_sub(*last_seen) < ttl
            });
            self.srt_flows
                .retain(|_, last_seen| now.saturating_sub(*last_seen) < SRT_FLOW_TTL_MS);
            self.fragment_flows
                .retain(|_, (_, last_seen)| now.saturating_sub(*last_seen) < FRAGMENT_FLOW_TTL_MS);
            self.tcp_flows
                .retain(|_, flow| now.saturating_sub(flow.touched) < 60_000);
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
        // RACK-style fast loss for the outer TCP carrier: newer, uniquely
        // acknowledged packets from the SAME inner flow and UDP subflow can
        // trigger a paced repair before the 70+ ms deadline. Another flow or
        // WAN never contributes evidence because its timing is independent.
        let fast_due: Vec<_> = self
            .pending
            .iter()
            .filter_map(|(&id, packet)| packet.fast_repair_path.map(|path| (id, path)))
            .filter(|&(_, path)| {
                data_paths.contains(&path) && self.paths[path].next_send <= now as f64
            })
            .take(64)
            .collect();
        for (id, path) in fast_due {
            let mut packet = self.pending.remove(&id).expect("known fast-repair ID");
            if now.saturating_sub(packet.born) > PACKET_TTL_MS {
                self.release_flight(&packet);
                self.counters.expired_packets += 1;
                continue;
            }
            packet.fast_repair_path = None;
            packet.fast_ack_evidence.clear();
            self.paths[path].repair_timeout(now, true);
            output.push(self.send_copy(&mut packet, id, path, now));
            packet.last_repair = now;
            packet.repaired = true;
            self.counters.repairs += 1;
            self.counters.tcp_same_path_repairs += 1;
            self.counters.tcp_fast_ack_repairs += 1;
            self.pending.insert(id, packet);
        }
        // Retry unsent protection before ordinary timeout repairs and new
        // traffic. Never bypass pacing/cwnd or require the primary to fail.
        // The first delivery ACK removes Pending and cancels its backup too.
        let waiting: Vec<_> = self
            .pending
            .iter()
            .filter_map(|(&id, packet)| packet.protection_path.map(|path| (id, path)))
            .collect();
        let mut blocked_protection = BTreeSet::new();
        let mut protection_sent = 0;
        for (id, path) in waiting {
            if protection_sent >= 64 {
                break;
            }
            let packet = self.pending.get(&id).expect("known protection ID");
            let current_attempts = packet
                .attempts
                .iter()
                .filter(|&(&index, attempt)| {
                    self.paths
                        .get(index)
                        .is_some_and(|candidate| candidate.generation == attempt.generation)
                })
                .count();
            if self.policy == Policy::DataSaver
                || now.saturating_sub(packet.born) > PACKET_TTL_MS
                || packet
                    .attempts
                    .get(&path)
                    .is_some_and(|attempt| attempt.generation == self.paths[path].generation)
                || current_attempts >= 2
                || !self.paths[path].enabled
                || matches!(self.paths[path].state, "failed" | "removed")
            {
                self.pending.get_mut(&id).unwrap().protection_path = None;
                continue;
            }
            if blocked_protection.contains(&path) {
                continue;
            }
            let eligible = if ipv4_udp(&packet.body) {
                self.udp_protection_targets(packet.body.len(), now)
            } else if ipv4_tcp(&packet.body) {
                self.tcp_protection_targets(packet.body.len(), now)
            } else {
                self.targets(packet.body.len(), true, now)
            };
            if !eligible.contains(&path) {
                // Preserve copy order on this path; a small fragment tail
                // must not jump ahead of its temporarily blocked first part.
                blocked_protection.insert(path);
                continue;
            }
            let mut packet = self.pending.remove(&id).unwrap();
            output.push(self.send_copy(&mut packet, id, path, now));
            self.pending.insert(id, packet);
            self.counters.protection_copies += 1;
            self.counters.protection_deferred_sent += 1;
            protection_sent += 1;
        }
        let due: Vec<_> = self
            .pending
            .iter_mut()
            .filter_map(|(&id, packet)| {
                let placement_due = now.saturating_sub(packet.last_repair) >= 2
                    && packet.attempts.iter().all(|(&index, attempt)| {
                        let current = self
                            .paths
                            .get(index)
                            .is_some_and(|path| path.generation == attempt.generation);
                        !current
                            || !data_paths.contains(&index)
                            || now.saturating_sub(attempt.stamp) >= self.paths[index].repair_ms()
                    });
                if !placement_due {
                    return None;
                }
                // TCP placement eligibility is not loss evidence. A quiet or
                // policy-excluded path can still deliver its outstanding data.
                // Let any still-live, unexpired attempt finish. Explicit
                // removal/carrier failure bypasses this guard immediately;
                // silent failures remain bounded by the packet's repair timer.
                // Keep the repository UDP lane and legacy UDP policy unchanged.
                if ipv4_tcp(&packet.body)
                    && packet.attempts.iter().any(|(&index, attempt)| {
                        attempt.generation == self.paths[index].generation
                            && self.paths[index].ready(now)
                            && now.saturating_sub(attempt.stamp) < self.paths[index].repair_ms()
                    })
                {
                    if !packet.tcp_early_repair_deferred {
                        packet.tcp_early_repair_deferred = true;
                        self.counters.tcp_early_repairs_deferred += 1;
                    }
                    return None;
                }
                Some(id)
            })
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
            for (&index, attempt) in &packet.attempts {
                let path = &self.paths[index];
                if attempt.generation == path.generation
                    && data_paths.contains(&index)
                    && path.next_send <= now as f64
                    && !candidates.contains(&index)
                {
                    candidates.push(index);
                }
            }
            let tcp = ipv4_tcp(&packet.body);
            let has_unavailable_attempt = tcp
                && packet.attempts.iter().any(|(&index, attempt)| {
                    self.paths.get(index).is_none_or(|path| {
                        path.generation != attempt.generation || !path.ready(now)
                    })
                });
            let target = if tcp {
                // A prior attempt is not a reason to reject the fastest healthy
                // path. Same-path retries reuse their existing flight charge;
                // all copies still consume pacing and sent-byte budgets.
                candidates.iter().copied().min_by(|&a, &b| {
                    let cost = |i: usize| {
                        // One earliest-arrival retry is useful; repeating it
                        // forever when only probes get through is not. An
                        // already retried, still unacknowledged copy contributes
                        // a repair-interval penalty so an alternate can recover.
                        let repeated = packet.attempts.get(&i).is_some_and(|attempt| {
                            attempt.generation == self.paths[i].generation
                                && attempt.stamp > packet.born
                        });
                        self.paths[i].tcp_forward_ms(now, packet.body.len())
                            + if repeated {
                                self.paths[i].repair_ms() as f64
                            } else {
                                0.0
                            }
                    };
                    cost(a).total_cmp(&cost(b))
                })
            } else {
                candidates
                    .iter()
                    .find(|&&index| {
                        !packet.attempts.get(&index).is_some_and(|attempt| {
                            attempt.generation == self.paths[index].generation
                        })
                    })
                    .copied()
                    .or_else(|| {
                        candidates.first().copied().filter(|&index| {
                            packet.attempts.get(&index).is_some_and(|attempt| {
                                attempt.generation == self.paths[index].generation
                                    && now.saturating_sub(attempt.stamp)
                                        >= self.paths[index].repair_ms()
                            })
                        })
                    })
            };
            if let Some(target) = target {
                if tcp {
                    if has_unavailable_attempt {
                        self.counters.tcp_unavailable_path_repairs += 1;
                    } else {
                        self.counters.tcp_deadline_repairs += 1;
                    }
                }
                if tcp
                    && packet
                        .attempts
                        .get(&target)
                        .is_some_and(|attempt| attempt.generation == self.paths[target].generation)
                {
                    self.counters.tcp_same_path_repairs += 1;
                }
                // A missing redundant copy on a dead adapter is not evidence
                // that the responding survivor is congested. Penalizing every
                // attempted path here collapsed the survivor's window exactly
                // when it had to carry the stream alone. A lone responsive
                // attempt is repaired and recorded without loss-based window
                // backoff; its RTT/queue-delay controller remains active. Only
                // redundant attempts that are all responsive supply enough
                // evidence to apply the ordinary loss response to every copy.
                let has_unresponsive_attempt = packet.attempts.iter().any(|(&index, attempt)| {
                    self.paths.get(index).is_none_or(|path| {
                        path.generation != attempt.generation || !path.recently_responding(now)
                    })
                });
                let current_attempts = packet
                    .attempts
                    .iter()
                    .filter(|&(&index, attempt)| {
                        self.paths
                            .get(index)
                            .is_some_and(|path| path.generation == attempt.generation)
                    })
                    .count();
                let redundant_responsive_loss = !has_unresponsive_attempt && current_attempts > 1;
                for (&index, attempt) in &packet.attempts {
                    if let Some(path) = self.paths.get_mut(index) {
                        if path.generation != attempt.generation {
                            continue;
                        }
                        let unresponsive = !path.recently_responding(now);
                        if !has_unresponsive_attempt || unresponsive {
                            path.repair_timeout(now, unresponsive || redundant_responsive_loss);
                        }
                    }
                }
                output.push(self.send_copy(&mut packet, id, target, now));
                packet.repaired = true;
                self.counters.repairs += 1;
            }
            packet.last_repair = now;
            self.pending.insert(id, packet);
        }
        // Inspect each queued packet at most once and emit at most 128 new
        // packets per turn. Deferred packets are restored in original order:
        // a blocked UDP pin must neither exceed its cwnd/pacer nor block an
        // unrelated stream on another link. Rotating just part of a FIFO would
        // reorder a stream at the per-tick budget boundary.
        let scan_budget = self.urgent.len() + self.streaming.len() + self.queued.len();
        // Read lengths once without parsing, path sorting, or allocation per
        // packet. Small TCP ACKs must still fit even when full-sized data
        // cannot. UDP in the bulk queue may acquire SRT/continuity priority,
        // so use its most permissive budget here, never a stricter one.
        let mut minimum_bulk = None::<usize>;
        let mut minimum_priority = self
            .urgent
            .iter()
            .chain(&self.streaming)
            .map(Vec::len)
            .min();
        let mut tcp_backlog = BTreeMap::<[u8; 12], usize>::new();
        for packet in &self.queued {
            if let Some(key) = tcp_flow_key(packet) {
                *tcp_backlog.entry(key).or_default() += packet.len();
            }
            let minimum = if packet.get(9) == Some(&17) {
                &mut minimum_priority
            } else {
                &mut minimum_bulk
            };
            *minimum = Some(minimum.map_or(packet.len(), |size| size.min(packet.len())));
        }
        let mut deferred: [VecDeque<Vec<u8>>; 3] = std::array::from_fn(|_| VecDeque::new());
        let mut blocked_flows = BTreeSet::new();
        let mut blocked_tcp = BTreeSet::new();
        let mut sent = 0;
        for _ in 0..scan_budget {
            if sent == 128 {
                break;
            }
            // If even the smallest queued packet cannot fit on ANY live
            // path, no classification/pin search can succeed this turn.
            // Leave the FIFO untouched until pacing or an ACK frees capacity.
            // Previously a 4,000-packet backlog was reclassified up to 500
            // times/sec despite no possible send.
            // Use all data paths, not one flow's preferred path: a blocked
            // pin must still allow other traffic on an available link.
            if !data_paths.iter().any(|&index| {
                let path = &self.paths[index];
                minimum_priority.is_some_and(|bytes| path.send_budget_allows(bytes, true, now))
                    || minimum_bulk.is_some_and(|bytes| path.send_budget_allows(bytes, false, now))
            }) {
                self.counters.budget_blocked_turns += 1;
                break;
            }
            let (priority, body) = if let Some(body) = self.urgent.pop_front() {
                (0, body)
            } else if let Some(body) = self.streaming.pop_front() {
                (1, body)
            } else if let Some(body) = self.queued.pop_front() {
                (2, body)
            } else {
                break;
            };
            let is_interactive = interactive(&body);
            self.counters.queue_scans += 1;
            // Only sequence-bearing bulk TCP changes placement. Bare ACKs,
            // UDP, and the separate UDP engine retain their existing behavior.
            let tcp_key = (!is_interactive).then(|| tcp_flow_key(&body)).flatten();
            if tcp_key.is_some_and(|key| blocked_tcp.contains(&key)) {
                deferred[priority].push_back(body);
                continue;
            }
            let (logical_udp_key, is_srt) = self.classify_udp_flow(&body, now);
            // Continuity cannot depend on seeing an application's handshake:
            // the stream may already be running when VERZ connects. Protect
            // all IPv4 UDP, including fragments, only in that explicit policy.
            // Smart keeps its existing bulk-UDP classification and TCP rules.
            let continuity_udp = self.policy == Policy::Continuity && ipv4_udp(&body);
            let protected_media = is_srt || is_realtime_media(&body) || continuity_udp;
            let protect_udp = protected_media && self.policy != Policy::DataSaver;
            let latency_sensitive = is_interactive || streaming(&body) || is_srt || continuity_udp;
            let mut targets = self.targets(body.len(), latency_sensitive, now);
            if protect_udp && targets.is_empty() {
                // A paced/full preferred primary must not hold both copies
                // while a healthy, budget-eligible slower carrier can send.
                targets = self.udp_protection_targets(body.len(), now);
            }
            // For bulk UDP flows, keep the whole 5-tuple on one path. Spraying
            // consecutive SRT/RTMP/WebRTC packets across paths of unequal RTT
            // reorders them and collapses effective throughput to the slowest
            // path. If the pinned path is dead, fall back to the fresh pick.
            // Only bulk packets create a pin; smaller companion packets (SRT
            // ACKs/NAKs, RTP marker, etc.) look up an existing pin so their
            // 5-tuple stays on the same path and does not get duplicated.
            let insert_key = (body.len() >= 500).then_some(logical_udp_key).flatten();
            let lookup_key = logical_udp_key.or_else(|| udp_flow_key(&body));
            let pinned_primary = lookup_key
                .and_then(|key| self.flow_paths.get(&key).map(|&(pinned, _)| pinned))
                // SRT protection is emitted only after selecting a primary.
                // Keeping an unavailable pin here blocks BOTH copies, even
                // when the alternate can send. Honor the pin only while it
                // passes current liveness, pacing and window eligibility.
                .filter(|&pinned| {
                    if protected_media {
                        targets.contains(&pinned)
                    } else {
                        self.placement_paths(latency_sensitive, now)
                            .contains(&pinned)
                    }
                });
            let primary = if let Some(key) = tcp_key {
                self.tcp_target(
                    key,
                    body.len(),
                    tcp_backlog.get(&key).copied().unwrap_or(body.len()),
                    now,
                )
            } else {
                pinned_primary.or_else(|| targets.first().copied())
            };
            if primary.is_none_or(|path| !targets.contains(&path))
                || lookup_key.is_some_and(|key| blocked_flows.contains(&key))
            {
                if let Some(key) = lookup_key {
                    blocked_flows.insert(key);
                }
                if let Some(key) = tcp_key {
                    blocked_tcp.insert(key);
                }
                deferred[priority].push_back(body);
                continue;
            }
            let primary = primary.expect("eligible primary");
            if let Some(key) = tcp_key {
                self.note_tcp_placement(key, primary, body.len(), now);
                if let Some(bytes) = tcp_backlog.get_mut(&key) {
                    *bytes = bytes.saturating_sub(body.len());
                }
            }
            let id = self.next_id;
            let Some(next) = id.checked_add(1) else {
                self.counters.queue_drops += 1;
                break;
            };
            self.next_id = next;
            if let Some(key) = insert_key.or(lookup_key.filter(|_| pinned_primary.is_some()))
                && (self.flow_paths.len() < MAX_FLOW_PINS || self.flow_paths.contains_key(&key))
            {
                self.flow_paths.insert(key, (primary, now));
            }
            // Match the UDP continuity rule for the complete TCP exchange.
            // Protecting only sequence-bearing data left pure ACK/control
            // packets pinned to the fastest interface; a cable pull then
            // stopped TCP's feedback loop until path failure was declared.
            // The existing token bucket retains the bounded overhead needed
            // for high-rate TCP bonding.
            let tcp_continuity_candidate = ipv4_tcp(&body) && self.policy == Policy::Continuity;
            let mut packet = Pending {
                body,
                born: now,
                attempts: BTreeMap::new(),
                last_repair: now,
                protection_path: None,
                tcp_early_repair_deferred: false,
                fast_ack_evidence: BTreeMap::new(),
                fast_repair_path: None,
                repaired: false,
            };
            output.push(self.send_copy(&mut packet, id, primary, now));
            // Smart bulk UDP stays pinned. Protected UDP sends the same VERZ
            // packet ID on a second path; either copy can deliver once without
            // waiting for loss detection or creating a second inner session.
            let follows_pin = pinned_primary.is_some();
            // Protected media selects a healthy backup independently of its
            // instantaneous send budget. Other traffic retains its existing
            // opportunistic duplication policy.
            // Candidate selection must happen before the token bucket is
            // consumed/refilled. Whether this packet earns a copy is decided
            // only after a distinct live alternate has been found.
            let protection_targets = if protect_udp || tcp_continuity_candidate {
                self.data_paths(now)
            } else {
                targets.clone()
            };
            let alternate = protection_targets
                .iter()
                .copied()
                .find(|&path| path != primary);
            if let Some(alternate) = alternate {
                // Detection-time budget for interactive protection, held
                // independent of the (much wider) failure eviction window so
                // that longer failure_ms values do not silently opt every
                // small packet into duplication.
                let recovery = 3.0 * PROBE_MS as f64
                    + self.paths[alternate].rtt_ms.unwrap_or(100.0)
                    + (self.paths[alternate].in_flight + packet.body.len()) as f64
                        / self.paths[alternate].estimated_bytes_per_ms();
                let protect_interactive = is_interactive
                    && !follows_pin
                    && (self.policy == Policy::Continuity
                        || (self.policy != Policy::DataSaver && is_realtime_media(&packet.body))
                        || recovery >= 100.0
                        || self.paths[primary].state == "degraded");
                let protect_tcp =
                    tcp_continuity_candidate && self.reserve_tcp_continuity(packet.body.len(), now);
                if protect_udp || protect_interactive || protect_tcp {
                    let can_send = if protect_udp {
                        self.udp_protection_targets(packet.body.len(), now)
                            .contains(&alternate)
                    } else if protect_tcp {
                        self.tcp_protection_targets(packet.body.len(), now)
                            .contains(&alternate)
                    } else {
                        targets.contains(&alternate)
                    };
                    if can_send {
                        output.push(self.send_copy(&mut packet, id, alternate, now));
                        self.counters.protection_copies += 1;
                    } else {
                        packet.protection_path = Some(alternate);
                        self.counters.protection_deferred += 1;
                    }
                }
            }
            self.pending.insert(id, packet);
            sent += 1;
        }
        for (waiting, queue) in
            deferred
                .iter_mut()
                .zip([&mut self.urgent, &mut self.streaming, &mut self.queued])
        {
            waiting.append(queue);
            std::mem::swap(waiting, queue);
        }
        output
    }
}

// Later fragments have no UDP header, but the IPv4 protocol field still
// identifies them. Keep their protection independent of fragment arrival order.
fn ipv4_udp(ip: &[u8]) -> bool {
    if ip.first().is_none_or(|v| v >> 4 != 4) || ip.get(9) != Some(&17) {
        return false;
    }
    let header = usize::from(ip[0] & 15) * 4;
    header >= 20
        && if fragment_offset(ip).is_some_and(|offset| offset > 0) {
            ip.len() > header
        } else {
            ip.len() >= header + 8
        }
}

fn ipv4_tcp(ip: &[u8]) -> bool {
    if ip.first().is_none_or(|v| v >> 4 != 4) || ip.get(9) != Some(&6) {
        return false;
    }
    let header = usize::from(ip[0] & 15) * 4;
    if header < 20 || ip.len() < header {
        return false;
    }
    if fragment_offset(ip).is_some_and(|offset| offset > 0) {
        return ip.len() > header;
    }
    if ip.len() < header + 20 {
        return false;
    }
    let tcp_header = usize::from(ip[header + 12] >> 4) * 4;
    tcp_header >= 20 && ip.len() >= header + tcp_header
}

fn interactive(ip: &[u8]) -> bool {
    // Large UDP/QUIC transfers are bulk too. Treating every UDP packet as
    // interactive duplicated downloads and consumed the capacity being bonded.
    // Bare TCP ACKs are also skipped: TCP already tolerates ACK loss via the
    // next cumulative ACK, and duplicating them halved each path's usable
    // bandwidth during bulk transfers.
    if fragmented(ip) {
        // A small last fragment is not a new voice/control packet. Keep all
        // fragments in the same priority class; honor an explicit EF mark.
        return ip.get(1).is_some_and(|v| v >> 2 == 46);
    }
    if bare_tcp_ack(ip) {
        return false;
    }
    ip.len() < 600 || ip.get(9) == Some(&1) || ip.get(1).is_some_and(|v| v >> 2 == 46)
}

// Sequence-bearing, unfragmented IPv4 TCP only. ACK-only traffic must not
// wait behind a data flow; malformed or fragmented payloads are not parsed as
// TCP headers. The protocol is implicit in the typed 12-byte key.
fn tcp_flow_key(ip: &[u8]) -> Option<[u8; 12]> {
    if ip.first().is_none_or(|v| v >> 4 != 4) || ip.get(9) != Some(&6) || fragmented(ip) {
        return None;
    }
    let iph = usize::from(ip[0] & 15) * 4;
    if iph < 20 || ip.len() < iph + 20 {
        return None;
    }
    let tcph = usize::from(ip[iph + 12] >> 4) * 4;
    if tcph < 20 || ip.len() < iph + tcph || (ip.len() == iph + tcph && ip[iph + 13] & 3 == 0) {
        return None;
    }
    let mut key = [0; 12];
    key[..8].copy_from_slice(&ip[12..20]);
    key[8..].copy_from_slice(&ip[iph..iph + 4]);
    Some(key)
}

fn bare_tcp_ack(ip: &[u8]) -> bool {
    if ip.first().is_none_or(|v| v >> 4 != 4) || ip.get(9) != Some(&6) || fragmented(ip) {
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
    if ip.first().is_none_or(|v| v >> 4 != 4) || ip.get(9) != Some(&17) || fragmented(ip) {
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
#[cfg(test)]
fn bulk_udp_flow_key(ip: &[u8]) -> Option<u128> {
    (ip.len() >= 500).then(|| udp_flow_key(ip)).flatten()
}

fn fragment_offset(ip: &[u8]) -> Option<u16> {
    (ip.len() >= 8).then(|| (u16::from(ip[6] & 0x1f) << 8) | u16::from(ip[7]))
}

fn fragmented(ip: &[u8]) -> bool {
    ip.get(6).is_some_and(|flags| flags & 0x3f != 0) || ip.get(7).is_some_and(|offset| *offset != 0)
}

// Any UDP 5-tuple, used only to *look up* an existing pin so that ACK/NAK/
// control packets in an ongoing media flow ride with the bulk stream instead
// of being duplicated as if they were an independent VoIP call.
fn udp_flow_key(ip: &[u8]) -> Option<u128> {
    if ip.first().is_none_or(|v| v >> 4 != 4) || ip.get(9) != Some(&17) {
        return None;
    }
    let iph = usize::from(ip[0] & 15) * 4;
    if iph < 20 || ip.len() < iph {
        return None;
    }
    let src_ip = u32::from_be_bytes(ip[12..16].try_into().ok()?);
    let dst_ip = u32::from_be_bytes(ip[16..20].try_into().ok()?);
    if fragmented(ip) {
        // Later IPv4 fragments contain payload, NOT UDP ports. All fragments
        // of one datagram use its authenticated IP ID instead, so large SRT
        // datagrams may be reassembled by the destination kernel. Bit 0 keeps
        // fragment keys disjoint from ordinary 5-tuples.
        let id = u16::from_be_bytes([ip[4], ip[5]]);
        return Some(
            (u128::from(src_ip) << 96) | (u128::from(dst_ip) << 64) | (u128::from(id) << 32) | 1,
        );
    }
    if ip.len() < iph + 8 {
        return None;
    }
    let dst_port = u16::from_be_bytes([ip[iph + 2], ip[iph + 3]]);
    if matches!(dst_port, 53 | 67 | 68 | 123 | 500 | 4500 | 5353) {
        return None;
    }
    let src_port = u16::from_be_bytes([ip[iph], ip[iph + 1]]);
    Some(
        (u128::from(src_ip) << 96)
            | (u128::from(dst_ip) << 64)
            | (u128::from(src_port) << 48)
            | (u128::from(dst_port) << 32),
    )
}

// The real UDP tuple is present in an unfragmented packet or the first IPv4
// fragment. Unlike udp_flow_key(), this deliberately ignores the MF flag.
fn udp_tuple_key(ip: &[u8]) -> Option<u128> {
    if ip.first().is_none_or(|v| v >> 4 != 4) || ip.get(9) != Some(&17) || fragment_offset(ip)? != 0
    {
        return None;
    }
    let iph = usize::from(ip[0] & 15) * 4;
    if iph < 20 || ip.len() < iph + 8 {
        return None;
    }
    let src_ip = u32::from_be_bytes(ip[12..16].try_into().ok()?);
    let dst_ip = u32::from_be_bytes(ip[16..20].try_into().ok()?);
    let src_port = u16::from_be_bytes([ip[iph], ip[iph + 1]]);
    let dst_port = u16::from_be_bytes([ip[iph + 2], ip[iph + 3]]);
    if matches!(dst_port, 53 | 67 | 68 | 123 | 500 | 4500 | 5353) {
        return None;
    }
    Some(
        (u128::from(src_ip) << 96)
            | (u128::from(dst_ip) << 64)
            | (u128::from(src_port) << 48)
            | (u128::from(dst_port) << 32),
    )
}

fn udp_fragment_key(ip: &[u8]) -> Option<u128> {
    if ip.first().is_none_or(|v| v >> 4 != 4) || ip.get(9) != Some(&17) || !fragmented(ip) {
        return None;
    }
    let src_ip = u32::from_be_bytes(ip.get(12..16)?.try_into().ok()?);
    let dst_ip = u32::from_be_bytes(ip.get(16..20)?.try_into().ok()?);
    let id = u16::from_be_bytes([*ip.get(4)?, *ip.get(5)?]);
    Some((u128::from(src_ip) << 96) | (u128::from(dst_ip) << 64) | (u128::from(id) << 32) | 1)
}

// SRT is port-independent. Its official 16-byte header distinguishes control
// packets with the top bit, a 15-bit type and a 16-bit subtype. Learning only
// standard control types with subtype zero makes accidental classification of
// arbitrary UDP vanishingly unlikely; later data packets inherit the flow.
fn is_srt_control_packet(ip: &[u8]) -> bool {
    if ip.first().is_none_or(|v| v >> 4 != 4)
        || ip.get(9) != Some(&17)
        || fragment_offset(ip) != Some(0)
    {
        return false;
    }
    let iph = usize::from(ip[0] & 15) * 4;
    let Some(payload) = ip.get(iph + 8..) else {
        return false;
    };
    if payload.len() < 16 {
        return false;
    }
    let control = u16::from_be_bytes([payload[0], payload[1]]);
    let control_type = control & 0x7fff;
    let subtype = u16::from_be_bytes([payload[2], payload[3]]);
    control & 0x8000 != 0 && control_type <= 8 && subtype == 0
}

fn streaming(ip: &[u8]) -> bool {
    // Honor explicit video DSCP and recognizable RTMP/RTSP endpoints. Large
    // unmarked UDP/QUIC is not guessed to be video. Explicit Continuity UDP
    // protection is handled separately by the scheduler, not classification.
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
        let mut p = vec![0; BOND_MTU];
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
    fn continuity_protects_unclassified_udp_without_observing_its_handshake() {
        let mut s = unequal_latency();
        s.policy = Policy::Continuity;
        // The stream was already running when VERZ connected. No SRT control
        // or recognizable application header has passed through this engine.
        let data = srt_packet(50_000, 23_456, 7);
        assert!(!is_srt_control_packet(&data));
        assert!(s.srt_flows.is_empty());
        s.enqueue(data.clone());
        let sent: Vec<_> = s
            .tick(100)
            .into_iter()
            .filter(|f| f.kind == Kind::Data)
            .collect();
        assert_eq!(
            sent.len(),
            2,
            "Continuity must protect generic large UDP too"
        );
        assert_eq!(sent[0].id, sent[1].id);
        assert_ne!(sent[0].path, sent[1].path);
        assert!(sent.iter().all(|f| f.body == data));
        let mut receiver = unequal_latency();
        assert!(receiver.receive(&sent[1], 130).0.is_some());
        assert!(receiver.receive(&sent[0], 140).0.is_none());
    }

    #[test]
    fn healthy_high_latency_udp_backup_is_not_removed_by_primary_latency_filter() {
        for policy in [Policy::Smart, Policy::Continuity] {
            let mut s = unequal_latency();
            s.policy = policy;
            s.paths[1].rtt_ms = Some(120.0);
            s.paths[1].minimum_rtt_ms = 120.0;
            s.paths[1].latency_excluded = true;
            assert_eq!(s.targets(1200, true, 100), vec![0]);
            s.classify_udp_flow(&srt_control_packet(50_000, 23_456, 0), 99);
            s.enqueue(srt_packet(50_000, 23_456, 7));
            let sent: Vec<_> = s
                .tick(100)
                .into_iter()
                .filter(|f| f.kind == Kind::Data)
                .collect();
            assert_eq!(sent.len(), 2, "healthy backup excluded for {policy:?}");
            assert_eq!(sent[0].path, 0, "fast path remains primary");
            assert_eq!(sent[1].path, 1);
        }
    }

    #[test]
    fn high_latency_udp_backup_respects_pacing_then_sends_deferred_copy() {
        let mut s = unequal_latency();
        s.policy = Policy::Continuity;
        s.paths[1].rtt_ms = Some(120.0);
        s.paths[1].latency_excluded = true;
        s.paths[1].next_send = 105.0;
        s.enqueue(srt_packet(50_000, 23_456, 7));
        let sent: Vec<_> = s
            .tick(100)
            .into_iter()
            .filter(|f| f.kind == Kind::Data)
            .collect();
        assert_eq!(sent.len(), 1, "must not bypass backup pacing");
        assert_eq!(s.counters.protection_deferred, 1);
        assert!(!s.tick(104).iter().any(|f| f.kind == Kind::Data));
        let backup: Vec<_> = s
            .tick(105)
            .into_iter()
            .filter(|f| f.kind == Kind::Data)
            .collect();
        assert_eq!(backup.len(), 1);
        assert_eq!(backup[0].path, 1);
        assert_eq!(backup[0].id, sent[0].id);
        assert_eq!(
            s.counters.repairs, 0,
            "copy must not wait for the repair timer"
        );
    }

    #[test]
    fn protected_udp_uses_slower_carrier_when_preferred_primary_is_budget_blocked() {
        for policy in [Policy::Smart, Policy::Continuity] {
            for paced in [false, true] {
                let mut s = unequal_latency();
                s.policy = policy;
                s.paths[1].rtt_ms = Some(120.0);
                s.paths[1].latency_excluded = true;
                let body = srt_packet(50_000, 23_456, 7);
                if policy == Policy::Smart {
                    s.classify_udp_flow(&srt_control_packet(50_000, 23_456, 0), 99);
                }
                s.flow_paths.insert(udp_flow_key(&body).unwrap(), (0, 99));
                if paced {
                    s.paths[0].next_send = 105.0;
                } else {
                    s.paths[0].in_flight = s.paths[0].congestion_window;
                }
                s.enqueue(body.clone());
                let sent: Vec<_> = s
                    .tick(100)
                    .into_iter()
                    .filter(|f| f.kind == Kind::Data)
                    .collect();
                assert_eq!(sent.len(), 1);
                assert_eq!(sent[0].path, 1);
                assert_eq!(sent[0].body, body);
                assert_eq!(s.counters.protection_deferred, 1);
                assert_eq!(s.paths[1].in_flight, body.len());
                assert_eq!(s.paths[1].sent_bytes, body.len() as u64);
                assert!(!s.tick(101).iter().any(|f| f.kind == Kind::Data));
                // Delivery on the alternate cancels the pending primary copy.
                acknowledge_packet(&mut s, &sent, 102);
                s.paths[0].in_flight = 0;
                assert!(!s.tick(105).iter().any(|f| f.kind == Kind::Data));
                assert_eq!(s.paths[1].in_flight, 0);
            }
        }
    }

    #[test]
    fn continuity_protects_fragment_tail_without_first_fragment_or_flow_metadata() {
        let mut s = unequal_latency();
        s.policy = Policy::Continuity;
        let mut tail = srt_packet(50_000, 23_456, 7);
        tail.truncate(104);
        tail[2..4].copy_from_slice(&104u16.to_be_bytes());
        tail[6..8].copy_from_slice(&157u16.to_be_bytes());
        assert!(s.classify_udp_flow(&tail, 99).0.is_none());
        s.enqueue(tail.clone());
        let sent: Vec<_> = s
            .tick(100)
            .into_iter()
            .filter(|f| f.kind == Kind::Data)
            .collect();
        assert_eq!(sent.len(), 2);
        assert_eq!(sent[0].id, sent[1].id);
        assert!(sent.iter().all(|frame| frame.body == tail));
    }

    #[test]
    fn bulk_tcp_and_non_continuity_bulk_udp_keep_single_copy_policy() {
        for policy in [Policy::Smart, Policy::Continuity, Policy::DataSaver] {
            let mut s = unequal_latency();
            s.policy = policy;
            s.enqueue(bulk());
            assert_eq!(
                s.tick(100).iter().filter(|f| f.kind == Kind::Data).count(),
                1
            );
            assert_eq!(s.counters.protection_copies, 0);
            if policy != Policy::Continuity {
                let mut s = unequal_latency();
                s.policy = policy;
                s.enqueue(srt_packet(50_000, 23_456, 7));
                assert_eq!(
                    s.tick(100).iter().filter(|f| f.kind == Kind::Data).count(),
                    1
                );
                assert_eq!(s.counters.protection_copies, 0);
            }
        }
    }

    #[test]
    fn udp_protection_classifier_rejects_short_invalid_and_non_ipv4_headers() {
        let udp = srt_packet(50_000, 23_456, 7);
        assert!(ipv4_udp(&udp));
        for len in 0..28 {
            assert!(!ipv4_udp(&udp[..len]));
        }
        for version_and_ihl in [0x44, 0x65, 0x4f] {
            let mut invalid = udp[..28].to_vec();
            invalid[0] = version_and_ihl;
            assert!(!ipv4_udp(&invalid));
        }
        assert!(!ipv4_udp(&bulk()));
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
    fn idle_rtt_changes_do_not_end_capacity_discovery_before_any_data_is_sent() {
        let mut s = Scheduler::new(vec![("hotspot".into(), false)], Policy::Smart).unwrap();
        let initial = s.paths[0].congestion_window;
        let threshold = s.paths[0].slow_start_threshold;
        // Establish a 20 ms path, then model a radio scheduling plateau. No
        // application packet has been sent: these are only heartbeat replies.
        for now in (100..500).step_by(20) {
            s.receive(&Frame::control(Kind::Pong, 0, 0, now - 20), now);
        }
        for now in (500..10_000).step_by(20) {
            s.receive(&Frame::control(Kind::Pong, 0, 0, now - 80), now);
        }
        assert_eq!(s.paths[0].in_flight, 0);
        assert_eq!(s.paths[0].sent_bytes, 0);
        assert!(s.paths[0].ready(10_000));
        assert!(
            s.paths[0].rtt_ms.unwrap() > 79.0,
            "liveness/RTT still update"
        );
        assert_eq!(
            s.paths[0].congestion_window, initial,
            "idle probes shrank the initial window"
        );
        assert_eq!(
            s.paths[0].slow_start_threshold, threshold,
            "idle probes ended slow start"
        );
        assert!(s.paths[0].window_control.idle_delay_observations > 0);
        assert_eq!(s.paths[0].window_control.delay_reductions, 0);
        assert!(s.paths[0].window_control.last_reduction.is_none());
    }

    #[test]
    fn idle_probe_plateau_does_not_destroy_a_previously_earned_window() {
        let mut p = Path::new(0, "hotspot".into(), false);
        p.minimum_rtt_ms = 20.0;
        p.rtt_ms = Some(80.0);
        p.congestion_window = 400_000;
        p.slow_start_threshold = 400_000;
        for now in (1000..20_000).step_by(20) {
            p.observe(now, now - 80);
        }
        assert_eq!(p.congestion_window, 400_000);
        assert_eq!(p.slow_start_threshold, 400_000);
        assert_eq!(p.in_flight, 0);
        assert_eq!(p.timeouts, 0);
        assert!(p.ready(20_000));
        assert_eq!(p.window_control.delay_reductions, 0);
        // This guard must not let an ACTIVE, delayed path escape backoff.
        p.in_flight = 400_000;
        p.observe(20_020, 19_940);
        assert!(p.congestion_window < 400_000);
        assert_eq!(p.window_control.delay_reductions, 1);
        let reduction = p.window_control.last_reduction.as_ref().unwrap();
        assert_eq!(reduction.reason, "rtt_delay");
        assert_eq!(reduction.before_bytes, 400_000);
        assert_eq!(reduction.in_flight_bytes, 400_000);
        assert_eq!(reduction.after_bytes, p.congestion_window);
    }

    #[test]
    fn ack_only_load_cannot_shrink_or_grow_an_unused_window() {
        let mut s = scheduler(Policy::Smart);
        let p = &mut s.paths[0];
        p.congestion_window = 98_000;
        p.slow_start_threshold = 4 * 1024 * 1024;
        p.in_flight = 4_420;
        p.minimum_rtt_ms = 3.0;
        p.rtt_ms = Some(48.0);
        p.jitter_ms = 0.0;
        for now in (1000..2000).step_by(20) {
            s.acknowledge_path(0, 52, now - 48, true, now);
        }
        assert_eq!(s.paths[0].congestion_window, 98_000);
        assert_eq!(s.paths[0].slow_start_threshold, 4 * 1024 * 1024);
        // Light ACK traffic at low RTT must not manufacture capacity either.
        for now in (2000..3000).step_by(20) {
            s.acknowledge_path(0, 52, now - 5, true, now);
        }
        assert_eq!(s.paths[0].congestion_window, 98_000);
    }

    #[test]
    fn tiny_recently_loaded_tail_cannot_cut_window_but_new_load_can() {
        let mut p = Path::new(0, "lan".into(), false);
        p.congestion_window = 400_000;
        p.in_flight = 300_000;
        p.rtt_ms = Some(60.0);
        p.minimum_rtt_ms = 3.0;
        p.note_capacity_use(1000);
        p.in_flight = 1000;
        p.observe(1060, 1000);
        assert_eq!(
            p.congestion_window, 400_000,
            "a tiny tail cannot have created a large queue"
        );
        let unchanged = p.congestion_window;
        p.observe(1300, 1240);
        assert_eq!(
            p.congestion_window, unchanged,
            "old load must not penalize light traffic forever"
        );
        p.in_flight = p.congestion_window;
        p.observe(1400, 1340);
        assert!(
            p.congestion_window < unchanged,
            "a new loaded transfer must still back off"
        );
    }

    #[test]
    fn delay_backoff_must_not_increase_a_small_loss_reduced_window() {
        let mut p = Path::new(0, "cellular".into(), false);
        p.minimum_rtt_ms = 20.0;
        p.rtt_ms = Some(80.0);
        p.jitter_ms = 0.0;
        p.congestion_window = 8 * BOND_MTU;
        p.in_flight = p.congestion_window;
        let before = p.congestion_window;
        p.observe(1000, 920);
        assert!(
            p.congestion_window <= before,
            "delay backoff increased a loss-reduced window"
        );
    }

    #[test]
    fn added_queue_delay_reduces_bulk_window_but_high_baseline_rtt_does_not() {
        let mut p = Path::new(0, "wifi".into(), false);
        p.congestion_window = 1_000_000;
        p.in_flight = p.congestion_window; // This test models an active transfer.
        p.observe(500, 300); // 200 ms baseline is not congestion.
        assert_eq!(p.congestion_window, 1_000_000);
        for now in 501..560 {
            p.observe(now, now - 240);
        }
        assert_eq!(
            p.congestion_window, 1_000_000,
            "a short run of elevated samples is a burst, not a queue"
        );
        for now in 560..800 {
            p.observe(now, now - 240);
        }
        assert!(p.congestion_window < 1_000_000);
        let window = p.congestion_window;
        p.acknowledge_capacity(1200);
        assert_eq!(p.congestion_window, window);
        assert_eq!(p.timeouts, 0); // Do not label queue-delay backoff packet loss.
        assert!(p.window_control.delay_reductions > 0);
        assert_eq!(p.window_control.loss_reductions, 0);
        assert_eq!(p.window_control.growth_paused_acks, 1);
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
    fn dead_redundant_attempt_does_not_collapse_fresh_survivor() {
        let mut s = scheduler(Policy::Continuity);
        s.enqueue(packet());
        let sent: Vec<_> = s
            .tick(31)
            .into_iter()
            .filter(|frame| frame.kind == Kind::Data)
            .collect();
        assert_eq!(sent.len(), 2);

        // Make path 0 a fresh but queue-elevated survivor. Before the repair
        // guard, path 1's missing protection copy called congestion_loss() on
        // both attempts and halved this healthy path exactly during failover.
        s.paths[0].minimum_rtt_ms = 10.0;
        s.paths[0].rtt_ms = Some(60.0);
        s.paths[0].jitter_ms = 0.0;
        s.paths[0].last_response = Some(100);
        s.paths[0].congestion_window = 400_000;
        s.paths[0].slow_start_threshold = 400_000;
        s.fail_path(1);

        let repaired = s
            .tick(111)
            .into_iter()
            .any(|frame| frame.kind == Kind::Data && frame.path == 0);
        assert!(repaired, "the survivor must immediately repair the copy");
        assert_eq!(
            s.paths[0].congestion_window, 400_000,
            "a dead redundant path must not collapse the live path's window"
        );
        assert_eq!(s.paths[0].timeouts, 0);
        assert_eq!(s.paths[1].timeouts, 1);
    }

    #[test]
    fn lone_survivor_repair_records_loss_without_window_collapse() {
        let mut s = scheduler(Policy::Smart);
        s.remove_path(1);
        s.enqueue(bulk());
        let sent = s
            .tick(31)
            .into_iter()
            .find(|frame| frame.kind == Kind::Data)
            .unwrap();
        assert_eq!(sent.path, 0);

        s.paths[0].minimum_rtt_ms = 10.0;
        s.paths[0].rtt_ms = Some(60.0);
        s.paths[0].jitter_ms = 0.0;
        s.paths[0].last_response = Some(100);
        s.paths[0].congestion_window = 400_000;
        s.paths[0].slow_start_threshold = 400_000;

        assert!(
            s.tick(111)
                .iter()
                .any(|frame| frame.kind == Kind::Data && frame.path == 0)
        );
        assert_eq!(s.paths[0].timeouts, 1, "repair loss remains observable");
        assert_eq!(
            s.paths[0].congestion_window, 400_000,
            "loss alone cannot destroy the only live path's capacity"
        );
    }

    #[test]
    fn idle_probe_failure_does_not_destroy_learned_capacity() {
        let mut s = unequal_latency();
        s.paths[0].congestion_window = 400_000;
        s.fail_path(0);
        assert!(!s.paths[0].ready(101));
        assert_eq!(s.paths[0].congestion_window, 400_000);
        // Loss during a persistent queue is treated as real congestion and
        // halves the window; a second event inside repair_ms is folded into
        // the first.
        s.paths[0].minimum_rtt_ms = 20.0;
        for now in (100..=500).step_by(10) {
            s.paths[0].observe(now, now - 60);
        }
        s.paths[0].repair_timeout(500, true);
        assert_eq!(s.paths[0].congestion_window, 200_000);
        s.paths[0].repair_timeout(501, true);
        assert_eq!(s.paths[0].congestion_window, 200_000);
    }

    #[test]
    fn random_wifi_loss_does_not_collapse_the_window() {
        // A Wi-Fi path can lose a few percent of packets to radio noise while
        // keeping RTT flat. The current experimental policy intentionally
        // ignores that signal; this test records behavior, not TCP equivalence
        // or proof that all flat-RTT losses are non-congestive.
        let mut path = Path::new(0, "en0".into(), false);
        path.minimum_rtt_ms = 12.0;
        path.congestion_window = 400_000;
        path.slow_start_threshold = 400_000;
        let mut now = 100_u64;
        for _ in 0..50 {
            path.observe(now, now - 12);
            path.repair_timeout(now, true);
            now += path.repair_ms() + 1;
        }
        assert_eq!(
            path.congestion_window, 400_000,
            "isolated loss with flat RTT must not shrink the window"
        );
        // Once RTT climbs (real queue building), the next loss halves normally.
        for _ in 0..30 {
            now += 10;
            path.observe(now, now - 60);
        }
        now += path.repair_ms() + 1;
        path.repair_timeout(now, true);
        assert_eq!(path.congestion_window, 200_000);
    }

    #[test]
    fn radio_holes_delay_bursts_without_cutting_a_loaded_window() {
        // Physical Wi-Fi survivor 2026-09-12: AWDL takes the radio for
        // 65-73 ms every ~0.5 s and a full-band scan dwells 100-200 ms per
        // channel. Nothing is lost; the queued burst arrives when the radio
        // returns, with the last-sent packets at near-minimum RTT.
        let mut p = Path::new(0, "en0".into(), false);
        p.congestion_window = 400_000;
        p.slow_start_threshold = 400_000;
        p.in_flight = 400_000;
        let mut now = 1_000_u64;
        for hole in [70_u64, 70, 160, 70, 200, 70, 70] {
            for _ in 0..40 {
                now += 10;
                p.observe(now, now - 5);
            }
            now += hole;
            let mut delayed = hole + 5;
            loop {
                p.observe(now, now - delayed);
                now += 1;
                if delayed <= 10 {
                    break;
                }
                delayed -= 10;
            }
        }
        assert_eq!(p.congestion_window, 400_000);
        assert_eq!(p.window_control.delay_reductions, 0);
        assert!(!p.queue_persistent);
        assert!(p.response_pause_ms >= 200 && p.response_pause_ms <= 300);
        assert!(
            p.repair_ms() >= 220,
            "deadline {} must cover the pauses",
            p.repair_ms()
        );
        // A lone-survivor repair fired during those holes is not congestion.
        p.repair_timeout(now, true);
        assert_eq!(p.congestion_window, 400_000);
        assert_eq!(p.window_control.loss_reductions, 0);
        // A real standing queue is still detected and reduced.
        for _ in 0..60 {
            now += 10;
            p.observe(now, now - 60);
        }
        assert!(p.queue_persistent);
        assert!(p.congestion_window < 400_000);
        assert!(p.window_control.delay_reductions >= 1);
        // Pauses age out, so the deadline returns to its RTT/jitter value.
        for _ in 0..500 {
            now += 10;
            p.observe(now, now - 5);
        }
        assert!(p.response_pause_ms <= 20);
        assert_eq!(p.repair_ms(), 70);
    }

    #[test]
    fn lone_survivor_deadline_covers_observed_pauses_instead_of_repairing_late_packets() {
        let mut s = scheduler(Policy::Continuity);
        s.remove_path(1);
        // Establish an 8 ms path that has recently shown a 90 ms silence.
        let mut now = 40_u64;
        for _ in 0..10 {
            now += 20;
            s.receive(&Frame::control(Kind::Pong, 0, 0, now - 8), now);
        }
        now += 90;
        s.receive(&Frame::control(Kind::Pong, 0, 0, now - 8), now);
        assert_eq!(s.paths[0].response_pause_ms, 90);
        assert_eq!(s.paths[0].repair_ms(), 110);
        s.enqueue(bulk());
        let sent = s
            .tick(now)
            .into_iter()
            .find(|f| f.kind == Kind::Data)
            .unwrap();
        let born = now;
        // The next hole delays the ACK for 95 ms: under the old 70 ms
        // deadline this was a repair plus a duplicate on the impaired link.
        while now < born + 95 {
            now += 2;
            assert!(
                !s.tick(now).iter().any(|f| f.kind == Kind::Data),
                "repaired at {} ms although the deadline is {} ms",
                now - born,
                s.paths[0].repair_ms()
            );
        }
        s.receive(&Frame::control(Kind::Ack, 0, sent.id, sent.stamp), now);
        assert_eq!(s.pending_packets(), 0);
        assert_eq!(s.counters.repairs, 0);
        assert_eq!(s.paths[0].timeouts, 0);
        // The bound keeps genuine loss recoverable even after long pauses.
        s.paths[0].response_pause_ms = 5_000;
        assert_eq!(s.paths[0].repair_ms(), MAX_PAUSE_REPAIR_MS);
    }

    #[test]
    fn capacity_discovery_grows_quickly_then_backs_off_on_real_loss() {
        let mut path = Path::new(0, "en0".into(), false);
        for _ in 0..512 {
            path.acknowledge_capacity(BOND_MTU);
        }
        assert_eq!(path.congestion_window, 544 * BOND_MTU);
        // Simulate a congestion signal, not radio noise: RTT is well above
        // the observed minimum for longer than any radio hole, so the window
        // halves per AIMD.
        path.minimum_rtt_ms = 10.0;
        for now in (100..=400).step_by(10) {
            path.observe(now, now - 45);
        }
        path.repair_timeout(400, true);
        let reduced = path.congestion_window;
        assert_eq!(reduced, 272 * BOND_MTU);
        assert_eq!(path.window_control.loss_reductions, 1);
        assert_eq!(
            path.window_control.last_reduction.as_ref().unwrap().reason,
            "loss_timeout"
        );
        // Growth stays paused until the queue actually drains.
        path.acknowledge_capacity(BOND_MTU);
        assert_eq!(path.congestion_window, reduced);
        path.observe(410, 400);
        for _ in 0..272 {
            path.acknowledge_capacity(BOND_MTU);
        }
        assert_eq!(path.congestion_window, reduced + BOND_MTU);
        path.congestion_window = 2 * 1024 * 1024;
        path.slow_start_threshold = path.congestion_window;
        for _ in 0..(path.congestion_window / BOND_MTU + 1) {
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
        p[..28].fill(0);
        p[0] = 0x45;
        p[2..4].copy_from_slice(&1200_u16.to_be_bytes());
        p[9] = 17; // UDP
        p[12..16].copy_from_slice(&[10, 0, 0, 2]);
        p[16..20].copy_from_slice(&[69, 164, 208, 201]);
        p[20..22].copy_from_slice(&sport.to_be_bytes());
        p[22..24].copy_from_slice(&dport.to_be_bytes());
        p
    }
    fn srt_control_packet(sport: u16, dport: u16, control_type: u16) -> Vec<u8> {
        let mut p = vec![0_u8; 72];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&72_u16.to_be_bytes());
        p[9] = 17;
        p[12..16].copy_from_slice(&[10, 0, 0, 2]);
        p[16..20].copy_from_slice(&[69, 164, 208, 201]);
        p[20..22].copy_from_slice(&sport.to_be_bytes());
        p[22..24].copy_from_slice(&dport.to_be_bytes());
        p[24..26].copy_from_slice(&52_u16.to_be_bytes());
        p[28..30].copy_from_slice(&(0x8000 | control_type).to_be_bytes());
        // Standard SRT controls use subtype zero. A non-zero destination
        // socket ID also makes the fixture representative of an active flow.
        p[40..44].copy_from_slice(&0x1234_5678_u32.to_be_bytes());
        p
    }

    fn acknowledge_packet(s: &mut Scheduler, sent: &[Frame], now: u64) {
        let first = sent.iter().find(|frame| frame.kind == Kind::Data).unwrap();
        s.receive(
            &Frame::control(Kind::Ack, first.path, first.id, first.stamp),
            now,
        );
    }

    #[test]
    fn recognized_srt_uses_alternate_when_primary_cannot_send() {
        for paced in [false, true] {
            let mut s = scheduler(Policy::Smart);
            s.classify_udp_flow(&srt_control_packet(50000, 9000, 0), 31);
            let data = srt_packet(50000, 9000, 1);
            s.flow_paths.insert(udp_flow_key(&data).unwrap(), (1, 31));
            if paced {
                s.paths[1].next_send = 50.0;
            } else {
                s.paths[1].in_flight = s.paths[1].congestion_window;
            }
            s.enqueue(data.clone());
            let sent = s.tick(32);
            assert!(
                sent.iter()
                    .any(|f| f.kind == Kind::Data && f.path == 0 && f.body == data)
            );
            assert!(!sent.iter().any(|f| f.kind == Kind::Data && f.path == 1));
        }
    }

    #[test]
    fn deferred_media_protection_respects_budget_and_cancels_on_delivery() {
        for paced in [false, true] {
            for acknowledged in [false, true] {
                let mut s = scheduler(Policy::Continuity);
                s.classify_udp_flow(&srt_control_packet(50000, 9000, 0), 31);
                if paced {
                    s.paths[0].next_send = 36.0;
                } else {
                    s.paths[0].in_flight = s.paths[0].congestion_window;
                }
                let data = srt_packet(50000, 9000, 1);
                s.enqueue(data.clone());
                let sent: Vec<_> = s
                    .tick(32)
                    .into_iter()
                    .filter(|f| f.kind == Kind::Data)
                    .collect();
                assert_eq!(sent.len(), 1);
                assert_eq!(sent[0].path, 1);
                assert_eq!(s.counters.protection_deferred, 1);
                assert!(!s.tick(34).iter().any(|f| f.kind == Kind::Data));
                if acknowledged {
                    acknowledge_packet(&mut s, &sent, 34);
                }
                s.paths[0].in_flight = 0;
                let backup: Vec<_> = s
                    .tick(36)
                    .into_iter()
                    .filter(|f| f.kind == Kind::Data)
                    .collect();
                if acknowledged {
                    assert!(backup.is_empty(), "delivered packets need no queued backup");
                    assert_eq!(s.pending_packets(), 0);
                } else {
                    assert_eq!(backup.len(), 1);
                    assert_eq!(backup[0].path, 0);
                    assert_eq!(backup[0].id, sent[0].id);
                    assert_eq!(backup[0].body, data);
                    assert_eq!(s.counters.protection_deferred_sent, 1);
                    let mut rx = scheduler(Policy::Continuity);
                    assert!(rx.receive(&backup[0], 40).0.is_some());
                    assert!(rx.receive(&sent[0], 41).0.is_none());
                    acknowledge_packet(&mut s, &backup, 40);
                    assert_eq!(s.paths[0].in_flight, 0);
                    assert_eq!(s.paths[1].in_flight, 0);
                }
                assert_eq!(s.counters.repairs, 0);
            }
        }
    }

    #[test]
    fn deferred_protection_does_not_revive_removed_paths_or_override_data_saver() {
        for remove in [false, true] {
            let mut s = scheduler(Policy::Continuity);
            s.classify_udp_flow(&srt_control_packet(50000, 9000, 0), 31);
            s.paths[0].next_send = 40.0;
            s.enqueue(srt_packet(50000, 9000, 1));
            s.tick(32);
            assert_eq!(s.counters.protection_deferred, 1);
            if remove {
                s.remove_path(0);
            } else {
                s.policy = Policy::DataSaver;
            }
            assert!(!s.tick(40).iter().any(|f| f.kind == Kind::Data));
            assert!(s.pending.values().all(|p| p.protection_path.is_none()));
        }
    }

    #[test]
    fn recognized_srt_does_not_wait_for_silent_pinned_path() {
        let mut s = scheduler(Policy::Smart);
        let body = srt_control_packet(50000, 9000, 0);
        s.classify_udp_flow(&body, 31);
        let data = srt_packet(50000, 9000, 1);
        let key = udp_flow_key(&data).unwrap();
        s.flow_paths.insert(key, (1, 31));
        s.paths[1].last_response = Some(31);
        s.paths[0].last_response = Some(100);
        // LAN has stopped responding but has not reached full eviction.
        assert!(s.paths[1].ready(100));
        assert!(!s.data_paths(100).contains(&1));
        s.enqueue(data.clone());
        let sent = s.tick(100);
        assert!(
            sent.iter()
                .any(|f| f.kind == Kind::Data && f.path == 0 && f.body == data),
            "a silent SRT primary must not prevent delivery on the live alternate"
        );
    }

    #[test]
    fn smart_learns_srt_without_a_fixed_port_and_protects_bulk_data() {
        let mut s = unequal_latency();
        let control = srt_control_packet(50_000, 23_456, 2);
        assert!(is_srt_control_packet(&control));
        s.enqueue(control);
        let handshake: Vec<_> = s
            .tick(120)
            .into_iter()
            .filter(|frame| frame.kind == Kind::Data)
            .collect();
        assert_eq!(handshake.len(), 2);
        assert_eq!(handshake[0].id, handshake[1].id);
        assert_ne!(handshake[0].path, handshake[1].path);
        acknowledge_packet(&mut s, &handshake, 130);

        let media = srt_packet(50_000, 23_456, 7);
        s.enqueue(media.clone());
        let sent: Vec<_> = s
            .tick(140)
            .into_iter()
            .filter(|frame| frame.kind == Kind::Data && frame.body == media)
            .collect();
        assert_eq!(sent.len(), 2, "recognized SRT must be warm on both paths");
        assert_eq!(sent[0].id, sent[1].id, "copies must deduplicate at relay");
        assert_ne!(sent[0].path, sent[1].path);
    }

    #[test]
    fn late_protection_ack_trains_the_standby_after_delivery_completed() {
        let mut s = unequal_latency();
        let packet = srt_control_packet(50_000, 23_456, 2);
        let bytes = packet.len() as u64;
        let initial_windows = [s.paths[0].congestion_window, s.paths[1].congestion_window];
        s.enqueue(packet);
        let sent: Vec<_> = s
            .tick(120)
            .into_iter()
            .filter(|frame| frame.kind == Kind::Data)
            .collect();
        assert_eq!(sent.len(), 2);
        assert_eq!(sent[0].id, sent[1].id);

        // The faster copy completes delivery and leaves the repair queue.
        s.receive(
            &Frame::control(Kind::Ack, sent[0].path, sent[0].id, sent[0].stamp),
            130,
        );
        assert_eq!(s.pending_packets(), 0);
        assert_eq!(s.paths[usize::from(sent[0].path)].acknowledged_bytes, bytes);
        assert_eq!(
            s.paths[usize::from(sent[1].path)].acknowledged_bytes,
            0,
            "the standby must be trained only after its own copy arrives"
        );

        // Its later ACK must still update delivery/RTT. A single control
        // packet does not validate enough capacity to grow the window.
        s.receive(
            &Frame::control(Kind::Ack, sent[1].path, sent[1].id, sent[1].stamp),
            180,
        );
        let standby = usize::from(sent[1].path);
        assert_eq!(s.paths[standby].acknowledged_bytes, bytes);
        assert_eq!(s.paths[standby].congestion_window, initial_windows[standby]);
        assert_eq!(s.paths[standby].last_response, Some(180));
        assert!(s.paths[standby].window_control.app_limited_growth_acks > 0);
        s.tick(250);
        assert_eq!(
            s.counters.repairs, 0,
            "delivered protection copies need no repair"
        );
    }

    #[test]
    fn srt_fragment_tail_inherits_flow_identity_and_protection() {
        let mut s = unequal_latency();
        let control = srt_control_packet(50_000, 27_000, 2);
        s.enqueue(control);
        let control_frames: Vec<_> = s
            .tick(120)
            .into_iter()
            .filter(|frame| frame.kind == Kind::Data)
            .collect();
        acknowledge_packet(&mut s, &control_frames, 130);

        let mut first = srt_packet(50_000, 27_000, 9);
        first[4..6].copy_from_slice(&91_u16.to_be_bytes());
        first[6] = 0x20; // More Fragments; UDP tuple is still in this fragment.
        s.enqueue(first.clone());
        let first_frames: Vec<_> = s
            .tick(140)
            .into_iter()
            .filter(|frame| frame.kind == Kind::Data && frame.body == first)
            .collect();
        assert_eq!(first_frames.len(), 2);
        acknowledge_packet(&mut s, &first_frames, 150);

        let mut tail = first[..100].to_vec();
        tail[2..4].copy_from_slice(&100_u16.to_be_bytes());
        tail[6..8].copy_from_slice(&147_u16.to_be_bytes());
        tail[20..].fill(0xaa); // Not a UDP header in a non-initial fragment.
        s.enqueue(tail.clone());
        let tail_frames: Vec<_> = s
            .tick(160)
            .into_iter()
            .filter(|frame| frame.kind == Kind::Data && frame.body == tail)
            .collect();
        assert_eq!(tail_frames.len(), 2);
        assert_eq!(tail_frames[0].id, tail_frames[1].id);
    }

    #[test]
    fn data_saver_and_invalid_control_do_not_enable_srt_redundancy() {
        let mut invalid = srt_control_packet(50_000, 29_000, 2);
        invalid[30..32].copy_from_slice(&1_u16.to_be_bytes());
        invalid.resize(600, 0);
        assert!(!is_srt_control_packet(&invalid));
        let mut smart = unequal_latency();
        smart.enqueue(invalid);
        assert_eq!(
            smart
                .tick(120)
                .iter()
                .filter(|frame| frame.kind == Kind::Data)
                .count(),
            1
        );

        let mut saver = scheduler(Policy::DataSaver);
        saver.enqueue(srt_control_packet(50_000, 29_001, 2));
        assert_eq!(
            saver
                .tick(31)
                .iter()
                .filter(|frame| frame.kind == Kind::Data)
                .count(),
            1
        );
    }

    #[test]
    fn returned_path_rediscovers_capacity_instead_of_releasing_a_burst() {
        let mut s = unequal_latency();
        s.paths[1].congestion_window = 4 * 1024 * 1024;
        s.paths[1].delivery_bps = 500_000_000.0;
        s.remove_path(1);
        assert_eq!(s.add_path(s.paths[1].name.clone(), false).unwrap(), 1);
        assert_eq!(s.paths[1].congestion_window, 32 * BOND_MTU);
        assert_eq!(s.paths[1].delivery_bps, 0.0);
        assert_eq!(s.paths[1].state, "discovering");
        assert!(!s.paths[1].ready(120));
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
        let paths: Vec<u8> = (120..126)
            .flat_map(|now| s.tick(now))
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
    fn pinned_udp_obeys_window_and_pacing_without_blocking_another_flow() {
        for blocked_by_pacing in [false, true] {
            let mut s = unequal_latency();
            let first_packet = srt_packet(50000, 9000, 1);
            s.enqueue(first_packet.clone());
            let first = s
                .tick(120)
                .into_iter()
                .find(|f| f.kind == Kind::Data)
                .unwrap();
            let pinned = usize::from(first.path);
            if blocked_by_pacing {
                s.paths[pinned].next_send = 1000.0;
            } else {
                s.paths[pinned].congestion_window = first_packet.len();
                s.paths[pinned].in_flight = first_packet.len();
            }
            let waiting = srt_packet(50000, 9000, 2);
            let independent = srt_packet(50001, 9001, 3);
            s.enqueue(waiting.clone());
            s.enqueue(independent.clone());
            let sent: Vec<_> = s
                .tick(122)
                .into_iter()
                .filter(|f| f.kind == Kind::Data)
                .collect();
            assert_eq!(sent.len(), 1);
            assert_eq!(sent[0].body, independent);
            assert_ne!(sent[0].path, first.path);
            assert_eq!(s.paths[pinned].in_flight, first_packet.len());
            assert_eq!(s.queued.front(), Some(&waiting));
            s.receive(
                &Frame::control(Kind::Ack, first.path, first.id, first.stamp),
                125,
            );
            s.paths[pinned].congestion_window = 32 * BOND_MTU;
            s.paths[pinned].next_send = 0.0;
            let resumed = s
                .tick(126)
                .into_iter()
                .find(|f| f.kind == Kind::Data)
                .unwrap();
            assert_eq!(resumed.body, waiting);
            assert_eq!(resumed.path, first.path);
        }
    }

    #[test]
    fn blocked_pin_preserves_fifo_beyond_the_send_budget() {
        let mut s = unequal_latency();
        s.enqueue(srt_packet(50000, 9000, 0));
        let first = s
            .tick(120)
            .into_iter()
            .find(|f| f.kind == Kind::Data)
            .unwrap();
        s.paths[usize::from(first.path)].next_send = 1000.0;
        let waiting: Vec<_> = (0..200).map(|seed| srt_packet(50000, 9000, seed)).collect();
        for packet in &waiting {
            s.enqueue(packet.clone());
        }
        let independent = srt_packet(50001, 9001, 250);
        s.enqueue(independent.clone());
        let sent: Vec<_> = s
            .tick(122)
            .into_iter()
            .filter(|f| f.kind == Kind::Data)
            .collect();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].body, independent);
        assert_eq!(s.queued.iter().cloned().collect::<Vec<_>>(), waiting);
    }

    #[test]
    fn silent_udp_path_is_repaired_and_replaced_before_eviction() {
        let mut s = unequal_latency();
        s.enqueue(srt_packet(50000, 9000, 1));
        let first = s
            .tick(120)
            .into_iter()
            .find(|f| f.kind == Kind::Data)
            .unwrap();
        let failed = usize::from(first.path);
        let alternate = 1 - failed;
        // No explicit fail_path/remove_path notification: emulate an upstream
        // outage while only the surviving adapter continues answering probes.
        let changed_at = 120;
        s.paths[failed].last_response = Some(changed_at);
        let new_packet = srt_packet(50000, 9000, 2);
        let mut repaired_at = None;
        for now in (122..=220).step_by(2) {
            if now % 20 == 0 {
                s.receive(
                    &Frame::control(Kind::Pong, alternate as u8, now, now - 10),
                    now,
                );
            }
            if now == 182 {
                s.enqueue(new_packet.clone());
            }
            let sent = s.tick(now);
            if sent.iter().any(|f| {
                f.kind == Kind::Data && f.id == first.id && usize::from(f.path) == alternate
            }) {
                repaired_at = Some(now);
                // Repair preserves the original packet identity for dedup.
                s.receive(
                    &Frame::control(Kind::Ack, alternate as u8, first.id, now),
                    now + 10,
                );
            }
            if sent
                .iter()
                .any(|f| f.kind == Kind::Data && f.body == new_packet)
            {
                assert!(
                    sent.iter()
                        .filter(|f| f.body == new_packet)
                        .all(|f| usize::from(f.path) == alternate)
                );
                assert!(
                    now - changed_at + 10 < 100,
                    "10 ms alternate delivery exceeded test budget"
                );
                break;
            }
        }
        assert!(repaired_at.is_some_and(|now| now - changed_at + 10 < 100));
        assert_eq!(
            s.flow_paths[&bulk_udp_flow_key(&new_packet).unwrap()].0,
            alternate
        );
        assert_ne!(
            s.paths[failed].state, "failed",
            "fast steering must not require eviction"
        );
    }

    #[test]
    fn historical_jitter_cannot_stretch_silent_udp_failover_to_seconds() {
        let mut s = unequal_latency();
        s.enqueue(srt_packet(50000, 9000, 1));
        let first = s
            .tick(120)
            .into_iter()
            .find(|f| f.kind == Kind::Data)
            .unwrap();
        let failed = usize::from(first.path);
        let alternate = 1 - failed;
        let changed_at = 120;
        s.paths[failed].jitter_ms = 500.0;
        s.paths[failed].last_response = Some(changed_at);
        assert_eq!(s.paths[failed].failure_ms(), 2_000);
        let next = srt_packet(50000, 9000, 2);
        let mut moved_at = None;
        for now in (122..=220).step_by(2) {
            if now % 20 == 0 {
                s.receive(
                    &Frame::control(Kind::Pong, alternate as u8, now, now - 10),
                    now,
                );
            }
            if now == 182 {
                s.enqueue(next.clone());
            }
            if s.tick(now).iter().any(|frame| {
                frame.kind == Kind::Data
                    && frame.body == next
                    && usize::from(frame.path) == alternate
            }) {
                moved_at = Some(now);
                break;
            }
        }
        assert!(moved_at.is_some_and(|now| now - changed_at + 10 < 100));
        assert_ne!(s.paths[failed].state, "failed");
    }

    #[test]
    fn stale_only_path_is_not_blackholed_before_its_failure_deadline() {
        let mut s = unequal_latency();
        s.remove_path(1);
        assert_eq!(s.data_paths(200), vec![0]);
    }

    #[test]
    fn udp_fragment_keys_ignore_payload_bytes_and_preserve_priority() {
        let mut first = srt_packet(50000, 9000, 1);
        first[4..6].copy_from_slice(&42_u16.to_be_bytes());
        first[6] = 0x20; // More Fragments.
        let mut last = first[..24].to_vec();
        last[2..4].copy_from_slice(&24_u16.to_be_bytes());
        last[6..8].copy_from_slice(&147_u16.to_be_bytes());
        last[20..24].copy_from_slice(&[11, 22, 33, 44]);
        assert_eq!(udp_flow_key(&first), udp_flow_key(&last));
        assert_ne!(
            udp_flow_key(&first),
            udp_flow_key(&srt_packet(50000, 9000, 1))
        );
        assert!(!interactive(&first));
        assert!(!interactive(&last));
        assert!(!is_realtime_media(&last));
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
            .insert(
                original.path as usize,
                Attempt {
                    stamp: 101,
                    generation: scheduler.paths[original.path as usize].generation,
                },
            );
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
        assert_eq!(rx.counters.delivered_bytes, BOND_MTU as u64);
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
    fn returning_used_path_stays_probe_only_during_probation() {
        let mut scheduler = scheduler(Policy::Smart);
        scheduler.paths[1].acknowledged_bytes = 1;
        scheduler.remove_path(1);
        assert_eq!(scheduler.add_path("ethernet".into(), false).unwrap(), 1);

        scheduler.receive(&Frame::control(Kind::Pong, 1, 40, 35), 40);
        assert_eq!(scheduler.paths[1].state, "recovering");
        for now in [50, 60, 5_039] {
            scheduler.receive(&Frame::control(Kind::Pong, 1, now, now - 5), now);
        }
        assert!(!scheduler.paths[1].ready(5_039));
        assert!(!scheduler.data_paths(5_039).contains(&1));

        scheduler.receive(&Frame::control(Kind::Pong, 1, 5_040, 5_035), 5_040);
        assert!(scheduler.paths[1].ready(5_040));
        assert_eq!(scheduler.paths[1].state, "healthy");
    }
    #[test]
    fn returning_path_is_admitted_after_uninterrupted_probe_evidence() {
        let mut scheduler = scheduler(Policy::Smart);
        scheduler.paths[1].acknowledged_bytes = 1;
        scheduler.remove_path(1);
        assert_eq!(scheduler.add_path("ethernet".into(), false).unwrap(), 1);
        // Continuous 20 ms probe replies: admitted after REJOIN_STABLE_MS.
        let mut now = 100;
        scheduler.receive(&Frame::control(Kind::Pong, 1, now, now - 5), now);
        let first = now;
        while now < first + REJOIN_STABLE_MS - 20 {
            now += 20;
            scheduler.receive(&Frame::control(Kind::Pong, 1, now, now - 5), now);
            assert!(!scheduler.paths[1].ready(now), "admitted too early at {now}");
        }
        now += 20;
        scheduler.receive(&Frame::control(Kind::Pong, 1, now, now - 5), now);
        assert!(scheduler.paths[1].ready(now));
        assert!(now - first < REJOIN_PROBATION_MS);
        assert_eq!(scheduler.paths[1].state, "healthy");
        assert_eq!(scheduler.paths[1].congestion_window, 32 * BOND_MTU);
    }
    #[test]
    fn probe_gap_during_probation_restarts_the_stability_clock() {
        let mut scheduler = scheduler(Policy::Smart);
        scheduler.paths[1].acknowledged_bytes = 1;
        scheduler.remove_path(1);
        scheduler.add_path("ethernet".into(), false).unwrap();
        let mut now = 100;
        for _ in 0..50 {
            scheduler.receive(&Frame::control(Kind::Pong, 1, now, now - 5), now);
            now += 20;
        }
        // 1 s of clean replies, then a 200 ms silence (e.g. ARP/route settling).
        now += 200;
        scheduler.receive(&Frame::control(Kind::Pong, 1, now, now - 5), now);
        let restarted = now;
        while now < restarted + REJOIN_STABLE_MS - 20 {
            now += 20;
            scheduler.receive(&Frame::control(Kind::Pong, 1, now, now - 5), now);
            assert!(!scheduler.paths[1].ready(now), "a silence must restart the clock");
        }
        now += 20;
        scheduler.receive(&Frame::control(Kind::Pong, 1, now, now - 5), now);
        assert!(scheduler.paths[1].ready(now));
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
    fn paced_paths_do_not_rescan_the_entire_backlog() {
        let mut s = scheduler(Policy::Smart);
        for p in &mut s.paths {
            p.next_send = 35.0;
        }
        for _ in 0..3000 {
            s.enqueue(packet());
        }
        let queued = s.queued_packets();
        assert!(!s.tick(31).iter().any(|f| f.kind == Kind::Data));
        assert_eq!(s.queued_packets(), queued);
        assert_eq!(s.counters.queue_scans, 0);
        assert!(s.tick(35).iter().any(|f| f.kind == Kind::Data));
        assert!(s.counters.queue_scans < 3000);
        assert_eq!(s.counters.queue_drops, 0);
    }
    #[test]
    fn full_windows_do_not_rescan_the_entire_backlog() {
        let mut s = scheduler(Policy::Smart);
        for p in &mut s.paths {
            p.in_flight = p.congestion_window;
        }
        for _ in 0..3000 {
            s.enqueue(packet());
        }
        assert!(!s.tick(31).iter().any(|f| f.kind == Kind::Data));
        assert_eq!(s.counters.queue_scans, 0);
        // A second available link must still make progress immediately.
        s.paths[1].in_flight = 0;
        assert!(
            s.tick(32)
                .iter()
                .any(|f| f.kind == Kind::Data && f.path == 1)
        );
        assert_eq!(s.counters.queue_drops, 0);
    }
    #[test]
    fn bulk_reserve_stops_scans_but_still_admits_small_priority_packets() {
        let mut s = scheduler(Policy::Smart);
        for p in &mut s.paths {
            p.in_flight = p.congestion_window - 4 * BOND_MTU;
        }
        for _ in 0..3000 {
            s.enqueue(bulk());
        }
        assert!(!s.tick(31).iter().any(|f| f.kind == Kind::Data));
        assert_eq!(s.counters.queue_scans, 0);
        s.enqueue(packet());
        assert!(
            s.tick(32)
                .iter()
                .any(|f| f.kind == Kind::Data && f.body.len() == 100)
        );
        assert_eq!(s.counters.queue_drops, 0);
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
