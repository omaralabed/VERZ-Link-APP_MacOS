//! Sending half: link health, repair planning and repair emission.
//!
//! Originals are placed by the caller's existing scheduler; this module only
//! decides which links are usable and which repairs to add:
//!
//! - **Proactive** repairs at the planned rate, for failures that reaction
//!   alone could not repair before the deadline.
//! - **Speculative** repairs the moment a link becomes suspect, covering the
//!   originals it may have swallowed, sent on the healthy links. A link whose
//!   queue would deliver after the deadline counts as suspect too. Anything
//!   the caller still places on an untrusted link afterwards (because nothing
//!   better was left) is covered one packet at a time as it goes.
//! - **Reactive** repairs as soon as feedback shows a link lost packets, and
//!   again for originals the receiver still reports missing.
//!
//! A repair covers a range of the unconfirmed window, so one repair fixes
//! whichever single original is missing there; nobody needs to know which.
//! Reactive repairs end at the last packet their link has echoed, so they
//! are never held up by packets that are merely still in flight.

use crate::coding::RepairHeader;
use crate::delay::DelayTrack;
use crate::health::Health;
use crate::planner::{self, PlanLink, Unit};
use crate::receiver::{LinkCounts, Report};
use std::collections::{HashMap, VecDeque};

#[derive(Clone, Debug)]
pub struct SenderConfig {
    /// End-to-end budget from send to release.
    pub deadline_us: u64,
    /// Acceptable fraction of originals missing their deadline because a
    /// failure was left unprotected.
    pub target_miss: f64,
    /// Protect every single-unit failure regardless of risk (continuity).
    pub protect_always: bool,
    pub max_window: u32,
    /// Failure probability at which a link is avoided and its in-flight
    /// originals are covered speculatively.
    pub suspect: f64,
    /// Failure probability at which a link is considered down.
    pub dead: f64,
    /// Prior failure rate per link, per hour.
    pub prior_outages_per_hour: f64,
    pub plan_interval_us: u64,
    pub packet_bits: f64,
    /// Measured loss rate at which a link is avoided like a suspect one.
    pub lossy: f64,
    /// How often the receiver reports, for reaction-time estimates.
    pub feedback_interval_us: u64,
    /// Share of the deadline: a link whose packets are predicted to take
    /// longer than this one way, because of its queue, is avoided. Its
    /// in-flight packets are covered once they are predicted to be late.
    pub congested: f64,
}

impl Default for SenderConfig {
    fn default() -> Self {
        Self {
            deadline_us: 200_000,
            target_miss: 1e-4,
            protect_always: false,
            max_window: 256,
            suspect: 0.1,
            dead: 0.99,
            prior_outages_per_hour: 1.0,
            plan_interval_us: 50_000,
            packet_bits: 1_254.0 * 8.0,
            lossy: 0.2,
            feedback_interval_us: 5_000,
            congested: 0.75,
        }
    }
}

/// What the platform knows about a link right now.
#[derive(Clone, Debug)]
pub struct LinkInput {
    pub id: u8,
    /// Interface is up (cable present, radio associated).
    pub carrier: bool,
    /// Shared upstream hint, e.g. the public address the server observed.
    pub upstream: Option<u32>,
    pub cost: f64,
    pub capacity_bps: f64,
    pub rtt_us: f64,
    /// Expected loss rate, used until enough packets have been measured.
    pub loss: f64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkState {
    Healthy,
    /// Delivering, but its queue makes packets sent now late: originals may
    /// still go on it when the scheduler sees nothing faster, repairs never.
    Slow,
    /// Silent or losing too much: avoided while anything else is left.
    Suspect,
    Dead,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RepairKind {
    Proactive,
    Speculative,
    Reactive,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RepairOrder {
    pub link: u8,
    pub header: RepairHeader,
    pub kind: RepairKind,
}

/// Per-link view for status pages and traces.
#[derive(Clone, Debug)]
pub struct LinkStatus {
    pub id: u8,
    pub state: LinkState,
    pub p_dead: f64,
    /// Originals placed per second.
    pub placed_pps: f64,
    /// Planned proactive repairs per second.
    pub repair_pps: f64,
    pub median_echo_us: Option<u64>,
    pub loss: f64,
    /// Queueing delay a packet sent now would see.
    pub queue_us: u64,
    /// One-way delay a packet sent now is expected to take.
    pub predicted_owd_us: f64,
    /// Capacity measured while the link was queueing, if it ever was.
    pub measured_capacity_bps: Option<f64>,
    /// Avoided because its queue would make packets late.
    pub congested: bool,
    /// How many times the link has become congested.
    pub slow_episodes: u32,
}

#[derive(Clone, Debug, Default)]
pub struct SenderStats {
    pub proactive: u64,
    pub speculative: u64,
    pub reactive: u64,
    pub unprotected_units: usize,
    /// Recent speculative covers: (time, link, first sequence, wanted, sent).
    pub covers: VecDeque<(u64, u8, u32, usize, usize)>,
}

#[derive(Clone, Debug)]
struct Tx {
    input: LinkInput,
    health: Health,
    placed: u64,
    rate_pps: f64,
    tokens: f64,
    plan_rate: f64,
    speculated: bool,
    dead: bool,
    outages: u32,
    dead_at: Option<u64>,
    last_stamp: u64,
    sent_packets: u64,
    sent_originals: u64,
    /// (stamp, packets sent, originals sent) up to and including that send.
    log: VecDeque<(u64, u64, u64)>,
    lost_packets: u64,
    lost_originals: u64,
    /// (packets, lost packets) at the previous loss-rate sample.
    loss_base: (u64, u64),
    measured_loss: Option<f64>,
    loss_sampled_at: u64,
    delay: DelayTrack,
    congested: bool,
    /// (time, packets received, busy then) at the previous delivery sample.
    delivery_base: Option<(u64, u64, bool)>,
    /// Capacity measured while the link was queueing, grown since.
    measured_capacity: Option<f64>,
    admit_tokens: f64,
    admit_at: u64,
    /// Bits of repairs sent recently that the link is still working off.
    burst_bits: f64,
    burst_at: u64,
    slow_episodes: u32,
}

/// Packets per loss-rate sample.
const LOSS_SAMPLE: u64 = 32;
/// Shortest window for a delivery-rate sample.
const DELIVERY_SAMPLE_US: u64 = 100_000;
/// Queueing beyond this means the link is delivering all it can.
const SATURATED_QUEUE_US: u64 = 10_000;
/// Share of a measured capacity offered to originals.
const ADMIT_SHARE: f64 = 0.85;
/// A measured capacity never falls below this, so a link can always be
/// tried again.
const MIN_MEASURED_BPS: f64 = 100_000.0;
/// Growth per second of a measured capacity while the link carries its
/// allowance without queueing, so a link that recovered is found out
/// without flooding it.
const CAPACITY_GROWTH_PER_S: f64 = 0.25;
const MAX_LOG: usize = 65_536;

impl Tx {
    /// Timestamps are unique per link, so feedback names an exact send.
    fn stamp(&mut self, now: u64, original: bool) -> u64 {
        let stamp = now.max(self.last_stamp + 1);
        self.last_stamp = stamp;
        self.health.on_sent(stamp);
        self.sent_packets += 1;
        self.sent_originals += u64::from(original);
        if self.log.len() == MAX_LOG {
            self.log.pop_front();
        }
        self.log.push_back((stamp, self.sent_packets, self.sent_originals));
        stamp
    }

    fn loss(&self) -> f64 {
        self.measured_loss.unwrap_or(self.input.loss)
    }

    /// One-way delay for a packet sent now: the empty-queue delay plus the
    /// queue as last reported. (Extrapolating the queue's growth was tried
    /// and dropped: a repair burst looks like a trend and starves cover.)
    fn predicted_owd(&self) -> f64 {
        match self.delay.base() {
            Some(base) => base as f64 / 2.0 + self.delay.queue() as f64,
            None => self.input.rtt_us / 2.0,
        }
    }

    /// What the link can carry: measured while it was queueing, otherwise
    /// what the platform believes.
    fn capacity_bps(&self) -> f64 {
        self.measured_capacity.unwrap_or(self.input.capacity_bps)
    }

    /// Queue the recent repair bursts still add, which the echo delay will
    /// only show a round trip from now.
    fn burst_queue_us(&mut self, now: u64) -> f64 {
        let drained = self.capacity_bps() * now.saturating_sub(self.burst_at) as f64 / 1e6;
        self.burst_bits = (self.burst_bits - drained).max(0.0);
        self.burst_at = now;
        self.burst_bits * 1e6 / self.capacity_bps().max(1.0)
    }
}

#[derive(Clone, Copy, Debug)]
struct Sent {
    seq: u32,
    sent_us: u64,
    link: u8,
}

pub struct CodedSender {
    cfg: SenderConfig,
    links: Vec<Tx>,
    window: VecDeque<Sent>,
    /// (send time, link) of recent repairs.
    repairs: VecDeque<(u64, u8)>,
    co_failures: HashMap<(u8, u8), u32>,
    next_seed: u32,
    start: Option<u64>,
    last_plan: u64,
    last_tokens: u64,
    last_rates: u64,
    orders: Vec<RepairOrder>,
    round_robin: usize,
    pub stats: SenderStats,
}

impl CodedSender {
    pub fn new(cfg: SenderConfig) -> Self {
        Self {
            cfg,
            links: Vec::new(),
            window: VecDeque::new(),
            repairs: VecDeque::new(),
            co_failures: HashMap::new(),
            next_seed: 1,
            start: None,
            last_plan: 0,
            last_tokens: 0,
            last_rates: 0,
            orders: Vec::new(),
            round_robin: 0,
            stats: SenderStats::default(),
        }
    }

    pub fn update_links(&mut self, now: u64, inputs: &[LinkInput]) {
        self.start.get_or_insert(now);
        for input in inputs {
            match self.links.iter_mut().find(|t| t.input.id == input.id) {
                Some(tx) => tx.input = input.clone(),
                None => self.links.push(Tx {
                    input: input.clone(),
                    health: Health::default(),
                    placed: 0,
                    rate_pps: 0.0,
                    tokens: 0.0,
                    plan_rate: 0.0,
                    speculated: false,
                    dead: false,
                    outages: 0,
                    dead_at: None,
                    last_stamp: 0,
                    sent_packets: 0,
                    sent_originals: 0,
                    log: VecDeque::new(),
                    lost_packets: 0,
                    lost_originals: 0,
                    loss_base: (0, 0),
                    measured_loss: None,
                    loss_sampled_at: now,
                    delay: DelayTrack::default(),
                    congested: false,
                    delivery_base: None,
                    measured_capacity: None,
                    admit_tokens: 0.0,
                    admit_at: now,
                    burst_bits: 0.0,
                    burst_at: now,
                    slow_episodes: 0,
                }),
            }
        }
        self.links.retain(|t| inputs.iter().any(|i| i.id == t.input.id));
    }

    pub fn state(&self, link: u8, now: u64) -> LinkState {
        let Some(tx) = self.tx(link) else {
            return LinkState::Dead;
        };
        if !tx.input.carrier {
            return LinkState::Dead;
        }
        let p = tx.health.p_dead(now, self.hazard(tx, now));
        if p >= self.cfg.dead {
            LinkState::Dead
        } else if p >= self.cfg.suspect || tx.loss() >= self.cfg.lossy {
            LinkState::Suspect
        } else if tx.congested {
            LinkState::Slow
        } else {
            LinkState::Healthy
        }
    }

    pub fn p_dead(&self, link: u8, now: u64) -> f64 {
        self.tx(link).map_or(1.0, |tx| tx.health.p_dead(now, self.hazard(tx, now)))
    }

    pub fn status(&self, now: u64) -> Vec<LinkStatus> {
        self.links
            .iter()
            .map(|tx| LinkStatus {
                id: tx.input.id,
                state: self.state(tx.input.id, now),
                p_dead: self.p_dead(tx.input.id, now),
                placed_pps: tx.rate_pps,
                repair_pps: tx.plan_rate,
                median_echo_us: tx.health.median_delay(),
                loss: tx.loss(),
                queue_us: tx.delay.queue(),
                predicted_owd_us: tx.predicted_owd(),
                measured_capacity_bps: tx.measured_capacity,
                congested: tx.congested,
                slow_episodes: tx.slow_episodes,
            })
            .collect()
    }

    /// An original was placed on `link`. Returns the timestamp to send with it.
    pub fn on_source_sent(&mut self, now: u64, seq: u32, link: u8) -> u64 {
        let stamp = match self.tx_mut(link) {
            Some(tx) => {
                tx.placed += 1;
                tx.stamp(now, true)
            }
            None => now,
        };
        self.window.push_back(Sent { seq, sent_us: stamp, link });
        // A link in doubt may still be the best there is; what goes on it is
        // covered at once, one repair per original, on a trusted link.
        if self.state(link, now) != LinkState::Healthy {
            let _ = self.emit(now, 1, Some(seq), Some(link), Some(seq), RepairKind::Speculative);
        }
        stamp
    }

    /// A probe or repair was sent on `link`. Returns the timestamp to send with it.
    pub fn on_other_sent(&mut self, now: u64, link: u8) -> u64 {
        self.tx_mut(link).map_or(now, |tx| tx.stamp(now, false))
    }

    /// May an original of `bits` go on `link` now? A link is unrestricted
    /// until congestion has shown what it can carry; from then on originals
    /// are admitted at that rate, which grows while the link keeps up.
    pub fn admit_original(&mut self, now: u64, link: u8, bits: f64) -> bool {
        let Some(tx) = self.tx_mut(link) else {
            return false;
        };
        let Some(capacity) = tx.measured_capacity else {
            return true;
        };
        let dt = now.saturating_sub(tx.admit_at) as f64 / 1e6;
        tx.admit_at = now;
        // A few packets of burst at most.
        tx.admit_tokens = (tx.admit_tokens + ADMIT_SHARE * capacity * dt).min(4.0 * bits);
        if tx.admit_tokens >= bits {
            tx.admit_tokens -= bits;
            true
        } else {
            false
        }
    }

    /// Everything a receiver report carries, arriving on `link`.
    pub fn on_feedback(&mut self, now: u64, link: u8, report: &Report) {
        self.on_echo(now, link, report.echo_us);
        for counts in &report.links {
            let (lost, until) = self.count_losses(now, counts);
            // Repair at once, around the link that lost them.
            let copies = self.reactive_copies(now, counts.id);
            let _ = self.emit(now, lost * copies, None, Some(counts.id), until, RepairKind::Reactive);
        }
        self.on_report(now, report.decoded_through, &report.missing);
    }

    /// Repairs per detected loss. If a lost repair can still be noticed and
    /// replaced before the deadline, one is enough; otherwise send enough
    /// that losing all of them is within the target.
    fn reactive_copies(&self, now: u64, lossy: u8) -> usize {
        let fastest = self.fastest_owd(now, None).min(1_000_000);
        let detected_after = self.tx(lossy).map_or(0.0, Self::owd) as u64 + self.cfg.feedback_interval_us + fastest;
        let round = 2 * fastest + self.cfg.feedback_interval_us + 10_000;
        if detected_after + 2 * round <= self.cfg.deadline_us {
            return 1;
        }
        let repair_loss = self
            .links
            .iter()
            .filter(|t| self.usable(t, now))
            .map(Tx::loss)
            .fold(f64::INFINITY, f64::min);
        let p = if repair_loss.is_finite() { repair_loss.clamp(1e-3, 0.5) } else { 0.5 };
        (self.cfg.target_miss.ln() / p.ln()).ceil().clamp(1.0, 3.0) as usize
    }

    /// Update loss accounting from one link's counts. Returns how many newly
    /// lost originals can still be repaired before their deadline, and the
    /// newest original the link has echoed, where their repairs should end.
    fn count_losses(&mut self, now: u64, counts: &LinkCounts) -> (usize, Option<u32>) {
        let fastest = self.fastest_owd(now, None);
        let packet_bits = self.cfg.packet_bits;
        let silent = self.p_dead(counts.id, now) >= self.cfg.suspect;
        let Some(tx) = self.tx_mut(counts.id) else {
            return (0, None);
        };
        // A congested link with a queue delivers all it can, so its delivery
        // rate over a window that stayed that way is its capacity. Jitter
        // alone must never count as a queue, hence the congested flag; a
        // silent link delivers nothing and must not be measured as such.
        let busy = tx.congested && !silent && tx.delay.queue() > SATURATED_QUEUE_US;
        match tx.delivery_base {
            Some((at, received, busy_then)) if now >= at + DELIVERY_SAMPLE_US => {
                if busy_then && busy {
                    let rate = counts.packets.saturating_sub(received) as f64 * packet_bits * 1e6 / (now - at) as f64;
                    let rate = rate.max(MIN_MEASURED_BPS);
                    tx.measured_capacity = Some(tx.measured_capacity.map_or(rate, |c| 0.5 * c + 0.5 * rate));
                }
                tx.delivery_base = Some((now, counts.packets, busy));
            }
            None => tx.delivery_base = Some((now, counts.packets, busy)),
            _ => {}
        }
        while tx.log.len() > 1 && tx.log[1].0 <= counts.newest_sent {
            tx.log.pop_front();
        }
        let Some(&(_, packets, originals)) = tx.log.front().filter(|e| e.0 <= counts.newest_sent) else {
            return (0, None);
        };
        tx.lost_packets = tx.lost_packets.max(packets.saturating_sub(counts.packets));
        let (base_packets, base_lost) = tx.loss_base;
        if packets >= base_packets + LOSS_SAMPLE {
            let sample = (tx.lost_packets - base_lost) as f64 / (packets - base_packets) as f64;
            tx.measured_loss = Some(tx.measured_loss.map_or(sample, |l| 0.75 * l + 0.25 * sample));
            tx.loss_base = (packets, tx.lost_packets);
            tx.loss_sampled_at = now;
        }
        let lost = originals.saturating_sub(counts.originals);
        let fresh = lost.saturating_sub(tx.lost_originals);
        tx.lost_originals = tx.lost_originals.max(lost);
        if fresh == 0 {
            return (0, None);
        }
        let deadline = self.cfg.deadline_us;
        let live = self
            .window
            .iter()
            .filter(|s| s.link == counts.id && s.sent_us <= counts.newest_sent && s.sent_us + deadline > now + fastest)
            .count();
        let until = self
            .window
            .iter()
            .rev()
            .find(|s| s.link == counts.id && s.sent_us <= counts.newest_sent)
            .map(|s| s.seq);
        ((fresh as usize).min(live), until)
    }

    pub fn on_echo(&mut self, now: u64, link: u8, echo_us: u64) {
        if let Some(tx) = self.tx_mut(link)
            && tx.health.on_echo(now, echo_us)
        {
            tx.delay.record(now, now.saturating_sub(echo_us));
        }
    }

    pub fn on_report(&mut self, now: u64, decoded_through: Option<u32>, missing: &[u32]) {
        if let Some(through) = decoded_through {
            while self.window.front().is_some_and(|s| s.seq <= through) {
                self.window.pop_front();
            }
        }
        let fastest = self.fastest_owd(now, None);
        let live: Vec<u32> = missing
            .iter()
            .copied()
            .filter(|&seq| {
                self.find(seq).is_some_and(|s| s.sent_us + self.cfg.deadline_us > now + fastest)
            })
            .collect();
        let (Some(&oldest), Some(&newest)) = (live.iter().min(), live.iter().max()) else {
            return;
        };
        let in_flight = self.repairs_in_flight(now, now.saturating_sub(self.min_rtt(now) + 10_000));
        let need = live.len().saturating_sub(in_flight);
        let _ = self.emit(now, need, Some(oldest), None, Some(newest), RepairKind::Reactive);
    }

    /// Advance time: detect failures, refresh the plan, emit due repairs.
    pub fn poll(&mut self, now: u64) -> Vec<RepairOrder> {
        self.start.get_or_insert(now);
        self.trim(now);
        self.refresh_rates(now);
        self.detect(now);
        if now.saturating_sub(self.last_plan) >= self.cfg.plan_interval_us {
            self.last_plan = now;
            self.plan(now);
        }
        self.proactive(now);
        std::mem::take(&mut self.orders)
    }

    fn tx(&self, link: u8) -> Option<&Tx> {
        self.links.iter().find(|t| t.input.id == link)
    }

    fn tx_mut(&mut self, link: u8) -> Option<&mut Tx> {
        self.links.iter_mut().find(|t| t.input.id == link)
    }

    fn find(&self, seq: u32) -> Option<&Sent> {
        let i = self.window.binary_search_by_key(&seq, |s| s.seq).ok()?;
        self.window.get(i)
    }

    /// Failures per hour: what was seen, with the prior rate counting as an
    /// hour of observation. (A five-minute prior was tried: it switches
    /// standing protection on for every flaky link, and the extra traffic
    /// cost more packets than it saved.)
    fn hazard(&self, tx: &Tx, now: u64) -> f64 {
        let hours = now.saturating_sub(self.start.unwrap_or(now)) as f64 / 3.6e9;
        (f64::from(tx.outages) + self.cfg.prior_outages_per_hour) / (hours + 1.0)
    }

    fn trim(&mut self, now: u64) {
        while self
            .window
            .front()
            .is_some_and(|s| s.sent_us + self.cfg.deadline_us <= now)
        {
            self.window.pop_front();
        }
        while self.repairs.front().is_some_and(|&(t, _)| now.saturating_sub(t) > 2_000_000) {
            self.repairs.pop_front();
        }
    }

    fn refresh_rates(&mut self, now: u64) {
        let dt = now.saturating_sub(self.last_rates);
        if dt < 100_000 {
            return;
        }
        self.last_rates = now;
        for tx in &mut self.links {
            let instant = tx.placed as f64 * 1e6 / dt as f64;
            tx.rate_pps = 0.7 * tx.rate_pps + 0.3 * instant;
            tx.placed = 0;
            // A loss figure nobody has refreshed fades: an avoided link sees
            // little traffic, and its last bad spell must not bar it forever.
            if let Some(loss) = tx.measured_loss
                && now.saturating_sub(tx.loss_sampled_at) > 500_000
            {
                tx.measured_loss = Some(loss * 0.95);
            }
            // A link carrying its allowance without queueing may be able to
            // carry more than when it was measured: find out gradually.
            if let Some(capacity) = tx.measured_capacity
                && tx.delay.queue() <= SATURATED_QUEUE_US
                && tx.rate_pps * self.cfg.packet_bits >= 0.5 * ADMIT_SHARE * capacity
            {
                tx.measured_capacity = Some(capacity * (1.0 + CAPACITY_GROWTH_PER_S * dt as f64 / 1e6));
            }
        }
    }

    fn detect(&mut self, now: u64) {
        let mut newly_dead = Vec::new();
        let mut newly_suspect = Vec::new();
        let congested_owd = self.cfg.congested * self.cfg.deadline_us as f64;
        for i in 0..self.links.len() {
            let hazard = self.hazard(&self.links[i], now);
            let tx = &mut self.links[i];
            let p = tx.health.p_dead(now, hazard);
            if p >= self.cfg.dead && !tx.dead {
                tx.dead = true;
                tx.outages += 1;
                tx.dead_at = Some(now);
                newly_dead.push(tx.input.id);
            }
            // Hysteresis, so a queue hovering at the limit does not flap.
            let owd = tx.predicted_owd();
            if owd > congested_owd {
                tx.slow_episodes += u32::from(!tx.congested);
                tx.congested = true;
            } else if owd < 0.7 * congested_owd {
                tx.congested = false;
            }
            if p < self.cfg.suspect {
                tx.dead = false;
            }
            if p < self.cfg.suspect && !tx.congested {
                tx.speculated = false;
            } else if !tx.speculated && tx.input.carrier {
                tx.speculated = true;
                newly_suspect.push(tx.input.id);
            }
        }
        // Learn which links fail together.
        for id in newly_dead {
            let partners: Vec<u8> = self
                .links
                .iter()
                .filter(|t| {
                    t.input.id != id && t.dead_at.is_some_and(|at| now.saturating_sub(at) <= 300_000)
                })
                .map(|t| t.input.id)
                .collect();
            for other in partners {
                let key = (id.min(other), id.max(other));
                *self.co_failures.entry(key).or_default() += 1;
            }
        }
        // Cover whatever a suspect link may have swallowed, immediately. A
        // link that is merely queueing still delivers; its packets need cover
        // only once they are predicted to arrive after their deadline.
        for id in newly_suspect {
            let queueing_only = self.state(id, now) == LinkState::Slow;
            if queueing_only && self.tx(id).is_some_and(|tx| tx.predicted_owd() < 0.9 * self.cfg.deadline_us as f64) {
                // Not yet: look again next poll, and cover at once if the
                // link falls silent meanwhile.
                if let Some(tx) = self.tx_mut(id) {
                    tx.speculated = false;
                }
                continue;
            }
            let since = self
                .tx(id)
                .and_then(|t| t.health.oldest_unanswered())
                .unwrap_or(now);
            let at_risk: Vec<u32> = self
                .window
                .iter()
                .filter(|s| s.link == id && s.sent_us >= since)
                .map(|s| s.seq)
                .collect();
            // Repairs it carried meanwhile are presumed lost as well.
            let lost_repairs = self.repairs.iter().filter(|&&(t, link)| link == id && t >= since).count();
            let oldest = at_risk.first().copied().or_else(|| self.window.front().map(|s| s.seq));
            if let Some(oldest) = oldest {
                // A few more than strictly needed: the cover spans packets
                // on other links too, and an undetected loss among them, or
                // of a repair itself, would otherwise hold up the rebuild.
                let range = self.window.back().map_or(0, |b| b.seq.saturating_sub(oldest) + 1) as f64;
                let others: Vec<f64> =
                    self.links.iter().filter(|t| t.input.id != id && t.input.carrier).map(Tx::loss).collect();
                let mean_loss = others.iter().sum::<f64>() / others.len().max(1) as f64;
                let wanted = at_risk.len() + lost_repairs;
                let margin = poisson_quantile((range + wanted as f64) * mean_loss, 1e-3) as usize;
                let wanted = wanted + margin;
                let sent = self.emit(now, wanted, Some(oldest), Some(id), None, RepairKind::Speculative);
                if self.stats.covers.len() == 256 {
                    self.stats.covers.pop_front();
                }
                self.stats.covers.push_back((now, id, oldest, wanted, sent));
            }
        }
    }

    fn usable(&self, tx: &Tx, now: u64) -> bool {
        tx.input.carrier && self.state(tx.input.id, now) == LinkState::Healthy
    }

    /// One-way delay to expect on a link now, queue included.
    fn owd(tx: &Tx) -> f64 {
        let typical = tx.health.median_delay().map_or(tx.input.rtt_us, |d| d as f64).max(1_000.0) / 2.0;
        typical.max(tx.predicted_owd())
    }

    /// One-way delay of the fastest healthy link; of the fastest link with a
    /// carrier when none is healthy, since reaction must still be estimated.
    fn fastest_owd(&self, now: u64, excluding: Option<&[usize]>) -> u64 {
        let fastest = |healthy_only: bool| {
            self.links
                .iter()
                .enumerate()
                .filter(|(i, _)| excluding.is_none_or(|ex| !ex.contains(i)))
                .filter(|(_, t)| if healthy_only { self.usable(t, now) } else { t.input.carrier })
                .map(|(_, t)| Self::owd(t))
                .fold(f64::INFINITY, f64::min)
        };
        let owd = fastest(true);
        let owd = if owd.is_finite() { owd } else { fastest(false) };
        owd.min(1e12) as u64
    }

    fn min_rtt(&self, now: u64) -> u64 {
        2 * self.fastest_owd(now, None).min(1_000_000)
    }

    /// Repairs sent since `since` on links still trusted; those sent on a
    /// link that has since gone suspect are presumed lost.
    fn repairs_in_flight(&self, now: u64, since: u64) -> usize {
        self.repairs
            .iter()
            .rev()
            .take_while(|&&(t, _)| t >= since)
            .filter(|&&(_, link)| self.tx(link).is_some_and(|tx| self.usable(tx, now)))
            .count()
    }

    /// Links that may fail together with `link`: the same upstream, or seen
    /// failing at the same moment before.
    fn partners(&self, link: u8) -> Vec<u8> {
        let upstream = self.tx(link).and_then(|t| t.input.upstream);
        self.links
            .iter()
            .map(|t| t.input.id)
            .filter(|&other| {
                other != link
                    && ((upstream.is_some() && self.tx(other).and_then(|t| t.input.upstream) == upstream)
                        || self.co_failures.get(&(link.min(other), link.max(other))).is_some_and(|&n| n > 0))
            })
            .collect()
    }

    fn header(&mut self, from: Option<u32>, until: Option<u32>) -> Option<RepairHeader> {
        let back = self.window.back()?.seq;
        let front = self.window.front()?.seq;
        let last = until.map_or(back, |u| u.min(back));
        let floor = last.saturating_sub(self.cfg.max_window - 1);
        let first = from.unwrap_or(front).max(front).max(floor);
        if first > last {
            return None;
        }
        let seed = self.next_seed;
        self.next_seed = self.next_seed.wrapping_add(1);
        Some(RepairHeader { first, count: (last - first + 1) as u16, seed })
    }

    /// Send `count` repairs spread over the healthy links, away from `avoid`
    /// and anything that tends to fail with it, safest and fastest first.
    fn emit(
        &mut self,
        now: u64,
        count: usize,
        from: Option<u32>,
        avoid: Option<u8>,
        until: Option<u32>,
        kind: RepairKind,
    ) -> usize {
        if count == 0 {
            return 0;
        }
        let mut excluded: Vec<u8> = avoid.into_iter().collect();
        if let Some(link) = avoid {
            excluded.extend(self.partners(link));
        }
        let candidates = |exclude: &[u8], healthy_only: bool| -> Vec<(u8, f64, f64)> {
            self.links
                .iter()
                .filter(|t| !exclude.contains(&t.input.id))
                .filter(|t| if healthy_only { self.usable(t, now) } else { t.input.carrier })
                .map(|t| (t.input.id, self.p_dead(t.input.id, now), Self::owd(t)))
                .collect()
        };
        // Prefer links unrelated to the avoided one, then any other link. Only
        // a known loss may be repaired on the very link that lost it: covering
        // a suspect link with itself either fails with it or was not needed.
        let avoided: Vec<u8> = avoid.into_iter().collect();
        let mut options = vec![(&excluded[..], true), (&avoided[..], true), (&avoided[..], false)];
        if kind == RepairKind::Reactive {
            options.extend([(&[][..], true), (&[][..], false)]);
        }
        let targets = options
            .into_iter()
            .map(|(exclude, healthy_only)| candidates(exclude, healthy_only))
            .find(|t| !t.is_empty());
        let Some(mut targets) = targets else {
            return 0;
        };
        // Links not suspected of dying first, in coarse bands so ordinary
        // noise does not reorder them; a band is used up before the next is
        // touched. Ordinary loss is not a reason to shun a link here: the
        // margin absorbs it, and spreading keeps every burst short.
        let band = |p_dead: f64| if p_dead < 1e-3 { 0.0 } else { (p_dead * 20.0).floor() + 1.0 };
        targets.sort_by(|a, b| (band(a.1), a.2).partial_cmp(&(band(b.1), b.2)).expect("finite"));
        // A burst is bounded by what each target can work off before the
        // repairs themselves would be late; flooding a link helps nobody.
        let room = self.cfg.congested * self.cfg.deadline_us as f64;
        let mut budget: Vec<usize> = Vec::with_capacity(targets.len());
        for &(id, _, owd) in &targets {
            let tx = self.tx_mut(id).expect("target exists");
            let headroom_us = (room - owd - tx.burst_queue_us(now)).max(0.0);
            budget.push((headroom_us * tx.capacity_bps() / 1e6 / self.cfg.packet_bits) as usize);
        }
        let n = targets.len();
        for sent in 0..count {
            let Some(k) = (0..n)
                .filter(|&k| budget[k] > 0)
                .min_by(|&a, &b| {
                    let order = band(targets[a].1).partial_cmp(&band(targets[b].1)).expect("finite");
                    order.then_with(|| ((self.round_robin + n - a) % n).cmp(&((self.round_robin + n - b) % n)).reverse())
                })
            else {
                return sent;
            };
            self.round_robin = k + 1;
            budget[k] -= 1;
            let Some(header) = self.header(from, until) else {
                return sent;
            };
            self.push(now, targets[k].0, header, kind);
        }
        count
    }

    fn push(&mut self, now: u64, link: u8, header: RepairHeader, kind: RepairKind) {
        match kind {
            RepairKind::Proactive => self.stats.proactive += 1,
            RepairKind::Speculative => self.stats.speculative += 1,
            RepairKind::Reactive => self.stats.reactive += 1,
        }
        self.repairs.push_back((now, link));
        let bits = self.cfg.packet_bits;
        if let Some(tx) = self.tx_mut(link) {
            tx.burst_queue_us(now);
            tx.burst_bits += bits;
        }
        self.orders.push(RepairOrder { link, header, kind });
    }

    fn plan(&mut self, now: u64) {
        let usable: Vec<usize> = (0..self.links.len())
            .filter(|&i| self.usable(&self.links[i], now))
            .collect();
        let total_pps: f64 = self.links.iter().map(|t| t.rate_pps).sum();
        for tx in &mut self.links {
            tx.plan_rate = 0.0;
        }
        // One link cannot protect against its own failure, but standing
        // repairs on it still cover random loss.
        if usable.is_empty() || total_pps <= 0.0 {
            self.stats.unprotected_units = 0;
            return;
        }
        let plan_links: Vec<PlanLink> = usable
            .iter()
            .map(|&i| {
                let tx = &self.links[i];
                let used = tx.rate_pps * self.cfg.packet_bits;
                PlanLink {
                    success: (1.0 - tx.loss()).clamp(0.0, 1.0),
                    spare: ((0.85 * tx.capacity_bps() - used) / self.cfg.packet_bits).max(0.0),
                    cost: tx.input.cost,
                }
            })
            .collect();
        // Failure groups: each link, links sharing an upstream, and links
        // observed failing together.
        let mut groups: Vec<Vec<usize>> = (0..usable.len()).map(|k| vec![k]).collect();
        let mut upstreams: HashMap<u32, Vec<usize>> = HashMap::new();
        for (k, &i) in usable.iter().enumerate() {
            if let Some(u) = self.links[i].input.upstream {
                upstreams.entry(u).or_default().push(k);
            }
        }
        groups.extend(upstreams.into_values().filter(|g| g.len() > 1));
        for (&(a, b), &count) in &self.co_failures {
            let ka = usable.iter().position(|&i| self.links[i].input.id == a);
            let kb = usable.iter().position(|&i| self.links[i].input.id == b);
            if let (Some(ka), Some(kb)) = (ka, kb)
                && count > 0
            {
                let mut pair = vec![ka, kb];
                pair.sort_unstable();
                if !groups.contains(&pair) {
                    groups.push(pair);
                }
            }
        }
        let suspect_ms = |k: usize| {
            let tx = &self.links[usable[k]];
            tx.health.time_to(self.cfg.suspect, self.hazard(tx, now))
        };
        let mut units = Vec::new();
        for members in groups {
            let share: f64 = members.iter().map(|&k| self.links[usable[k]].rate_pps).sum::<f64>() / total_pps;
            if share <= 0.0 {
                continue;
            }
            let survivors: Vec<usize> = (0..usable.len()).filter(|k| !members.contains(k)).collect();
            if survivors.is_empty() {
                continue;
            }
            let excluded: Vec<usize> = members.iter().map(|&k| usable[k]).collect();
            let detect = members.iter().map(|&k| suspect_ms(k)).max().unwrap_or(0);
            let react = detect + self.fastest_owd(now, Some(&excluded)) + 10_000;
            let protect = if self.cfg.protect_always {
                true
            } else if react <= self.cfg.deadline_us {
                // Reaction alone rebuilds everything in time.
                false
            } else {
                let hazard = members
                    .iter()
                    .map(|&k| self.hazard(&self.links[usable[k]], now))
                    .fold(0.0, f64::max);
                let window_hours = react as f64 / 3.6e9;
                let current = members
                    .iter()
                    .map(|&k| self.links[usable[k]].health.p_dead(now, hazard))
                    .fold(0.0, f64::max);
                (hazard * window_hours + current) * share > self.cfg.target_miss
            };
            if protect {
                units.push(Unit { members, required: share * total_pps * 1.1 });
            }
        }
        // Random loss that reaction cannot repair in time: the next packet on
        // the same link reveals the loss, feedback returns on the fastest
        // link and the repair goes out on the fastest link. Size standing
        // repairs so each deadline window rarely sees more losses than repairs.
        let fastest = self.fastest_owd(now, None) as f64;
        let window_us = self.cfg.deadline_us as f64 - fastest - 10_000.0;
        let mut expected = 0.0;
        for &i in &usable {
            let tx = &self.links[i];
            let gap = if tx.rate_pps > 1.0 { 1e6 / tx.rate_pps } else { 50_000.0 };
            let react = gap + Self::owd(tx) + self.cfg.feedback_interval_us as f64 + 2.0 * fastest + 10_000.0;
            if react > self.cfg.deadline_us as f64 && window_us > 0.0 {
                expected += tx.loss() * tx.rate_pps * window_us / 1e6;
            }
        }
        if expected > 0.0 {
            let per_window = poisson_quantile(expected, self.cfg.target_miss);
            units.push(Unit { members: Vec::new(), required: per_window * 1e6 / window_us });
        }
        let plan = planner::solve(&plan_links, &units);
        self.stats.unprotected_units = plan.unprotected;
        for (k, &i) in usable.iter().enumerate() {
            self.links[i].plan_rate = plan.rates[k];
        }
    }

    fn proactive(&mut self, now: u64) {
        let dt = now.saturating_sub(self.last_tokens) as f64 / 1e6;
        self.last_tokens = now;
        if self.window.is_empty() {
            return;
        }
        let mut due = Vec::new();
        for tx in &mut self.links {
            tx.tokens = (tx.tokens + tx.plan_rate * dt).min(4.0);
            while tx.tokens >= 1.0 {
                tx.tokens -= 1.0;
                due.push(tx.input.id);
            }
        }
        for link in due {
            if self.tx(link).is_some_and(|t| self.usable(t, now))
                && let Some(header) = self.header(None, None)
            {
                self.push(now, link, header, RepairKind::Proactive);
            }
        }
    }
}

/// Smallest k with P(Poisson(mean) > k) <= tail.
fn poisson_quantile(mean: f64, tail: f64) -> f64 {
    if mean > 50.0 {
        // Normal approximation; 4 sigma is beyond any target used here.
        return (mean + 4.0 * mean.sqrt()).ceil();
    }
    let mut p = (-mean).exp();
    let mut cdf = p;
    let mut k = 0.0;
    while 1.0 - cdf > tail && k < 1_000.0 {
        k += 1.0;
        p *= mean / k;
        cdf += p;
    }
    k
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(id: u8) -> LinkInput {
        LinkInput {
            id,
            carrier: true,
            upstream: None,
            cost: 1.0,
            capacity_bps: 50e6,
            rtt_us: 20_000.0,
            loss: 0.0,
        }
    }

    /// Two links, 10 ms one-way; answers echo every send.
    fn warmed(cfg: SenderConfig) -> (CodedSender, u64, u32) {
        let mut s = CodedSender::new(cfg);
        s.update_links(0, &[input(1), input(2)]);
        let mut seq = 0;
        let mut now = 0;
        while now < 2_000_000 {
            now += 1_000;
            let link = if seq % 2 == 0 { 1 } else { 2 };
            s.on_source_sent(now, seq, link);
            seq += 1;
            if now > 20_000 {
                s.on_echo(now, 1, now - 21_000);
                s.on_echo(now, 2, now - 20_000);
                s.on_report(now, Some(seq.saturating_sub(25)), &[]);
            }
            s.poll(now);
        }
        (s, now, seq)
    }

    #[test]
    fn silent_failure_triggers_speculative_cover_on_the_survivor() {
        let (mut s, mut now, mut seq) = warmed(SenderConfig::default());
        let stop = now;
        let mut orders = Vec::new();
        while now < stop + 100_000 {
            now += 1_000;
            let link = if seq % 2 == 0 { 1 } else { 2 };
            s.on_source_sent(now, seq, link);
            seq += 1;
            // Link 1 answers nothing after `stop`.
            s.on_echo(now, 2, now - 20_000);
            orders.extend(s.poll(now));
        }
        assert_ne!(s.state(1, now), LinkState::Healthy);
        let speculative: Vec<_> = orders.iter().filter(|o| o.kind == RepairKind::Speculative).collect();
        assert!(!speculative.is_empty());
        assert!(speculative.iter().all(|o| o.link == 2));
    }

    #[test]
    fn loose_deadline_needs_no_proactive_repairs_but_continuity_does() {
        let (relaxed, _, _) = warmed(SenderConfig::default());
        assert_eq!(relaxed.stats.proactive, 0);
        let (always, _, _) = warmed(SenderConfig { protect_always: true, ..Default::default() });
        // Two links: protecting either failure means roughly one repair per original.
        assert!(always.stats.proactive > 1_000, "{}", always.stats.proactive);
    }
}
