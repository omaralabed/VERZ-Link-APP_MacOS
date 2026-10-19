//! A fake network link with the behaviour that matters for bonding:
//! propagation delay, jitter, a finite uplink with a drop-tail queue, bursty
//! loss, capacity that wanders (cellular), and scripted impairments. A link
//! can instead replay a recording of a real one (see `replay.rs`).

use crate::replay::Replay;
use crate::rng::Rng;

/// Gilbert-Elliott bursty loss: a good and a bad state.
#[derive(Clone, Copy, Debug)]
pub struct BurstLoss {
    pub good_to_bad: f64,
    pub bad_to_good: f64,
    pub loss_good: f64,
    pub loss_bad: f64,
}

impl BurstLoss {
    pub const NONE: Self = Self { good_to_bad: 0.0, bad_to_good: 1.0, loss_good: 0.0, loss_bad: 0.0 };
}

#[derive(Clone, Debug)]
pub struct LinkSpec {
    pub name: String,
    pub kind: &'static str,
    pub owd_ms: f64,
    pub jitter_ms: f64,
    pub up_mbps: f64,
    pub queue_ms: f64,
    pub loss: BurstLoss,
    /// Cellular-style capacity random walk.
    pub wandering: bool,
    pub metered: bool,
    /// Shared upstream as the server would observe it (same public IP).
    pub upstream: u32,
    /// A recording of a real link, which replaces the model above.
    pub replay: Option<Replay>,
}

#[derive(Clone, Copy, Debug)]
pub enum Impairment {
    /// Link passes nothing. `visible` outages are seen by the OS (carrier
    /// lost after `CARRIER_DETECT`), silent ones are not.
    Outage { start: u64, end: u64, visible: bool },
    /// Extra loss ramps linearly from `from` to `to`, then stays at `to`.
    LossRamp { start: u64, end: u64, from: f64, to: f64 },
    /// Capacity multiplier ramps linearly from its current level to `to`,
    /// then stays. Later ramps continue from where earlier ones ended.
    CapacityRamp { start: u64, end: u64, to: f64 },
}

/// How long the OS takes to report a pulled cable or lost association.
pub const CARRIER_DETECT_US: u64 = 100_000;

#[derive(Clone, Debug)]
pub struct LinkSim {
    pub spec: LinkSpec,
    pub impairments: Vec<Impairment>,
    up_free_at: f64,
    last_up_arrival: u64,
    last_down_arrival: u64,
    bad_up: bool,
    bad_down: bool,
    walk: f64,
    last_walk: u64,
    rng: Rng,
    /// Separate stream so capacity over time is identical for every method,
    /// however many packets each one sends.
    walk_rng: Rng,
}

impl LinkSim {
    pub fn new(spec: LinkSpec, impairments: Vec<Impairment>, seed: u64) -> Self {
        Self {
            spec,
            impairments,
            up_free_at: 0.0,
            last_up_arrival: 0,
            last_down_arrival: 0,
            bad_up: false,
            bad_down: false,
            walk: 1.0,
            last_walk: 0,
            rng: Rng::new(seed),
            walk_rng: Rng::new(seed ^ 0x5741_4C4B),
        }
    }

    pub fn down_at(&self, t: u64) -> bool {
        if let Some(replay) = &self.spec.replay {
            return replay.down_at(t);
        }
        self.impairments.iter().any(|i| match *i {
            Impairment::Outage { start, end, .. } => t >= start && t < end,
            _ => false,
        })
    }

    pub fn carrier_at(&self, t: u64) -> bool {
        if let Some(replay) = &self.spec.replay {
            return replay.carrier_at(t);
        }
        !self.impairments.iter().any(|i| match *i {
            Impairment::Outage { start, end, visible: true } => {
                t >= start + CARRIER_DETECT_US && t < end
            }
            _ => false,
        })
    }

    pub fn outages(&self) -> Vec<(u64, u64)> {
        if let Some(replay) = &self.spec.replay {
            return replay.outages();
        }
        self.impairments
            .iter()
            .filter_map(|i| match *i {
                Impairment::Outage { start, end, .. } => Some((start, end)),
                _ => None,
            })
            .collect()
    }

    fn extra_loss(&self, t: u64) -> f64 {
        self.impairments
            .iter()
            .map(|i| match *i {
                Impairment::LossRamp { start, end, from, to } if t >= start => {
                    if t >= end {
                        to
                    } else {
                        from + (to - from) * (t - start) as f64 / (end - start) as f64
                    }
                }
                _ => 0.0,
            })
            .fold(0.0, f64::max)
    }

    fn capacity_factor(&mut self, t: u64) -> f64 {
        if self.spec.wandering {
            while self.last_walk + 500_000 <= t {
                self.last_walk += 500_000;
                let step = (0.12 * self.walk_rng.normal()).exp();
                self.walk = (self.walk * step).clamp(0.45, 1.25);
            }
        }
        // Ramps apply in order, each starting from the level the last one left.
        let mut level = 1.0;
        for i in &self.impairments {
            if let Impairment::CapacityRamp { start, end, to } = *i
                && t >= start
            {
                level = if t >= end { to } else { level + (to - level) * (t - start) as f64 / (end - start) as f64 };
            }
        }
        self.walk * level
    }

    fn lost(&mut self, t: u64, up: bool) -> bool {
        let loss = self.spec.loss;
        let bad = if up { &mut self.bad_up } else { &mut self.bad_down };
        *bad = if *bad {
            !self.rng.chance(loss.bad_to_good)
        } else {
            self.rng.chance(loss.good_to_bad)
        };
        let base = if *bad { loss.loss_bad } else { loss.loss_good };
        let p = base + self.extra_loss(t) * (1.0 - base);
        self.rng.chance(p)
    }

    fn jitter(&mut self) -> f64 {
        self.rng.exp(self.spec.jitter_ms * 1_000.0)
    }

    /// Client to server. Returns the arrival time, or `None` if dropped.
    pub fn send_up(&mut self, now: u64, bytes: usize) -> Option<u64> {
        if let Some(replay) = &self.spec.replay {
            let rtt = replay.up(now)?;
            let arrival = (now + rtt / 2).max(self.last_up_arrival);
            self.last_up_arrival = arrival;
            return Some(arrival);
        }
        if self.down_at(now) {
            return None;
        }
        let bps = self.spec.up_mbps * 1e6 * self.capacity_factor(now);
        let start = self.up_free_at.max(now as f64);
        if start - now as f64 > self.spec.queue_ms * 1_000.0 {
            return None;
        }
        self.up_free_at = start + bytes as f64 * 8e6 / bps.max(1.0);
        let arrival = (self.up_free_at + self.spec.owd_ms * 1_000.0 + self.jitter()) as u64;
        let arrival = arrival.max(self.last_up_arrival);
        self.last_up_arrival = arrival;
        if self.down_at(arrival) || self.lost(now, true) {
            return None;
        }
        Some(arrival)
    }

    /// Server to client (feedback). The downlink is assumed uncongested.
    pub fn send_down(&mut self, now: u64) -> Option<u64> {
        if let Some(replay) = &self.spec.replay {
            if replay.down_at(now) {
                return None;
            }
            let arrival = (now + replay.down_rtt(now) / 2).max(self.last_down_arrival);
            self.last_down_arrival = arrival;
            return Some(arrival);
        }
        if self.down_at(now) {
            return None;
        }
        let arrival = (now as f64 + self.spec.owd_ms * 1_000.0 + self.jitter()) as u64;
        let arrival = arrival.max(self.last_down_arrival);
        self.last_down_arrival = arrival;
        if self.down_at(arrival) || self.lost(now, false) {
            return None;
        }
        Some(arrival)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> LinkSpec {
        LinkSpec {
            name: "test".into(),
            kind: "ethernet",
            owd_ms: 10.0,
            jitter_ms: 0.0,
            up_mbps: 8.0,
            queue_ms: 50.0,
            loss: BurstLoss::NONE,
            wandering: false,
            metered: false,
            upstream: 1,
            replay: None,
        }
    }

    #[test]
    fn serialization_queueing_and_drop_tail() {
        let mut link = LinkSim::new(spec(), Vec::new(), 1);
        // 1000 bytes at 8 Mbit/s = 1 ms each.
        assert_eq!(link.send_up(0, 1_000), Some(11_000));
        assert_eq!(link.send_up(0, 1_000), Some(12_000));
        for _ in 0..60 {
            link.send_up(0, 1_000);
        }
        assert_eq!(link.send_up(0, 1_000), None, "queue beyond 50 ms is dropped");
    }

    #[test]
    fn capacity_ramps_chain_so_a_congested_link_recovers() {
        let ramps = vec![
            Impairment::CapacityRamp { start: 1_000, end: 2_000, to: 0.1 },
            Impairment::CapacityRamp { start: 5_000, end: 6_000, to: 1.0 },
        ];
        let mut link = LinkSim::new(spec(), ramps, 1);
        assert!((link.capacity_factor(3_000) - 0.1).abs() < 1e-9);
        assert!((link.capacity_factor(5_500) - 0.55).abs() < 1e-9);
        assert!((link.capacity_factor(7_000) - 1.0).abs() < 1e-9);
    }

    #[test]
    fn silent_outage_keeps_carrier_and_visible_outage_drops_it() {
        let silent = LinkSim::new(spec(), vec![Impairment::Outage { start: 100, end: 900_000, visible: false }], 1);
        assert!(silent.down_at(500_000) && silent.carrier_at(500_000));
        let pulled = LinkSim::new(spec(), vec![Impairment::Outage { start: 100, end: 900_000, visible: true }], 1);
        assert!(pulled.carrier_at(50_000));
        assert!(!pulled.carrier_at(200_000));
    }
}
