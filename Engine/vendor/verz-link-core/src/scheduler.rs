//! Packet scheduling port of the copied Pi router, independent of platform I/O.
//! Keep reference ordering and counter semantics: a WAN's media type is not a score.
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub struct Link {
    pub id: u8,
    pub status: u8,
    pub disabled: bool,
    pub probed: bool,
    pub rtt: f64,
    pub jitter: f64,
    pub variance: f64,
    pub loss: f64,
    pub capacity: f64,
    pub uptime: f64,
}

impl Link {
    fn healthy(&self) -> bool {
        !self.disabled && matches!(self.status, 1 | 2)
    }
    fn unstable(&self, threshold: f64) -> bool {
        self.loss > threshold || self.jitter > 30.0 || self.status == 2
    }
    pub fn stability(&self) -> f64 {
        let loss = (self.loss / 100.0).clamp(0.0, 1.0);
        let uptime = if self.uptime <= 0.0 {
            0.01
        } else {
            self.uptime.min(1.0)
        };
        (1.0 - loss)
            * uptime
            * (1.0 / (1.0 + self.variance / 50.0))
            * (1.0 / (1.0 + self.jitter / 20.0))
    }
    pub fn quality(&self, base: f64) -> f64 {
        if !self.probed {
            return 0.0;
        }
        let capacity = if self.capacity <= 0.0 {
            10_000_000.0
        } else {
            self.capacity
        };
        let denom = self.rtt + self.jitter + if base <= 0.0 { 1.0 } else { base };
        capacity * self.stability() / if denom <= 0.0 { 1.0 } else { denom }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct Config {
    pub bond_all: bool,
    pub base_rtt: f64,
    pub voice_max_rtt: f64,
    pub fec: bool,
    pub unstable_loss: f64,
    pub critical_loss: f64,
    pub aggressive_off: bool,
    pub aggressive_spread: f64,
    pub quality_ratio: f64,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            bond_all: false,
            base_rtt: 10.0,
            voice_max_rtt: 300.0,
            fec: true,
            unstable_loss: 8.0,
            critical_loss: 20.0,
            aggressive_off: false,
            aggressive_spread: 150.0,
            quality_ratio: 0.65,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Decision {
    pub primary: u8,
    pub fec: u8,
}

pub struct Scheduler {
    cfg: Config,
    counter: u64,
}
impl Scheduler {
    pub fn new(mut cfg: Config) -> Self {
        if cfg.voice_max_rtt <= 0.0 {
            cfg.voice_max_rtt = 300.0;
        }
        if cfg.unstable_loss <= 0.0 {
            cfg.unstable_loss = 8.0;
        }
        if cfg.critical_loss <= 0.0 {
            cfg.critical_loss = 20.0;
        }
        if cfg.aggressive_spread <= 0.0 {
            cfg.aggressive_spread = 150.0;
        }
        if cfg.quality_ratio <= 0.0 || cfg.quality_ratio > 1.0 {
            cfg.quality_ratio = 0.65;
        }
        Self { cfg, counter: 0 }
    }
    fn next(&mut self) -> u64 {
        self.counter = self.counter.wrapping_add(1);
        self.counter
    }
    fn best_quality(&self, links: &[Link]) -> Link {
        let probed: Vec<_> = links.iter().copied().filter(|s| s.probed).collect();
        let candidates = if probed.is_empty() { links } else { &probed };
        let mut best = candidates[0];
        for s in &candidates[1..] {
            if s.quality(self.cfg.base_rtt) > best.quality(self.cfg.base_rtt) {
                best = *s;
            }
        }
        best
    }
    fn stable(links: &[Link], exclude: u8, max_loss: f64) -> Option<Link> {
        let mut best = None;
        let mut score = 0.0;
        for s in links {
            if s.id == exclude || s.loss > max_loss {
                continue;
            }
            if s.stability() > score {
                best = Some(*s);
                score = s.stability();
            }
        }
        best
    }
    fn can_bond(&self, links: &[Link], spread: f64) -> bool {
        if links.len() < 2
            || links
                .iter()
                .any(|s| !s.probed || s.status != 1 || s.unstable(self.cfg.unstable_loss))
        {
            return false;
        }
        let (mut min_r, mut max_r) = (links[0].rtt, links[0].rtt);
        let (mut min_q, mut max_q) = (links[0].quality(self.cfg.base_rtt), 0.0_f64);
        for s in links {
            min_r = min_r.min(s.rtt);
            max_r = max_r.max(s.rtt);
            min_q = min_q.min(s.quality(self.cfg.base_rtt));
            max_q = max_q.max(s.quality(self.cfg.base_rtt));
        }
        !(spread > 0.0 && max_r - min_r > spread)
            && max_q > 0.0
            && min_q / max_q >= self.cfg.quality_ratio
    }
    fn voice_primary(&self, links: &[Link]) -> Link {
        let fast: Vec<_> = links
            .iter()
            .copied()
            .filter(|s| s.rtt <= self.cfg.voice_max_rtt)
            .collect();
        if fast.is_empty() {
            return self.best_quality(links);
        }
        let best = self.best_quality(&fast);
        if best.loss > self.cfg.critical_loss || best.jitter > 45.0 {
            if let Some(stable) = Self::stable(&fast, 0, self.cfg.unstable_loss)
                && stable.id != best.id
            {
                return stable;
            }
            if let Some(stable) = Self::stable(links, 0, self.cfg.unstable_loss)
                && stable.stability() > best.stability() * 1.5
            {
                return stable;
            }
        }
        best
    }
    fn weighted(&mut self, links: &[Link]) -> Result<u8, &'static str> {
        let weights: Vec<_> = links
            .iter()
            .map(|s| (s.id, s.quality(self.cfg.base_rtt)))
            .filter(|(_, q)| *q > 0.0)
            .collect();
        let total: f64 = weights.iter().map(|(_, q)| q).sum();
        if total <= 0.0 {
            return Err("no schedulable links");
        }
        let h = self.next().wrapping_mul(0x9E3779B97F4A7C15);
        let fraction = (h >> 32) as f64 / 4_294_967_296.0;
        let mut cumulative = 0.0;
        for (id, q) in &weights {
            cumulative += q / total;
            if fraction < cumulative {
                return Ok(*id);
            }
        }
        Ok(weights.last().unwrap().0)
    }
    pub fn schedule(&mut self, class: u16, snapshot: &[Link]) -> Result<Decision, &'static str> {
        let links: Vec<_> = snapshot.iter().copied().filter(Link::healthy).collect();
        if links.is_empty() {
            return Err("no healthy links available");
        }
        let voice = class == 1 || class == 4;
        if voice {
            if !self.cfg.aggressive_off
                && self.can_bond(&links, self.cfg.aggressive_spread)
                && self.can_bond(&links, 75.0)
            {
                let mut sorted = links.clone();
                sorted.sort_by_key(|s| s.id);
                let primary = sorted[self.next() as usize % sorted.len()].id;
                return Ok(Decision { primary, fec: 0 });
            }
            let primary = self.voice_primary(&links).id;
            let fec = if self.cfg.fec {
                Self::stable(&links, primary, f64::INFINITY).map_or(0, |s| s.id)
            } else {
                0
            };
            return Ok(Decision { primary, fec });
        }
        if self.cfg.bond_all {
            let mut sorted = links;
            sorted.sort_by_key(|s| s.id);
            let idx = self.next() as usize % sorted.len();
            let primary = sorted[idx].id;
            let next = sorted[(idx + 1) % sorted.len()].id;
            return Ok(Decision {
                primary,
                fec: if class == 2 && self.cfg.fec && next != primary {
                    next
                } else {
                    0
                },
            });
        }
        if class == 2 {
            let best = self.best_quality(&links);
            let fec = if self.cfg.fec && best.unstable(self.cfg.unstable_loss) {
                Self::stable(&links, best.id, f64::INFINITY).map_or(0, |s| s.id)
            } else {
                0
            };
            return Ok(Decision {
                primary: best.id,
                fec,
            });
        }
        Ok(Decision {
            primary: self.weighted(&links)?,
            fec: 0,
        })
    }
}
