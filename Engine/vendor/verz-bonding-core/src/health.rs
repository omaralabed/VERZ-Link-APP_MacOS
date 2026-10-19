//! Probability that a link has failed, from the rhythm of its feedback.
//!
//! Two kinds of evidence, each judged against what the link itself has shown
//! to be normal:
//!
//! - **Unanswered sends.** Every packet sent on a link is echoed by the
//!   receiver's feedback on that link. A live link rarely leaves a send
//!   unanswered for longer than its usual round trip.
//! - **Silent feedback.** On a busy link feedback arrives every few
//!   milliseconds, so a gap many times longer is damning however long the
//!   round trip is. This catches failures on slow links long before the
//!   first evidence could. It is used only while the link is busy, so an
//!   idle link's sparse feedback is not mistaken for a failure.
//!
//! Either way Bayes' rule gives
//!
//! ```text
//! P(dead | silent for tau) = prior(tau) / (prior(tau) + (1 - prior(tau)) * g(tau))
//! prior(tau) = 1 - exp(-hazard * tau)       chance the link died meanwhile
//! g(tau)     = P(live link stays silent for tau), learned from history
//! ```
//!
//! `g` is empirical up to a high percentile of what was seen and decays
//! exponentially beyond it. For unanswered sends that is the 99th: a real 1%
//! rate of long stalls (ordinary on Wi-Fi) is respected, while one freak
//! delay cannot blunt detection for the next few hundred samples. The wait
//! recorded is that of the *oldest* send an echo answers, since after a stall
//! the echo names the newest packet of the burst and would hide the stall.
//! Silent feedback uses the 90th, so it reacts fast, but it alone never
//! declares a link dead: it makes the link suspect, which routes around it
//! and covers its packets, and leaves certainty to the unanswered sends.

use std::collections::VecDeque;

const MAX_SAMPLES: usize = 256;
const MIN_SAMPLES: usize = 8;
const MAX_OWED: usize = 16_384;
/// Outstanding sends from which a link counts as busy.
const BUSY_OWED: usize = 4;
const US_PER_HOUR: f64 = 3.6e9;
/// Before enough samples are observed, fall back to a plain timeout.
const COLD_TIMEOUT_US: u64 = 1_500_000;
/// Silent feedback can make a link this suspect, never more.
const SILENCE_CAP: f64 = 0.5;

/// How long one kind of wait normally takes on this link.
#[derive(Clone, Debug)]
struct Track {
    samples: VecDeque<u64>,
    sorted: Vec<u64>,
    /// Percentile up to which the distribution is taken as observed.
    anchor: usize,
}

impl Track {
    fn new(anchor: usize) -> Self {
        Self { samples: VecDeque::new(), sorted: Vec::new(), anchor }
    }

    fn record(&mut self, value: u64) {
        if self.samples.len() == MAX_SAMPLES {
            let old = self.samples.pop_front().expect("full");
            if let Ok(i) = self.sorted.binary_search(&old) {
                self.sorted.remove(i);
            }
        }
        self.samples.push_back(value);
        let i = self.sorted.partition_point(|&x| x < value);
        self.sorted.insert(i, value);
    }

    fn median(&self) -> Option<u64> {
        (!self.sorted.is_empty()).then(|| self.sorted[self.sorted.len() / 2])
    }

    /// Probability that a live link makes this wait last `tau`.
    fn survival(&self, tau: u64) -> f64 {
        let n = self.sorted.len();
        let anchor = self.sorted[(n * self.anchor / 100).min(n - 1)];
        if tau <= anchor {
            let above = n - self.sorted.partition_point(|&x| x < tau);
            return (above as f64 + 0.5) / (n as f64 + 1.0);
        }
        let median = self.sorted[n / 2];
        let scale = ((anchor - median) as f64 / 2.0).max(2_000.0);
        let beyond = (100 - self.anchor) as f64 / 100.0;
        beyond * (-((tau - anchor) as f64) / scale).exp()
    }

    fn p_dead_after(&self, tau: u64, hazard_per_hour: f64) -> f64 {
        if self.sorted.len() < MIN_SAMPLES {
            return if tau > COLD_TIMEOUT_US { 1.0 } else { 0.0 };
        }
        let prior = 1.0 - (-(hazard_per_hour / US_PER_HOUR) * tau as f64).exp();
        let g = self.survival(tau);
        prior / (prior + (1.0 - prior) * g)
    }

    /// Wait after which the failure probability first reaches `threshold`.
    fn time_to(&self, threshold: f64, hazard_per_hour: f64) -> u64 {
        let mut hi = 1_000_u64;
        while hi < 8_000_000 && self.p_dead_after(hi, hazard_per_hour) < threshold {
            hi *= 2;
        }
        let mut lo = hi / 2;
        while hi - lo > 250 {
            let mid = (lo + hi) / 2;
            if self.p_dead_after(mid, hazard_per_hour) >= threshold {
                hi = mid;
            } else {
                lo = mid;
            }
        }
        hi
    }
}

#[derive(Clone, Debug)]
pub struct Health {
    owed: VecDeque<u64>,
    answers: Track,
    gaps: Track,
    last_feedback: Option<u64>,
}

impl Default for Health {
    fn default() -> Self {
        Self { owed: VecDeque::new(), answers: Track::new(99), gaps: Track::new(90), last_feedback: None }
    }
}

impl Health {
    /// Something was sent on this link and should be echoed.
    pub fn on_sent(&mut self, now: u64) {
        if self.owed.len() == MAX_OWED {
            self.owed.pop_front();
        }
        self.owed.push_back(now);
    }

    /// Feedback arrived echoing the newest send time this link delivered.
    /// Returns true when it answered at least one outstanding send.
    pub fn on_echo(&mut self, now: u64, echo: u64) -> bool {
        if self.busy()
            && let Some(last) = self.last_feedback
        {
            self.gaps.record(now.saturating_sub(last));
        }
        self.last_feedback = Some(now);
        let mut oldest = None;
        while let Some(&t) = self.owed.front().filter(|&&t| t <= echo) {
            self.owed.pop_front();
            oldest.get_or_insert(t);
        }
        if let Some(t) = oldest {
            self.answers.record(now.saturating_sub(t));
        }
        oldest.is_some()
    }

    fn busy(&self) -> bool {
        self.owed.len() >= BUSY_OWED
    }

    /// Send time of the oldest packet not yet echoed.
    pub fn oldest_unanswered(&self) -> Option<u64> {
        self.owed.front().copied()
    }

    pub fn samples(&self) -> usize {
        self.answers.sorted.len()
    }

    /// Median answer delay, if known.
    pub fn median_delay(&self) -> Option<u64> {
        self.answers.median()
    }

    pub fn p_dead(&self, now: u64, hazard_per_hour: f64) -> f64 {
        let unanswered = self
            .oldest_unanswered()
            .map_or(0.0, |t| self.answers.p_dead_after(now.saturating_sub(t), hazard_per_hour));
        let silent = match self.last_feedback {
            Some(t) if self.busy() => self.gaps.p_dead_after(now.saturating_sub(t), hazard_per_hour).min(SILENCE_CAP),
            _ => 0.0,
        };
        unanswered.max(silent)
    }

    /// Failure probability from an unanswered send alone, after `tau`.
    pub fn p_dead_after(&self, tau: u64, hazard_per_hour: f64) -> f64 {
        self.answers.p_dead_after(tau, hazard_per_hour)
    }

    /// Silence after which the failure probability first reaches `threshold`.
    pub fn time_to(&self, threshold: f64, hazard_per_hour: f64) -> u64 {
        let by_answers = self.answers.time_to(threshold, hazard_per_hour);
        if self.busy() {
            by_answers.min(self.gaps.time_to(threshold, hazard_per_hour))
        } else {
            by_answers
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Sends every `cadence_us`, each answered after its delay. The link is
    /// first in, first out, so a slow packet holds up those behind it, and
    /// feedback is delivered in arrival order.
    fn trained(cadence_us: u64, delays_us: impl IntoIterator<Item = u64>) -> Health {
        let mut h = Health::default();
        let mut events: Vec<(u64, bool, u64)> = Vec::new();
        let mut t = 0;
        let mut last_arrival = 0;
        for d in delays_us {
            t += cadence_us;
            let arrival = (t + d).max(last_arrival);
            last_arrival = arrival;
            events.push((t, true, t));
            events.push((arrival, false, t));
        }
        events.sort_by_key(|&(at, is_send, _)| (at, !is_send));
        for (at, is_send, sent) in events {
            if is_send {
                h.on_sent(at);
            } else {
                h.on_echo(at, sent);
            }
        }
        h
    }

    #[test]
    fn busy_wired_link_is_declared_failed_within_tens_of_milliseconds() {
        let h = trained(5_000, (0..256).map(|i| 16_000 + (i % 6) * 1_000));
        let suspect = h.time_to(0.1, 1.0);
        let dead = h.time_to(0.99, 1.0);
        assert!(suspect < 40_000, "suspect after {suspect} us");
        assert!(dead < 60_000, "dead after {dead} us");
        assert!(h.p_dead_after(20_000, 1.0) < 1e-3);
    }

    #[test]
    fn idle_jittery_cellular_link_needs_more_evidence() {
        // A probe every 50 ms, answered after 50-149 ms: never busy, so only
        // the round trip can tell.
        let h = trained(50_000, (0..256).map(|i| 50_000 + (i * 7919 % 100) * 1_000));
        assert!(h.p_dead_after(120_000, 1.0) < 1e-3);
        assert!(h.time_to(0.1, 1.0) > 150_000);
        assert!(h.time_to(0.99, 1.0) > 250_000);
    }

    #[test]
    fn busy_jittery_cellular_link_is_caught_by_its_feedback_rhythm() {
        // The same round trips, but a packet every 5 ms: feedback arrives
        // every few milliseconds, and a long gap gives the failure away
        // well before a round trip has passed.
        let mut h = trained(5_000, (0..256).map(|i| 50_000 + (i * 7919 % 100) * 1_000));
        // Still busy: the last few sends are in flight.
        for k in 1..=8 {
            h.on_sent(2_000_000 + k * 5_000);
        }
        // Suspect before even one median round trip (100 ms) has passed.
        let suspect = h.time_to(0.1, 1.0);
        assert!(suspect < 100_000, "suspect after {suspect} us");
        assert!(h.time_to(0.1, 1.0) >= h.gaps.time_to(0.1, 1.0));
    }

    #[test]
    fn a_link_with_routine_long_stalls_is_not_suspected_during_one() {
        // Wi-Fi: 8 ms answers, but 2% of them take 100-150 ms.
        let h = trained(5_000, (0..256).map(|i| if i % 50 == 0 { 100_000 + (i % 3) * 25_000 } else { 8_000 + (i % 4) * 500 }));
        assert!(h.p_dead_after(140_000, 1.0) < 0.1, "p {}", h.p_dead_after(140_000, 1.0));
        assert!(h.time_to(0.1, 1.0) > 150_000);
    }

    #[test]
    fn silent_feedback_alone_never_declares_a_link_dead() {
        // Jittery answers (50-149 ms) but feedback every few milliseconds:
        // after 60 ms of silence the feedback rhythm is broken while no send
        // is overdue yet, so the link is suspect, not dead.
        let mut h = trained(5_000, (0..256).map(|i| 50_000 + (i * 7919 % 100) * 1_000));
        for k in 1..=8 {
            h.on_sent(2_000_000 + k * 5_000);
        }
        let p = h.p_dead(2_100_000, 1.0);
        assert!((0.1..=SILENCE_CAP).contains(&p), "p {p}");
    }

    #[test]
    fn one_freak_delay_does_not_blunt_detection() {
        let mut steady = trained(5_000, (0..256).map(|_| 20_000));
        let mut freak = steady.clone();
        freak.on_sent(2_000_000);
        freak.on_echo(2_150_000, 2_000_000);
        steady.on_sent(2_000_000);
        steady.on_echo(2_020_000, 2_000_000);
        let a = steady.answers.time_to(0.1, 1.0);
        let b = freak.answers.time_to(0.1, 1.0);
        assert!(b <= a + 5_000, "steady {a} us, after one 150 ms echo {b} us");
    }

    #[test]
    fn an_answer_clears_suspicion() {
        let mut h = trained(5_000, (0..64).map(|_| 20_000));
        h.on_sent(1_000_000);
        assert!(h.p_dead(1_200_000, 1.0) > 0.99);
        h.on_echo(1_210_000, 1_000_000);
        assert_eq!(h.p_dead(1_210_000, 1.0), 0.0);
    }
}
