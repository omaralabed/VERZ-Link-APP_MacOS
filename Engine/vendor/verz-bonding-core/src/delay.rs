//! Queueing delay on a link, from its echo delays.
//!
//! The smallest echo delay seen over a long window is the link's delay with an
//! empty queue. The smallest over the last few tens of milliseconds is its
//! delay now, with most jitter filtered out. The difference is the queue a
//! packet sent now will wait behind. It shows up a few round trips after the
//! link congests, long before the queue overflows and drops anything.

use std::collections::VecDeque;

const BASE_WINDOW_US: u64 = 10_000_000;
const RECENT_WINDOW_US: u64 = 30_000;

#[derive(Clone, Debug, Default)]
pub struct DelayTrack {
    base: VecDeque<(u64, u64)>,
    recent: VecDeque<(u64, u64)>,
}

impl DelayTrack {
    pub fn record(&mut self, now: u64, delay: u64) {
        push_min(&mut self.base, now, delay, BASE_WINDOW_US);
        push_min(&mut self.recent, now, delay, RECENT_WINDOW_US);
    }

    /// Echo delay with an empty queue.
    pub fn base(&self) -> Option<u64> {
        self.base.front().map(|&(_, d)| d)
    }

    /// Extra delay a packet sent now is expected to wait in the queue.
    pub fn queue(&self) -> u64 {
        match (self.recent.front(), self.base()) {
            (Some(&(_, recent)), Some(base)) => recent.saturating_sub(base),
            _ => 0,
        }
    }
}

/// Sliding-window minimum: the front is always the window's minimum.
fn push_min(q: &mut VecDeque<(u64, u64)>, now: u64, value: u64, window: u64) {
    while q.back().is_some_and(|&(_, v)| v >= value) {
        q.pop_back();
    }
    q.push_back((now, value));
    while q.front().is_some_and(|&(t, _)| now.saturating_sub(t) > window) {
        q.pop_front();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jitter_alone_is_not_queueing() {
        let mut d = DelayTrack::default();
        // 60 ms base with up to 30 ms of jitter, one echo every 5 ms.
        let mut worst = 0;
        for i in 0..2_000_u64 {
            d.record(i * 5_000, 60_000 + (i * 7_919 % 31) * 1_000);
            if i > 100 {
                worst = worst.max(d.queue());
            }
        }
        assert_eq!(d.base(), Some(60_000));
        assert!(worst <= 8_000, "30 ms of jitter read as {worst} us of queue");
    }

    #[test]
    fn a_growing_queue_shows_within_the_recent_window() {
        let mut d = DelayTrack::default();
        for i in 0..1_000_u64 {
            d.record(i * 5_000, 60_000);
        }
        // The queue grows by 1 ms per echo for 200 ms.
        let start = 1_000 * 5_000;
        for k in 0..40_u64 {
            d.record(start + k * 5_000, 60_000 + k * 1_000);
        }
        assert!(d.queue() >= 30_000, "queue {}", d.queue());
    }

    #[test]
    fn the_base_forgets_a_path_that_got_permanently_slower() {
        let mut d = DelayTrack::default();
        d.record(0, 20_000);
        for i in 1..=2_200_u64 {
            d.record(i * 5_000, 50_000);
        }
        assert_eq!(d.base(), Some(50_000));
        assert_eq!(d.queue(), 0);
    }
}
