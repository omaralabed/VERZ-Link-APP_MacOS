//! Per-stream reassembly with injectable monotonic time for deterministic tests.
use std::collections::BTreeMap;
use verz_link_core::{FEC, Packet};

#[derive(Default, Debug)]
pub struct Output {
    pub ready: Vec<Packet>,
    pub ack: Option<u32>,
    pub nack: Vec<u32>,
}

pub struct Stream {
    next: u32,
    pending: BTreeMap<u32, (Packet, u64)>,
    copies: BTreeMap<u32, Packet>,
    gap: Option<u64>,
    nack_at: Option<u64>,
    retries: u8,
    budget: u64,
    grace: u64,
    adaptive_release: Option<u64>,
    adaptive_sender_epoch: Option<i64>,
    adaptive_receiver_epoch: u64,
    latest_sent: i64,
    capacity: usize,
    repair_before_release: bool,
}
impl Stream {
    pub fn buffered_bytes(&self) -> usize {
        self.pending
            .values()
            .map(|(p, _)| p.payload.len())
            .sum::<usize>()
            + self.copies.values().map(|p| p.payload.len()).sum::<usize>()
    }
    /// Durations are microseconds. Caller owns class-dependent/adaptive budgets.
    pub fn new(budget: u64, grace: u64, capacity: usize) -> Self {
        Self::new_from(0, budget, grace, capacity)
    }

    pub fn new_from(next: u32, budget: u64, grace: u64, capacity: usize) -> Self {
        Self {
            next,
            pending: BTreeMap::new(),
            copies: BTreeMap::new(),
            gap: None,
            nack_at: None,
            retries: 0,
            budget,
            grace,
            adaptive_release: None,
            adaptive_sender_epoch: None,
            adaptive_receiver_epoch: 0,
            latest_sent: 0,
            capacity: capacity.max(1),
            repair_before_release: false,
        }
    }

    pub fn new_repairing(budget: u64, grace: u64, capacity: usize) -> Self {
        Self::new_repairing_from(0, budget, grace, capacity)
    }

    pub fn new_repairing_from(next: u32, budget: u64, grace: u64, capacity: usize) -> Self {
        Self {
            next,
            pending: BTreeMap::new(),
            copies: BTreeMap::new(),
            gap: None,
            nack_at: None,
            retries: 0,
            budget,
            grace,
            adaptive_release: None,
            adaptive_sender_epoch: None,
            adaptive_receiver_epoch: 0,
            latest_sent: 0,
            capacity: capacity.max(1),
            repair_before_release: true,
        }
    }

    /// Enable/update the fixed playout window only for an isolated repairing
    /// stream. Existing continuity streams retain their original behavior.
    pub fn set_adaptive_window(&mut self, nack_delay: u64, release_delay: u64) {
        if self.repair_before_release {
            self.budget = nack_delay.max(1);
            self.adaptive_release = Some(release_delay.max(self.budget));
        }
    }
    fn adaptive_deadline(&self, packet: &Packet) -> u64 {
        let Some(delay) = self.adaptive_release else {
            return 0;
        };
        let sender_epoch = self.adaptive_sender_epoch.unwrap_or(packet.timestamp_us);
        let sender_delta = packet.timestamp_us.saturating_sub(sender_epoch).max(0) as u64;
        self.adaptive_receiver_epoch
            .saturating_add(sender_delta)
            .saturating_add(delay)
    }
    fn clear_gap(&mut self) {
        self.gap = None;
        self.nack_at = None;
        self.retries = 0;
    }
    fn advance(&mut self) {
        self.next = self.next.wrapping_add(1);
        self.clear_gap();
        self.copies.retain(|seq, _| *seq >= self.next);
    }
    fn sequential(&mut self, out: &mut Vec<Packet>) {
        while let Some((p, _)) = self.pending.remove(&self.next) {
            out.push(p);
            self.advance();
        }
    }
    fn next_copy(&mut self, out: &mut Vec<Packet>) -> bool {
        if self.pending.contains_key(&self.next) {
            return false;
        }
        if let Some(p) = self.copies.remove(&self.next) {
            out.push(p);
            self.advance();
            self.sequential(out);
            return true;
        }
        false
    }
    fn finish(&mut self, ready: Vec<Packet>, now: u64) -> Output {
        if self.repair_before_release
            && self.gap.is_none()
            && self
                .pending
                .keys()
                .next()
                .is_some_and(|seq| *seq > self.next)
        {
            // Draining one repaired hole may expose another already-buffered
            // hole. Start its timer now instead of waiting for another packet.
            self.gap = Some(now);
        }
        let ack = if !ready.is_empty() && self.next > 0 {
            Some(self.next - 1)
        } else {
            None
        };
        let mut nack = Vec::new();
        if let Some(gap) = self.gap
            && !self.pending.contains_key(&self.next)
            && !self.copies.contains_key(&self.next)
            && now.saturating_sub(gap) >= self.budget
        {
            match self.nack_at {
                None => {
                    self.nack_at = Some(now);
                    self.retries = 1;
                    self.collect_missing(&mut nack);
                }
                Some(at)
                    if self.retries < 3
                        && now.saturating_sub(at) >= (self.grace / 2).max(10_000)
                        && now.saturating_sub(at) < self.grace =>
                {
                    self.nack_at = Some(now);
                    self.retries += 1;
                    self.collect_missing(&mut nack);
                }
                _ => {}
            }
        }
        Output { ready, ack, nack }
    }

    fn collect_missing(&self, missing: &mut Vec<u32>) {
        if !self.repair_before_release {
            missing.push(self.next);
            return;
        }
        let mut expected = self.next;
        let mut present: Vec<_> = if self.adaptive_release.is_some() {
            self.pending
                .keys()
                .chain(self.copies.keys())
                .copied()
                .collect()
        } else {
            self.pending.keys().copied().collect()
        };
        present.sort_unstable();
        present.dedup();
        for sequence in present {
            if sequence < expected {
                continue;
            }
            while expected < sequence && missing.len() < 32 {
                missing.push(expected);
                expected = expected.wrapping_add(1);
            }
            if missing.len() == 32 {
                return;
            }
            expected = sequence.wrapping_add(1);
        }
        if missing.is_empty() {
            missing.push(self.next);
        }
    }
    pub fn insert(&mut self, packet: Packet, now: u64) -> Result<Output, &'static str> {
        if !packet.is_data() {
            return Ok(Output::default());
        }
        let previous = self.latest_sent;
        self.latest_sent = self.latest_sent.max(packet.timestamp_us);
        if packet.sequence < self.next {
            let reset =
                (packet.sequence == 0 && self.next >= 16) || self.next - packet.sequence > 256;
            if packet.flags & FEC != 0
                || !reset
                || packet.timestamp_us == 0
                || packet.timestamp_us <= previous
            {
                return Ok(Output::default());
            }
            self.next = 0;
            self.pending.clear();
            self.copies.clear();
            self.clear_gap();
            self.adaptive_sender_epoch = None;
            self.adaptive_receiver_epoch = 0;
        }
        if self.adaptive_release.is_some() {
            return self.insert_adaptive(packet, now);
        }
        if packet.flags & FEC != 0 {
            if self.copies.len() >= self.capacity && !self.copies.contains_key(&packet.sequence) {
                return Err("FEC buffer capacity reached");
            }
            let seq = packet.sequence;
            self.copies.insert(seq, packet);
            let mut ready = Vec::new();
            if seq == self.next && self.next_copy(&mut ready) {
                return Ok(self.finish(ready, now));
            }
            if seq > self.next && self.gap.is_none() {
                self.gap = Some(now);
            }
            return Ok(self.tick(now));
        }
        if packet.sequence == self.next {
            let mut ready = vec![packet];
            self.advance();
            self.sequential(&mut ready);
            return Ok(self.finish(ready, now));
        }
        if self.pending.len() >= self.capacity && !self.pending.contains_key(&packet.sequence) {
            return Err("reorder buffer capacity reached");
        }
        self.pending.entry(packet.sequence).or_insert((packet, now));
        if self.gap.is_none() {
            self.gap = Some(now);
        }
        Ok(self.tick(now))
    }
    fn insert_adaptive(&mut self, packet: Packet, now: u64) -> Result<Output, &'static str> {
        if self.adaptive_sender_epoch.is_none() {
            self.adaptive_sender_epoch = Some(packet.timestamp_us);
            self.adaptive_receiver_epoch = now;
        }
        let sequence = packet.sequence;
        if self.pending.contains_key(&sequence) || self.copies.contains_key(&sequence) {
            return Ok(self.tick_adaptive(now));
        }
        if self.pending.len() + self.copies.len() >= self.capacity {
            return Err("adaptive playout buffer capacity reached");
        }
        if packet.flags & FEC != 0 {
            self.copies.insert(sequence, packet);
        } else {
            self.pending.insert(sequence, (packet, now));
        }
        if sequence > self.next && self.gap.is_none() {
            self.gap = Some(now);
        }
        Ok(self.tick_adaptive(now))
    }
    fn adaptive_candidate(&self, sequence: u32) -> Option<&Packet> {
        self.pending
            .get(&sequence)
            .map(|(packet, _)| packet)
            .or_else(|| self.copies.get(&sequence))
    }
    fn adaptive_first_later(&self) -> Option<&Packet> {
        let pending = self
            .pending
            .range(self.next.wrapping_add(1)..)
            .next()
            .map(|(_, (packet, _))| packet);
        let copy = self
            .copies
            .range(self.next.wrapping_add(1)..)
            .next()
            .map(|(_, packet)| packet);
        match (pending, copy) {
            (Some(left), Some(right)) if left.sequence <= right.sequence => Some(left),
            (Some(_), Some(right)) => Some(right),
            (Some(packet), None) | (None, Some(packet)) => Some(packet),
            (None, None) => None,
        }
    }
    fn take_adaptive(&mut self, sequence: u32) -> Option<Packet> {
        self.pending
            .remove(&sequence)
            .map(|(packet, _)| packet)
            .or_else(|| self.copies.remove(&sequence))
    }
    fn tick_adaptive(&mut self, now: u64) -> Output {
        let mut ready = Vec::new();
        loop {
            if let Some(packet) = self.adaptive_candidate(self.next) {
                if now < self.adaptive_deadline(packet) {
                    break;
                }
                let sequence = self.next;
                if let Some(packet) = self.take_adaptive(sequence) {
                    ready.push(packet);
                    self.advance();
                    continue;
                }
            }
            let Some(later) = self.adaptive_first_later() else {
                break;
            };
            let later_deadline = self.adaptive_deadline(later);
            if self.gap.is_none() {
                self.gap = Some(now);
            }
            if now < later_deadline {
                break;
            }
            // The measured protection deadline passed without either an
            // original or a copy. Drop exactly this sequence and continue the
            // time-aligned playout; later packets never escape early.
            self.advance();
        }
        self.finish(ready, now)
    }
    pub fn tick(&mut self, now: u64) -> Output {
        if self.adaptive_release.is_some() {
            return self.tick_adaptive(now);
        }
        let mut ready = Vec::new();
        if self.next_copy(&mut ready) {
            return self.finish(ready, now);
        }
        if let Some((packet, _)) = self.pending.remove(&self.next) {
            ready.push(packet);
            self.advance();
            self.sequential(&mut ready);
            return self.finish(ready, now);
        }
        if self.repair_before_release
            && let Some(gap) = self.gap
            && now.saturating_sub(gap) >= self.budget
        {
            if self
                .nack_at
                .is_some_and(|at| now.saturating_sub(at) >= self.grace)
            {
                // The repair window expired. Drop exactly the missing sequence,
                // then release only the now-contiguous suffix.
                self.advance();
                self.sequential(&mut ready);
                return self.finish(ready, now);
            }
            // finish() emits or repeats the NACK. Do not run the legacy aged
            // release below while a Bonded Speed repair is still possible.
            return self.finish(ready, now);
        }
        if self.gap.is_some()
            && self
                .nack_at
                .is_some_and(|at| now.saturating_sub(at) >= self.grace)
            && !self.copies.contains_key(&self.next)
        {
            self.pending.remove(&self.next);
            self.advance();
        }
        if self.next_copy(&mut ready) {
            return self.finish(ready, now);
        }
        let aged: Vec<_> = self
            .pending
            .iter()
            .filter(|(seq, (_, at))| **seq != self.next && now.saturating_sub(*at) > self.budget)
            .map(|(&seq, _)| seq)
            .collect();
        for seq in aged {
            let Some((packet, _)) = self.pending.remove(&seq) else {
                continue;
            };
            let packet = self.copies.remove(&seq).unwrap_or(packet);
            if seq < self.next {
                continue;
            }
            if seq > self.next {
                self.pending.retain(|s, _| *s < self.next || *s >= seq);
                self.copies.retain(|s, _| *s < self.next || *s >= seq);
                self.next = seq;
                self.clear_gap();
            }
            ready.push(packet);
            self.advance();
        }
        self.sequential(&mut ready);
        self.finish(ready, now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn p(sequence: u32) -> Packet {
        Packet {
            sequence,
            class: 4,
            timestamp_us: 100 + sequence as i64,
            ..Default::default()
        }
    }
    fn stream() -> Stream {
        Stream::new(50_000, 25_000, 512)
    }
    #[test]
    fn restores_packet_order_and_acks() {
        let mut s = stream();
        assert_eq!(s.insert(p(0), 0).unwrap().ack, Some(0));
        assert!(s.insert(p(2), 1).unwrap().ready.is_empty());
        let out = s.insert(p(1), 2).unwrap();
        assert_eq!(
            out.ready.iter().map(|p| p.sequence).collect::<Vec<_>>(),
            vec![1, 2]
        );
        assert_eq!(out.ack, Some(2));
    }
    #[test]
    fn backup_copy_recovers_missing_primary_once() {
        let mut s = stream();
        let mut copy = p(0);
        copy.flags = FEC;
        copy.link = 2;
        assert_eq!(s.insert(copy, 0).unwrap().ready.len(), 1);
        assert!(s.insert(p(0), 1).unwrap().ready.is_empty());
    }
    #[test]
    fn tick_requests_gap_without_new_packets() {
        let mut s = stream();
        s.insert(p(1), 0).unwrap();
        assert!(s.tick(49_999).nack.is_empty());
        assert_eq!(s.tick(50_000).nack, vec![0]);
        // Mirrors the copied aged-packet rule: expired queued packets may advance the gap.
        assert_eq!(s.tick(50_001).ready[0].sequence, 1);
    }

    #[test]
    fn repairing_stream_requests_missing_packet_before_releasing_later_payload() {
        let mut s = Stream::new_repairing(30_000, 50_000, 1_024);
        assert!(s.insert(p(1), 0).unwrap().ready.is_empty());
        let request = s.tick(30_000);
        assert_eq!(request.nack, vec![0]);
        assert!(request.ready.is_empty());
        let restored = s.insert(p(0), 40_000).unwrap();
        assert_eq!(
            restored
                .ready
                .iter()
                .map(|packet| packet.sequence)
                .collect::<Vec<_>>(),
            [0, 1]
        );
        assert_eq!(restored.ack, Some(1));
    }

    #[test]
    fn repairing_stream_requests_a_burst_of_cross_wan_holes_together() {
        let mut s = Stream::new_repairing(30_000, 50_000, 1_024);
        for sequence in [1, 3, 5] {
            assert!(s.insert(p(sequence), 0).unwrap().ready.is_empty());
        }
        let request = s.tick(30_000);
        assert_eq!(request.nack, [0, 2, 4]);
        assert!(request.ready.is_empty());
    }

    #[test]
    fn adaptive_repair_window_waits_for_a_delayed_protection_copy() {
        let mut s = Stream::new_repairing(30_000, 50_000, 1_024);
        s.set_adaptive_window(30_000, 300_000);
        assert!(s.insert(p(1), 0).unwrap().ready.is_empty());
        assert_eq!(s.tick(30_000).nack, [0]);
        assert!(s.tick(299_999).ready.is_empty());

        let restored = s.insert(p(0), 300_000).unwrap();
        assert_eq!(
            restored
                .ready
                .iter()
                .map(|packet| packet.sequence)
                .collect::<Vec<_>>(),
            [0, 1]
        );
    }

    #[test]
    fn adaptive_repair_window_releases_after_its_measured_deadline() {
        let mut s = Stream::new_repairing(30_000, 50_000, 1_024);
        s.set_adaptive_window(30_000, 300_000);
        assert!(s.insert(p(1), 0).unwrap().ready.is_empty());
        assert_eq!(s.tick(30_000).nack, [0]);
        assert!(s.tick(299_999).ready.is_empty());
        assert_eq!(
            s.tick(300_000)
                .ready
                .iter()
                .map(|packet| packet.sequence)
                .collect::<Vec<_>>(),
            [1]
        );
    }

    #[test]
    fn adaptive_playout_holds_even_in_order_payload_until_its_deadline() {
        let mut s = Stream::new_repairing(30_000, 50_000, 1_024);
        s.set_adaptive_window(30_000, 300_000);
        assert!(s.insert(p(0), 0).unwrap().ready.is_empty());
        assert!(s.tick(299_999).ready.is_empty());
        assert_eq!(s.tick(300_000).ready[0].sequence, 0);
    }

    #[test]
    fn adaptive_playout_uses_sender_timing_for_a_copy_that_arrives_late() {
        let mut s = Stream::new_repairing(30_000, 50_000, 1_024);
        s.set_adaptive_window(30_000, 300_000);
        assert!(s.insert(p(1), 1).unwrap().ready.is_empty());
        let mut copy = p(0);
        copy.flags = FEC;
        assert!(s.insert(copy, 250_000).unwrap().ready.is_empty());
        assert!(s.tick(299_999).ready.is_empty());
        assert_eq!(
            s.tick(300_001)
                .ready
                .iter()
                .map(|packet| packet.sequence)
                .collect::<Vec<_>>(),
            [0, 1]
        );
    }

    #[test]
    fn adaptive_playout_hides_a_fast_wan_gap_with_slow_wan_copies() {
        let mut s = Stream::new_repairing(30_000, 50_000, 1_024);
        s.set_adaptive_window(30_000, 300_000);
        let mut events = Vec::new();
        for sequence in 0..20 {
            let mut original = p(sequence);
            original.timestamp_us = i64::from(sequence) * 20_000;
            if !(5..=10).contains(&sequence) {
                events.push((u64::from(sequence) * 20_000 + 10_000, original.clone()));
            }
            let mut copy = original;
            copy.flags = FEC;
            copy.link = 2;
            events.push((u64::from(sequence) * 20_000 + 250_000, copy));
        }
        events.sort_by_key(|(at, _)| *at);

        let mut delivered = Vec::new();
        let mut index = 0;
        for now in (0..=700_000).step_by(1_000) {
            while index < events.len() && events[index].0 <= now {
                let (at, packet) = events[index].clone();
                delivered.extend(
                    s.insert(packet, at)
                        .unwrap()
                        .ready
                        .into_iter()
                        .map(|packet| (now, packet.sequence)),
                );
                index += 1;
            }
            delivered.extend(
                s.tick(now)
                    .ready
                    .into_iter()
                    .map(|packet| (now, packet.sequence)),
            );
        }
        assert_eq!(
            delivered
                .iter()
                .map(|(_, sequence)| *sequence)
                .collect::<Vec<_>>(),
            (0..20).collect::<Vec<_>>()
        );
        assert!(
            delivered
                .windows(2)
                .all(|pair| pair[1].0.saturating_sub(pair[0].0) <= 20_000),
            "the protected output developed a visible delivery gap"
        );
    }

    #[test]
    fn existing_continuity_timing_cannot_be_changed_accidentally() {
        let mut s = Stream::new(50_000, 25_000, 64);
        s.set_adaptive_window(30_000, 300_000);
        assert!(s.insert(p(1), 0).unwrap().ready.is_empty());
        assert!(s.tick(49_999).ready.is_empty());
        assert_eq!(s.tick(50_001).ready[0].sequence, 1);
    }
    #[test]
    fn delayed_packet_does_not_restart_stream() {
        let mut s = stream();
        for seq in 0..300 {
            s.insert(p(seq), seq as u64).unwrap();
        }
        assert!(s.insert(p(0), 301).unwrap().ready.is_empty());
        let mut restart = p(0);
        restart.timestamp_us = 1000;
        assert_eq!(s.insert(restart, 302).unwrap().ack, Some(0));
    }
    #[test]
    fn bounded_pending_memory() {
        let mut s = Stream::new(50_000, 25_000, 2);
        s.insert(p(1), 0).unwrap();
        s.insert(p(2), 0).unwrap();
        assert!(s.insert(p(3), 0).is_err());
    }
}
