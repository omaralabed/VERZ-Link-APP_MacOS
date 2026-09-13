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
    latest_sent: i64,
    capacity: usize,
}
impl Stream {
    /// Durations are microseconds. Caller owns class-dependent/adaptive budgets.
    pub fn new(budget: u64, grace: u64, capacity: usize) -> Self {
        Self {
            next: 0,
            pending: BTreeMap::new(),
            copies: BTreeMap::new(),
            gap: None,
            nack_at: None,
            retries: 0,
            budget,
            grace,
            latest_sent: 0,
            capacity: capacity.max(1),
        }
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
        // A surviving path can carry only protection copies. Drain the whole
        // contiguous prefix, not one copy per timer tick after a reorder gap.
        while let Some(p) = self
            .pending
            .remove(&self.next)
            .map(|(p, _)| p)
            .or_else(|| self.copies.remove(&self.next))
        {
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
                    nack.push(self.next);
                }
                Some(at)
                    if self.retries < 3
                        && now.saturating_sub(at) >= (self.grace / 2).max(10_000)
                        && now.saturating_sub(at) < self.grace =>
                {
                    self.nack_at = Some(now);
                    self.retries += 1;
                    nack.push(self.next);
                }
                _ => {}
            }
        }
        Output { ready, ack, nack }
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
        }
        if packet.flags & FEC != 0 {
            if packet.sequence == self.next {
                // Gap-filling data needs no buffer slot, even if future copies
                // filled it. Refusing this packet prevents the queue draining.
                let mut ready = vec![packet];
                self.advance();
                self.sequential(&mut ready);
                return Ok(self.finish(ready, now));
            }
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
    pub fn tick(&mut self, now: u64) -> Output {
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

    #[test]
    fn full_future_copy_buffer_accepts_gap_fill_and_drains_all_ready_copies() {
        let mut s = Stream::new(50_000, 25_000, 4);
        for seq in 1..=4 {
            let mut copy = p(seq);
            copy.flags = FEC;
            assert!(s.insert(copy, 1000).unwrap().ready.is_empty());
        }
        let mut gap = p(0);
        gap.flags = FEC;
        let out = s.insert(gap, 2000).unwrap();
        assert_eq!(
            out.ready.iter().map(|p| p.sequence).collect::<Vec<_>>(),
            vec![0, 1, 2, 3, 4]
        );
        assert_eq!(out.ack, Some(4));
        assert!(s.copies.is_empty());
    }
}
