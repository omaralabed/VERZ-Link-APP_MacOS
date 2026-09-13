//! Ports of copied Boundlink PacketCache and packetDeduper.
//! Single-owner mutable state; link removal must not recreate these objects.
use crate::Packet;
use std::collections::{HashMap, VecDeque};

fn before(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

pub struct PacketCache {
    max: usize,
    packets: HashMap<(u16, u32), Packet>,
    order: VecDeque<(u16, u32)>,
    high_ack: HashMap<u16, u32>,
}
impl PacketCache {
    pub fn new(max: usize) -> Self {
        Self {
            max: if max == 0 { 512 } else { max },
            packets: HashMap::new(),
            order: VecDeque::new(),
            high_ack: HashMap::new(),
        }
    }
    pub fn store(&mut self, packet: Packet) {
        let key = (packet.local_port, packet.sequence);
        if self
            .high_ack
            .get(&key.0)
            .is_some_and(|&ack| key.1 == ack || before(key.1, ack))
        {
            return;
        }
        if !self.packets.contains_key(&key) {
            self.order.push_back(key);
        }
        self.packets.insert(key, packet);
        while self.order.len() > self.max {
            if let Some(key) = self.order.pop_front() {
                self.packets.remove(&key);
            }
        }
    }
    pub fn get(&self, port: u16, seq: u32) -> Option<&Packet> {
        self.packets.get(&(port, seq))
    }
    pub fn trim_through(&mut self, port: u16, ack: u32) {
        if self
            .high_ack
            .get(&port)
            .is_some_and(|&old| ack == old || before(ack, old))
        {
            return;
        }
        self.high_ack.insert(port, ack);
        self.order.retain(|key| {
            if key.0 == port && (key.1 == ack || before(key.1, ack)) {
                self.packets.remove(key);
                false
            } else {
                true
            }
        });
    }
    pub fn reset_flow(&mut self, port: u16) {
        self.high_ack.remove(&port);
        self.order.retain(|key| {
            if key.0 == port {
                self.packets.remove(key);
                false
            } else {
                true
            }
        });
    }
    pub fn len(&self) -> usize {
        self.packets.len()
    }
    pub fn is_empty(&self) -> bool {
        self.packets.is_empty()
    }
}

#[derive(Clone, Copy, Hash, PartialEq, Eq)]
pub struct DeliveryKey {
    pub session: u32,
    pub local_port: u16,
    pub sequence: u32,
    pub timestamp_us: i64,
}
impl From<&Packet> for DeliveryKey {
    fn from(p: &Packet) -> Self {
        Self {
            session: p.session,
            local_port: p.local_port,
            sequence: p.sequence,
            timestamp_us: p.timestamp_us,
        }
    }
}
pub struct Deduper {
    max: usize,
    ttl_us: u64,
    seen: HashMap<DeliveryKey, u64>,
    order: VecDeque<(DeliveryKey, u64)>,
}
impl Deduper {
    pub fn new(max: usize, ttl_us: u64) -> Self {
        Self {
            max,
            ttl_us,
            seen: HashMap::new(),
            order: VecDeque::new(),
        }
    }
    pub fn seen_or_add(&mut self, key: DeliveryKey, now_us: u64) -> bool {
        self.prune(now_us);
        if self.seen.contains_key(&key) {
            return true;
        }
        self.seen.insert(key, now_us);
        self.order.push_back((key, now_us));
        self.prune(now_us);
        false
    }
    fn prune(&mut self, now_us: u64) {
        while let Some(&(key, at)) = self.order.front() {
            if self.order.len() <= self.max && now_us.saturating_sub(at) <= self.ttl_us {
                break;
            }
            self.order.pop_front();
            if self.seen.get(&key) == Some(&at) {
                self.seen.remove(&key);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn p(port: u16, seq: u32) -> Packet {
        Packet {
            local_port: port,
            sequence: seq,
            payload: vec![1, 2, 3],
            ..Default::default()
        }
    }
    #[test]
    fn cache_eviction_and_replacement() {
        let mut c = PacketCache::new(2);
        c.store(p(1, 1));
        c.store(p(1, 1));
        c.store(p(1, 2));
        assert_eq!(c.len(), 2);
        c.store(p(1, 3));
        assert!(c.get(1, 1).is_none());
    }
    #[test]
    fn ack_is_per_flow_and_ignores_stale() {
        let mut c = PacketCache::new(10);
        c.store(p(1, 1));
        c.store(p(1, 2));
        c.store(p(2, 1));
        c.trim_through(1, 1);
        c.trim_through(1, 0);
        c.store(p(1, 1));
        assert!(c.get(1, 1).is_none());
        assert!(c.get(1, 2).is_some());
        assert!(c.get(2, 1).is_some());
    }
    #[test]
    fn sequence_wrap_and_explicit_restart() {
        let mut c = PacketCache::new(10);
        for seq in [u32::MAX, 0, 1] {
            c.store(p(1, seq));
        }
        c.trim_through(1, 0);
        assert_eq!(c.len(), 1);
        assert!(c.get(1, 1).is_some());
        c.reset_flow(1);
        c.store(p(1, 0));
        assert!(c.get(1, 0).is_some());
    }
    #[test]
    fn duplicate_copies_ignore_path_but_distinguish_sender_restart() {
        let mut d = Deduper::new(10, 1000);
        let a = p(1, 1);
        let mut b = a.clone();
        b.link = 2;
        assert!(!d.seen_or_add((&a).into(), 0));
        assert!(d.seen_or_add((&b).into(), 1));
        b.timestamp_us = 1;
        assert!(!d.seen_or_add((&b).into(), 2));
    }
    #[test]
    fn dedup_bounds_and_ttl() {
        let mut d = Deduper::new(2, 10);
        for seq in 0..3 {
            assert!(!d.seen_or_add((&p(1, seq)).into(), 0));
        }
        assert_eq!(d.seen.len(), 2);
        assert!(!d.seen_or_add((&p(1, 0)).into(), 0));
        assert!(!d.seen_or_add((&p(1, 0)).into(), 11));
    }
}
