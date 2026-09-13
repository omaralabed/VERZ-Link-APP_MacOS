//! Capacity-weighted UDP uplink scheduling used only by Bonded Speed (mode 1).
//!
//! The existing continuity modes do not call this controller.  It learns from
//! cumulative receiver ACKs, keeps independent state per WAN incarnation, and
//! schedules by bytes rather than packet count so mixed datagram sizes retain
//! the intended capacity share.
use std::collections::{BTreeMap, HashMap, VecDeque};
use verz_link_core::scheduler::Link;

const DEFAULT_CAPACITY_BPS: f64 = 10_000_000.0;
const MIN_CAPACITY_BPS: f64 = 256_000.0;
const MAX_CAPACITY_BPS: f64 = 10_000_000_000.0;
const SAMPLE_US: u64 = 250_000;
const LOSS_BACKOFF_US: u64 = 250_000;
const LOSS_COOLDOWN_US: u64 = 250_000;
const REPAIR_RETRY_US: u64 = 20_000;
const MIN_SAMPLE_BYTES: u64 = 16 * 1024;
const MAX_PENDING: usize = 32_768;
const MAX_VIRTUAL_BACKLOG_US: f64 = 250_000.0;

fn before(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

#[derive(Clone, Debug)]
struct Delivery {
    path: u8,
    generation: u64,
    wire_bytes: usize,
    loss_counted: bool,
    last_repair_us: Option<u64>,
}

#[derive(Clone, Debug)]
struct PathModel {
    generation: u64,
    capacity_bps: f64,
    virtual_finish_us: f64,
    in_flight: usize,
    sample_started_us: u64,
    sample_sent_bytes: u64,
    sample_delivered_bytes: u64,
    confirmed_samples: u32,
    delivered_bytes: u64,
    sent_bytes: u64,
    nacks: u64,
    last_backoff_us: Option<u64>,
    blocked_until_us: u64,
}

impl PathModel {
    fn new(generation: u64, now_us: u64) -> Self {
        Self {
            generation,
            capacity_bps: DEFAULT_CAPACITY_BPS,
            virtual_finish_us: now_us as f64,
            in_flight: 0,
            sample_started_us: now_us,
            sample_sent_bytes: 0,
            sample_delivered_bytes: 0,
            confirmed_samples: 0,
            delivered_bytes: 0,
            sent_bytes: 0,
            nacks: 0,
            last_backoff_us: None,
            blocked_until_us: 0,
        }
    }

    fn effective_bps(&self, link: &Link) -> f64 {
        (self.capacity_bps * link.stability().clamp(0.10, 1.0))
            .clamp(MIN_CAPACITY_BPS, MAX_CAPACITY_BPS)
    }

    fn sent(&mut self, bytes: usize) {
        self.in_flight = self.in_flight.saturating_add(bytes);
        self.sent_bytes = self.sent_bytes.saturating_add(bytes as u64);
        self.sample_sent_bytes = self.sample_sent_bytes.saturating_add(bytes as u64);
    }

    fn delivered(&mut self, bytes: usize, now_us: u64) {
        self.in_flight = self.in_flight.saturating_sub(bytes);
        self.delivered_bytes = self.delivered_bytes.saturating_add(bytes as u64);
        self.sample_delivered_bytes = self.sample_delivered_bytes.saturating_add(bytes as u64);
        let elapsed = now_us.saturating_sub(self.sample_started_us);
        if elapsed < SAMPLE_US || self.sample_delivered_bytes < MIN_SAMPLE_BYTES {
            return;
        }
        let sample = (self.sample_delivered_bytes as f64 * 8_000_000.0 / elapsed as f64)
            .clamp(MIN_CAPACITY_BPS, MAX_CAPACITY_BPS);
        let offered = self.sample_sent_bytes as f64 * 8_000_000.0 / elapsed as f64;
        // Only reduce a capacity estimate when the path was actually offered
        // enough work to test it. An idle stream is never evidence of a slow WAN.
        let loaded = offered >= self.capacity_bps * 0.75 || self.in_flight >= 32 * 1024;
        let target = (sample * 1.10).clamp(MIN_CAPACITY_BPS, MAX_CAPACITY_BPS);
        if target >= self.capacity_bps || loaded {
            let alpha = if self.confirmed_samples == 0 {
                0.50
            } else {
                0.25
            };
            self.capacity_bps = ((1.0 - alpha) * self.capacity_bps + alpha * target)
                .clamp(MIN_CAPACITY_BPS, MAX_CAPACITY_BPS);
            self.confirmed_samples = self.confirmed_samples.saturating_add(1);
            // A changed service rate must not leave old virtual work hundreds of
            // milliseconds ahead and suppress an otherwise usable path.
            self.virtual_finish_us = self
                .virtual_finish_us
                .min(now_us as f64 + MAX_VIRTUAL_BACKLOG_US);
        }
        self.sample_started_us = now_us;
        self.sample_sent_bytes = 0;
        self.sample_delivered_bytes = 0;
    }

    fn nack(&mut self, now_us: u64) {
        self.nacks = self.nacks.saturating_add(1);
        self.blocked_until_us = self
            .blocked_until_us
            .max(now_us.saturating_add(LOSS_COOLDOWN_US));
        if self
            .last_backoff_us
            .is_some_and(|last| now_us.saturating_sub(last) < LOSS_BACKOFF_US)
        {
            return;
        }
        self.capacity_bps = (self.capacity_bps * 0.85).max(MIN_CAPACITY_BPS);
        self.last_backoff_us = Some(now_us);
    }
}

#[derive(Default)]
pub struct BondedSpeed {
    paths: BTreeMap<u8, PathModel>,
    pending: HashMap<(u16, u32), Delivery>,
    order: VecDeque<(u16, u32)>,
    flow_order: HashMap<u16, VecDeque<u32>>,
    high_ack: HashMap<u16, u32>,
    next_generation: u64,
    pub scheduled_packets: u64,
    pub acknowledged_packets: u64,
    pub nack_events: u64,
    pub repair_packets: u64,
}

impl BondedSpeed {
    pub fn add_path(&mut self, id: u8, now_us: u64) {
        if self.paths.contains_key(&id) {
            return;
        }
        self.next_generation = self.next_generation.saturating_add(1).max(1);
        self.paths
            .insert(id, PathModel::new(self.next_generation, now_us));
    }

    pub fn remove_path(&mut self, id: u8) {
        self.paths.remove(&id);
    }

    pub fn reset_runtime(&mut self, now_us: u64) {
        self.pending.clear();
        self.order.clear();
        self.flow_order.clear();
        self.high_ack.clear();
        for model in self.paths.values_mut() {
            model.in_flight = 0;
            model.virtual_finish_us = now_us as f64;
            model.sample_started_us = now_us;
            model.sample_sent_bytes = 0;
            model.sample_delivered_bytes = 0;
            model.blocked_until_us = 0;
        }
    }

    pub fn capacity_bps(&self, id: u8) -> Option<f64> {
        self.paths
            .get(&id)
            .filter(|path| path.confirmed_samples > 0)
            .map(|path| path.capacity_bps)
    }

    /// Weighted fair service by bytes. A continuously backlogged stream receives
    /// shares proportional to measured usable capacity; idle capacity remains
    /// work-conserving because virtual service drains against monotonic time.
    pub fn select(&mut self, links: &[Link], wire_bytes: usize, now_us: u64) -> Option<u8> {
        for link in links {
            if !self.paths.contains_key(&link.id) {
                self.add_path(link.id, now_us);
            }
        }
        let healthy = |link: &&Link| {
            !link.disabled && matches!(link.status, 1 | 2) && self.paths.contains_key(&link.id)
        };
        let has_unblocked = links.iter().filter(healthy).any(|link| {
            self.paths
                .get(&link.id)
                .is_some_and(|model| now_us >= model.blocked_until_us)
        });
        let selected = links
            .iter()
            .filter(healthy)
            .filter(|link| {
                !has_unblocked
                    || self
                        .paths
                        .get(&link.id)
                        .is_some_and(|model| now_us >= model.blocked_until_us)
            })
            .filter_map(|link| {
                let model = self.paths.get(&link.id)?;
                let rate = model.effective_bps(link);
                let start = model.virtual_finish_us.max(now_us as f64);
                let serialization = wire_bytes as f64 * 8_000_000.0 / rate;
                // Normal bytes in flight grow with RTT and are not congestion.
                // Penalize only work above the estimated bandwidth-delay product.
                let rtt_ms = link.rtt.max(1.0);
                let bdp_bytes = rate * rtt_ms / 8_000.0;
                let excess = (model.in_flight as f64 - bdp_bytes).max(0.0);
                let queue = excess * 8_000_000.0 / rate;
                // Approximate one-way propagation aligns striped packet arrival
                // without excluding a healthy higher-latency WAN from bulk work.
                let propagation = rtt_ms * 500.0;
                Some((
                    link.id,
                    start + serialization + propagation + queue.min(100_000.0),
                ))
            })
            .min_by(|a, b| a.1.total_cmp(&b.1))?;
        let link = links.iter().find(|link| link.id == selected.0)?;
        let model = self.paths.get_mut(&selected.0)?;
        let rate = model.effective_bps(link);
        let start = model.virtual_finish_us.max(now_us as f64);
        model.virtual_finish_us = start + wire_bytes as f64 * 8_000_000.0 / rate;
        Some(selected.0)
    }

    pub fn sent(&mut self, port: u16, sequence: u32, path: u8, wire_bytes: usize, now_us: u64) {
        if !self.paths.contains_key(&path) {
            self.add_path(path, now_us);
        }
        let model = self.paths.get_mut(&path).expect("path inserted");
        model.sent(wire_bytes);
        let delivery = Delivery {
            path,
            generation: model.generation,
            wire_bytes,
            loss_counted: false,
            last_repair_us: None,
        };
        let key = (port, sequence);
        if self.pending.insert(key, delivery).is_none() {
            self.order.push_back(key);
            self.flow_order.entry(port).or_default().push_back(sequence);
        }
        let mut evicted = false;
        while self.pending.len() > MAX_PENDING {
            if let Some(key) = self.order.pop_front()
                && let Some(old) = self.pending.remove(&key)
            {
                evicted = true;
                if let Some(path) = self.paths.get_mut(&old.path)
                    && path.generation == old.generation
                {
                    path.in_flight = path.in_flight.saturating_sub(old.wire_bytes);
                }
            }
        }
        if evicted {
            self.clean_flow_fronts();
        }
        if self.order.len() > MAX_PENDING * 2 {
            self.order.retain(|key| self.pending.contains_key(key));
        }
        self.scheduled_packets = self.scheduled_packets.saturating_add(1);
    }

    pub fn acknowledge(&mut self, port: u16, ack: u32, now_us: u64) {
        if self
            .high_ack
            .get(&port)
            .is_some_and(|old| *old == ack || before(ack, *old))
        {
            return;
        }
        self.high_ack.insert(port, ack);
        let mut acknowledged = Vec::new();
        if let Some(order) = self.flow_order.get_mut(&port) {
            while order
                .front()
                .is_some_and(|sequence| *sequence == ack || before(*sequence, ack))
            {
                if let Some(sequence) = order.pop_front() {
                    acknowledged.push((port, sequence));
                }
            }
        }
        for key in acknowledged {
            let Some(delivery) = self.pending.remove(&key) else {
                continue;
            };
            if let Some(path) = self.paths.get_mut(&delivery.path)
                && path.generation == delivery.generation
            {
                path.delivered(delivery.wire_bytes, now_us);
                self.acknowledged_packets = self.acknowledged_packets.saturating_add(1);
            }
        }
        if self.flow_order.get(&port).is_some_and(VecDeque::is_empty) {
            self.flow_order.remove(&port);
        }
        while self
            .order
            .front()
            .is_some_and(|key| !self.pending.contains_key(key))
        {
            self.order.pop_front();
        }
    }

    pub fn nack(&mut self, port: u16, sequences: &[u32], now_us: u64) -> Vec<u32> {
        let mut repair = Vec::new();
        for sequence in sequences {
            let Some(delivery) = self.pending.get_mut(&(port, *sequence)) else {
                continue;
            };
            if delivery
                .last_repair_us
                .is_none_or(|last| now_us.saturating_sub(last) >= REPAIR_RETRY_US)
            {
                delivery.last_repair_us = Some(now_us);
                repair.push(*sequence);
            }
            if !delivery.loss_counted {
                delivery.loss_counted = true;
                if let Some(path) = self.paths.get_mut(&delivery.path)
                    && path.generation == delivery.generation
                {
                    path.nack(now_us);
                    self.nack_events = self.nack_events.saturating_add(1);
                }
            }
        }
        repair
    }

    pub fn repair_sent(
        &mut self,
        port: u16,
        sequence: u32,
        path: u8,
        wire_bytes: usize,
        now_us: u64,
    ) {
        let Some(previous) = self.pending.get(&(port, sequence)).cloned() else {
            return;
        };
        if let Some(model) = self.paths.get_mut(&previous.path)
            && model.generation == previous.generation
        {
            model.in_flight = model.in_flight.saturating_sub(previous.wire_bytes);
        }
        if !self.paths.contains_key(&path) {
            self.add_path(path, now_us);
        }
        let model = self.paths.get_mut(&path).expect("path inserted");
        model.sent(wire_bytes);
        let serialization = wire_bytes as f64 * 8_000_000.0 / model.capacity_bps;
        model.virtual_finish_us = model.virtual_finish_us.max(now_us as f64) + serialization;
        self.pending.insert(
            (port, sequence),
            Delivery {
                path,
                generation: model.generation,
                wire_bytes,
                loss_counted: previous.loss_counted,
                last_repair_us: previous.last_repair_us,
            },
        );
        self.repair_packets = self.repair_packets.saturating_add(1);
    }

    fn clean_flow_fronts(&mut self) {
        let ports: Vec<_> = self.flow_order.keys().copied().collect();
        for port in ports {
            if let Some(order) = self.flow_order.get_mut(&port) {
                while order
                    .front()
                    .is_some_and(|sequence| !self.pending.contains_key(&(port, *sequence)))
                {
                    order.pop_front();
                }
            }
            if self.flow_order.get(&port).is_some_and(VecDeque::is_empty) {
                self.flow_order.remove(&port);
            }
        }
    }

    pub fn status(&self) -> serde_json::Value {
        serde_json::json!({
            "scheduled_packets": self.scheduled_packets,
            "acknowledged_packets": self.acknowledged_packets,
            "nack_events": self.nack_events,
            "repair_packets": self.repair_packets,
            "pending_packets": self.pending.len(),
            "paths": self.paths.iter().map(|(id, p)| serde_json::json!({
                "id": id,
                "capacity_bps": p.capacity_bps,
                "confirmed_samples": p.confirmed_samples,
                "in_flight_bytes": p.in_flight,
                "sent_bytes": p.sent_bytes,
                "delivered_bytes": p.delivered_bytes,
                "nacks": p.nacks,
                "blocked_until_us": p.blocked_until_us
            })).collect::<Vec<_>>()
        })
    }

    #[cfg(test)]
    fn set_capacity(&mut self, id: u8, capacity_bps: f64) {
        self.add_path(id, 0);
        self.paths.get_mut(&id).unwrap().capacity_bps = capacity_bps;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn links(ids: &[u8]) -> Vec<Link> {
        ids.iter()
            .map(|id| Link {
                id: *id,
                status: 1,
                disabled: false,
                probed: true,
                rtt: 20.0,
                jitter: 0.0,
                variance: 0.0,
                loss: 0.0,
                capacity: 0.0,
                uptime: 1.0,
            })
            .collect()
    }

    #[test]
    fn fifteen_plus_five_is_scheduled_three_to_one_by_bytes() {
        let mut bond = BondedSpeed::default();
        bond.set_capacity(1, 15_000_000.0);
        bond.set_capacity(2, 5_000_000.0);
        let mut counts = BTreeMap::<u8, usize>::new();
        for _ in 0..4_000 {
            let path = bond.select(&links(&[1, 2]), 1_400, 0).unwrap();
            *counts.entry(path).or_default() += 1;
        }
        let fast_share = counts[&1] as f64 / 4_000.0;
        assert!((0.74..=0.76).contains(&fast_share), "share={fast_share}");
    }

    #[test]
    fn eighty_percent_target_fits_inside_fifteen_plus_five_megabit_paths() {
        let mut bond = BondedSpeed::default();
        bond.set_capacity(1, 15_000_000.0);
        bond.set_capacity(2, 5_000_000.0);
        let packet_bytes = 1_000;
        let packets_for_sixteen_mbps = 2_000;
        let mut bytes = BTreeMap::<u8, usize>::new();
        for _ in 0..packets_for_sixteen_mbps {
            let path = bond.select(&links(&[1, 2]), packet_bytes, 0).unwrap();
            *bytes.entry(path).or_default() += packet_bytes;
        }
        let fast_bps = bytes[&1] as u64 * 8;
        let slow_bps = bytes[&2] as u64 * 8;
        assert_eq!(fast_bps + slow_bps, 16_000_000);
        assert!(fast_bps <= 15_000_000, "fast allocation={fast_bps}");
        assert!(slow_bps <= 5_000_000, "slow allocation={slow_bps}");
    }

    #[test]
    fn failed_path_is_removed_immediately_and_rejoin_is_a_new_incarnation() {
        let mut bond = BondedSpeed::default();
        bond.set_capacity(1, 15_000_000.0);
        bond.set_capacity(2, 5_000_000.0);
        let first_generation = bond.paths[&2].generation;
        assert_eq!(bond.select(&links(&[1]), 1_400, 0), Some(1));
        bond.remove_path(2);
        bond.add_path(2, 1_000);
        assert!(bond.paths[&2].generation > first_generation);
        assert_eq!(bond.paths[&2].in_flight, 0);
    }

    #[test]
    fn cumulative_ack_credits_each_original_wan_once() {
        let mut bond = BondedSpeed::default();
        bond.add_path(1, 0);
        bond.add_path(2, 0);
        bond.sent(9, 0, 1, 1_000, 0);
        bond.sent(9, 1, 2, 1_000, 0);
        bond.acknowledge(9, 1, 300_000);
        bond.acknowledge(9, 1, 301_000);
        assert_eq!(bond.acknowledged_packets, 2);
        assert_eq!(bond.paths[&1].delivered_bytes, 1_000);
        assert_eq!(bond.paths[&2].delivered_bytes, 1_000);
        assert!(bond.pending.is_empty());
        assert!(bond.flow_order.is_empty());
    }

    #[test]
    fn duplicate_nacks_reduce_a_path_only_once() {
        let mut bond = BondedSpeed::default();
        bond.add_path(1, 0);
        bond.sent(9, 0, 1, 1_000, 0);
        assert_eq!(bond.nack(9, &[0], 1_000_000), [0]);
        let after_first = bond.paths[&1].capacity_bps;
        assert!(bond.nack(9, &[0], 1_001_000).is_empty());
        assert_eq!(bond.paths[&1].capacity_bps, after_first);
        assert_eq!(bond.nack_events, 1);
        assert_eq!(bond.nack(9, &[0], 1_020_000), [0]);
        assert_eq!(bond.nack_events, 1);
    }

    #[test]
    fn separate_losses_cannot_collapse_capacity_in_one_feedback_burst() {
        let mut bond = BondedSpeed::default();
        bond.add_path(1, 0);
        for sequence in 0..100 {
            bond.sent(9, sequence, 1, 1_000, 0);
        }
        bond.nack(9, &(0..100).collect::<Vec<_>>(), 1_000_000);
        assert_eq!(bond.paths[&1].capacity_bps, DEFAULT_CAPACITY_BPS * 0.85);
        assert_eq!(bond.paths[&1].nacks, 100);
        assert_eq!(bond.nack_events, 100);
    }

    #[test]
    fn repair_moves_delivery_accounting_and_service_charge_to_surviving_wan() {
        let mut bond = BondedSpeed::default();
        bond.add_path(1, 0);
        bond.add_path(2, 0);
        bond.sent(9, 0, 1, 1_000, 0);
        bond.repair_sent(9, 0, 2, 1_100, 100_000);
        assert_eq!(bond.paths[&1].in_flight, 0);
        assert_eq!(bond.paths[&2].in_flight, 1_100);
        assert_eq!(bond.paths[&2].sent_bytes, 1_100);
        bond.acknowledge(9, 0, 300_000);
        assert_eq!(bond.paths[&2].delivered_bytes, 1_100);
        assert_eq!(bond.repair_packets, 1);
    }

    #[test]
    fn loss_feedback_quarantines_only_the_suspect_wan_then_retries_it() {
        let mut bond = BondedSpeed::default();
        bond.add_path(1, 0);
        bond.add_path(2, 0);
        bond.sent(9, 0, 1, 1_000, 0);
        bond.nack(9, &[0], 100_000);
        for now in [100_000, 200_000, 349_999] {
            assert_eq!(bond.select(&links(&[1, 2]), 1_000, now), Some(2));
        }
        assert!(
            (0..100).any(|_| bond.select(&links(&[1, 2]), 1_000, 350_000) == Some(1)),
            "the quarantined WAN must receive a controlled trial after cooldown"
        );
    }

    #[test]
    fn higher_rtt_wan_keeps_its_capacity_share_after_pipeline_warmup() {
        let mut bond = BondedSpeed::default();
        bond.set_capacity(1, 10_000_000.0);
        bond.set_capacity(2, 10_000_000.0);
        let mut unequal = links(&[1, 2]);
        unequal[0].rtt = 10.0;
        unequal[1].rtt = 80.0;
        let mut counts = BTreeMap::<u8, usize>::new();
        for _ in 0..4_000 {
            let path = bond.select(&unequal, 1_400, 0).unwrap();
            *counts.entry(path).or_default() += 1;
        }
        let slow_share = counts[&2] as f64 / 4_000.0;
        assert!(
            (0.48..=0.50).contains(&slow_share),
            "slow share={slow_share}"
        );
    }

    #[test]
    fn ack_work_is_limited_to_its_flow_and_global_history_stays_bounded() {
        let mut bond = BondedSpeed::default();
        bond.add_path(1, 0);
        for sequence in 0..70_000u32 {
            let port = if sequence % 2 == 0 { 9 } else { 10 };
            bond.sent(port, sequence / 2, 1, 100, sequence as u64);
            bond.acknowledge(port, sequence / 2, sequence as u64 + 1);
        }
        assert!(bond.pending.is_empty());
        assert!(bond.flow_order.is_empty());
        assert!(bond.order.len() <= MAX_PENDING * 2);
        assert_eq!(bond.acknowledged_packets, 70_000);
    }

    #[test]
    fn delivered_goodput_learns_unequal_fifteen_and_five_megabit_paths() {
        let mut bond = BondedSpeed::default();
        bond.add_path(1, 0);
        bond.add_path(2, 0);
        // Both paths are offered enough traffic to expose their usable rates.
        // The receiver confirms 15 Mbps on path 1 and 5 Mbps on path 2.
        for window in 1..=12 {
            bond.paths.get_mut(&1).unwrap().sent(468_750);
            bond.paths
                .get_mut(&1)
                .unwrap()
                .delivered(468_750, window * SAMPLE_US);
            bond.paths.get_mut(&2).unwrap().sent(468_750);
            bond.paths
                .get_mut(&2)
                .unwrap()
                .delivered(156_250, window * SAMPLE_US);
        }
        let fast = bond.paths[&1].capacity_bps;
        let slow = bond.paths[&2].capacity_bps;
        assert!((14_000_000.0..=17_000_000.0).contains(&fast), "fast={fast}");
        assert!((5_000_000.0..=6_500_000.0).contains(&slow), "slow={slow}");
        assert!(
            (2.5..=3.2).contains(&(fast / slow)),
            "ratio={}",
            fast / slow
        );
    }
}
