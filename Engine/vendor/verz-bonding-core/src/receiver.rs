//! Receiving half: rebuild, release in order by deadline, report back.
//!
//! Send times come from the sender's clock. The receiver never compares them
//! with its own clock directly: it learns the smallest difference between the
//! two (clock offset plus the fastest link's one-way delay, neither needed on
//! its own) and places every send time on its own clock through that. A
//! deadline then counts from when the packet would have arrived at best, the
//! same for every link.

use crate::coding::{Decoder, RepairHeader};
use std::collections::{BTreeMap, VecDeque};

#[derive(Clone, Debug)]
pub struct ReceiverConfig {
    /// End-to-end budget from send to release.
    pub deadline_us: u64,
    pub report_interval_us: u64,
    /// Bytes per original for real decoding; 0 tracks decodability only.
    pub payload_len: usize,
}

impl Default for ReceiverConfig {
    fn default() -> Self {
        Self { deadline_us: 200_000, report_interval_us: 5_000, payload_len: 0 }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    /// Every original up to and including this one was released or abandoned.
    pub decoded_through: Option<u32>,
    /// Originals overdue on every link that can still meet their deadline.
    pub missing: Vec<u32>,
    /// Newest sender timestamp delivered on the link carrying this report.
    pub echo_us: u64,
    /// What arrived on every link. Links deliver in order, so the sender can
    /// tell exactly how many of the packets it sent up to `newest_sent` were
    /// lost, one round trip after the loss, without naming them.
    pub links: Vec<LinkCounts>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LinkCounts {
    pub id: u8,
    pub newest_sent: u64,
    /// Packets of any kind received on this link.
    pub packets: u64,
    /// Originals among them.
    pub originals: u64,
}

impl Report {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(14 + 4 * self.missing.len() + 25 * self.links.len());
        out.extend_from_slice(&self.decoded_through.unwrap_or(u32::MAX).to_be_bytes());
        out.extend_from_slice(&self.echo_us.to_be_bytes());
        out.push(self.missing.len().min(255) as u8);
        for seq in self.missing.iter().take(255) {
            out.extend_from_slice(&seq.to_be_bytes());
        }
        out.push(self.links.len().min(255) as u8);
        for l in self.links.iter().take(255) {
            out.push(l.id);
            out.extend_from_slice(&l.newest_sent.to_be_bytes());
            out.extend_from_slice(&l.packets.to_be_bytes());
            out.extend_from_slice(&l.originals.to_be_bytes());
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let mut at = 0;
        let mut take = |n: usize| {
            let slice = bytes.get(at..at + n)?;
            at += n;
            Some(slice)
        };
        let through = u32::from_be_bytes(take(4)?.try_into().ok()?);
        let echo_us = u64::from_be_bytes(take(8)?.try_into().ok()?);
        let n = usize::from(take(1)?[0]);
        let mut missing = Vec::with_capacity(n);
        for _ in 0..n {
            missing.push(u32::from_be_bytes(take(4)?.try_into().ok()?));
        }
        let n = usize::from(take(1)?[0]);
        let mut links = Vec::with_capacity(n);
        for _ in 0..n {
            links.push(LinkCounts {
                id: take(1)?[0],
                newest_sent: u64::from_be_bytes(take(8)?.try_into().ok()?),
                packets: u64::from_be_bytes(take(8)?.try_into().ok()?),
                originals: u64::from_be_bytes(take(8)?.try_into().ok()?),
            });
        }
        Some(Self {
            decoded_through: (through != u32::MAX).then_some(through),
            missing,
            echo_us,
            links,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Delivery {
    Released(u32),
    Abandoned(u32),
}

#[derive(Clone, Debug)]
struct RxLink {
    id: u8,
    newest_sent: u64,
    packets: u64,
    originals: u64,
    dirty: bool,
    last_rx: u64,
    owd: f64,
    dev: f64,
}

/// Smallest (receiver time − send time) seen over the last minute: how the
/// sender's clock maps onto ours, fastest link included.
#[derive(Debug, Default)]
struct Clock {
    minima: VecDeque<(u64, i64)>,
}

const CLOCK_WINDOW_US: u64 = 60_000_000;

impl Clock {
    fn observe(&mut self, now: u64, sent_us: u64) {
        let diff = now as i64 - sent_us as i64;
        while self.minima.back().is_some_and(|&(_, d)| d >= diff) {
            self.minima.pop_back();
        }
        self.minima.push_back((now, diff));
        while self.minima.front().is_some_and(|&(t, _)| now.saturating_sub(t) > CLOCK_WINDOW_US) {
            self.minima.pop_front();
        }
    }

    /// The send time on the receiver's clock.
    fn local(&self, sent_us: u64) -> u64 {
        let offset = self.minima.front().map_or(0, |&(_, d)| d);
        (sent_us as i64 + offset).max(0) as u64
    }
}

pub struct CodedReceiver {
    cfg: ReceiverConfig,
    decoder: Decoder,
    clock: Clock,
    next: u32,
    sent: BTreeMap<u32, u64>,
    highest: Option<u32>,
    links: Vec<RxLink>,
    /// Sequence and send time of the newest released original with a known
    /// send time, to estimate when a missing one was sent.
    last_sent: Option<(u32, u64)>,
    last_report: u64,
    out: Vec<Delivery>,
    pub rebuilt: u64,
    pub abandoned: u64,
}

const MAX_MISSING: usize = 64;
const MISSING_SCAN: u32 = 1_024;
/// Sequences further ahead than this are not believed.
const MAX_AHEAD: u32 = 4_096;

impl CodedReceiver {
    pub fn new(cfg: ReceiverConfig) -> Self {
        Self {
            decoder: Decoder::new(cfg.payload_len),
            cfg,
            clock: Clock::default(),
            next: 0,
            sent: BTreeMap::new(),
            highest: None,
            links: Vec::new(),
            last_sent: None,
            last_report: 0,
            out: Vec::new(),
            rebuilt: 0,
            abandoned: 0,
        }
    }

    /// The next original to release.
    pub fn next_seq(&self) -> u32 {
        self.next
    }

    pub fn memory_bytes(&self) -> usize {
        self.decoder.memory_bytes()
    }

    /// (next to release, highest seen, pending equations, their unknowns).
    pub fn debug(&self) -> (u32, Option<u32>, usize, Vec<u32>) {
        (self.next, self.highest, self.decoder.pending_equations(), self.decoder.unknowns())
    }

    pub fn on_source(&mut self, now: u64, link: u8, seq: u32, sent_us: u64, payload: &[u8]) {
        self.clock.observe(now, sent_us);
        let i = self.touch(now, link, sent_us);
        self.links[i].originals += 1;
        if self.highest.is_none() {
            // The stream may be joined mid-way: start from what is seen first.
            self.next = seq;
        }
        if seq < self.next || seq > self.next + MAX_AHEAD {
            return;
        }
        self.sent.insert(seq, sent_us);
        self.highest = Some(self.highest.map_or(seq, |h| h.max(seq)));
        let rebuilt = self.decoder.add_source(seq, payload);
        self.rebuilt += rebuilt.len() as u64;
        self.release(now);
    }

    pub fn on_repair(&mut self, now: u64, link: u8, header: RepairHeader, sent_us: u64, payload: &[u8]) {
        self.clock.observe(now, sent_us);
        let _ = self.touch(now, link, sent_us);
        if header.first > self.next + MAX_AHEAD {
            return;
        }
        self.highest = Some(self.highest.map_or(header.last(), |h| h.max(header.last())));
        let rebuilt = self.decoder.add_repair(header, payload);
        self.rebuilt += rebuilt.len() as u64;
        self.release(now);
    }

    /// A liveness probe arrived; it is echoed like data.
    pub fn on_probe(&mut self, now: u64, link: u8, sent_us: u64) {
        self.clock.observe(now, sent_us);
        let _ = self.touch(now, link, sent_us);
    }

    /// Deliveries since the last call, in order.
    pub fn drain(&mut self) -> Vec<Delivery> {
        std::mem::take(&mut self.out)
    }

    pub fn payload(&self, seq: u32) -> Option<&[u8]> {
        self.decoder.payload(seq)
    }

    /// Advance deadlines and produce feedback, one report per link.
    pub fn poll(&mut self, now: u64) -> Vec<(u8, Report)> {
        self.release(now);
        if now.saturating_sub(self.last_report) < self.cfg.report_interval_us {
            return Vec::new();
        }
        self.last_report = now;
        let missing = self.missing(now);
        let decoded_through = self.next.checked_sub(1);
        let counts: Vec<LinkCounts> = self
            .links
            .iter()
            .map(|l| LinkCounts { id: l.id, newest_sent: l.newest_sent, packets: l.packets, originals: l.originals })
            .collect();
        let mut reports = Vec::new();
        for link in &mut self.links {
            let recent = now.saturating_sub(link.last_rx) < 1_000_000;
            if link.dirty || (!missing.is_empty() && recent) {
                link.dirty = false;
                reports.push((
                    link.id,
                    Report {
                        decoded_through,
                        missing: missing.clone(),
                        echo_us: link.newest_sent,
                        links: counts.clone(),
                    },
                ));
            }
        }
        reports
    }

    fn touch(&mut self, now: u64, id: u8, sent_us: u64) -> usize {
        let sample = now.saturating_sub(self.clock.local(sent_us)) as f64;
        let i = match self.links.iter().position(|l| l.id == id) {
            Some(i) => i,
            None => {
                self.links.push(RxLink {
                    id,
                    newest_sent: 0,
                    packets: 0,
                    originals: 0,
                    dirty: false,
                    last_rx: now,
                    owd: sample,
                    dev: 0.0,
                });
                self.links.len() - 1
            }
        };
        let link = &mut self.links[i];
        link.newest_sent = link.newest_sent.max(sent_us);
        link.packets += 1;
        link.dirty = true;
        link.last_rx = now;
        link.dev = 0.75 * link.dev + 0.25 * (sample - link.owd).abs();
        link.owd = 0.875 * link.owd + 0.125 * sample;
        i
    }

    fn release(&mut self, now: u64) {
        loop {
            if self.decoder.is_known(self.next) {
                if let Some(&sent) = self.sent.get(&self.next) {
                    self.last_sent = Some((self.next, sent));
                }
                self.out.push(Delivery::Released(self.next));
                self.next += 1;
                continue;
            }
            // Hold a gap only until its own deadline, estimated between its
            // neighbours' send times. Waiting longer could not make it useful
            // and would delay everything behind it.
            let overdue = self.sent.range(self.next + 1..).next().is_some_and(|(&later, &at)| {
                let sent = match self.last_sent {
                    Some((seq, t)) if t <= at => t + (at - t) * u64::from(self.next - seq) / u64::from(later - seq),
                    _ => at,
                };
                now >= self.clock.local(sent) + self.cfg.deadline_us
            });
            if overdue {
                self.out.push(Delivery::Abandoned(self.next));
                self.abandoned += 1;
                self.next += 1;
                continue;
            }
            break;
        }
        self.decoder.forget_below(self.next);
        self.sent = self.sent.split_off(&self.next);
    }

    fn sent_estimate(&self, seq: u32) -> Option<u64> {
        let before = self.sent.range(..=seq).next_back();
        let after = self.sent.range(seq..).next();
        match (before, after) {
            (Some((&a, &ta)), Some((&b, &tb))) if b > a => {
                Some(ta + (tb - ta) * u64::from(seq - a) / u64::from(b - a))
            }
            (Some((_, &t)), _) | (_, Some((_, &t))) => Some(t),
            _ => None,
        }
    }

    fn missing(&self, now: u64) -> Vec<u32> {
        let Some(highest) = self.highest else {
            return Vec::new();
        };
        // An original is overdue once even the slowest active link should
        // have delivered it. A congested link must not hide every other
        // loss, and past half the deadline a repair could hardly arrive.
        let horizon = (self
            .links
            .iter()
            .filter(|l| now.saturating_sub(l.last_rx) < 1_000_000)
            .map(|l| l.owd + 4.0 * l.dev)
            .fold(0.0, f64::max) as u64
            + 2_000)
            .min(self.cfg.deadline_us / 2);
        let mut missing = Vec::new();
        let end = highest.min(self.next + MISSING_SCAN);
        for seq in self.next..end {
            if self.decoder.is_known(seq) {
                continue;
            }
            let Some(sent) = self.sent_estimate(seq) else {
                continue;
            };
            let sent = self.clock.local(sent);
            if now >= sent + horizon && now < sent + self.cfg.deadline_us {
                missing.push(seq);
                if missing.len() == MAX_MISSING {
                    break;
                }
            }
        }
        missing
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn releases_in_order_and_abandons_only_at_the_deadline() {
        let mut rx = CodedReceiver::new(ReceiverConfig { deadline_us: 100_000, ..Default::default() });
        // Sends at 0 and 2_000 arrive 10 ms later: the clock maps sender 0 to
        // receiver 10_000.
        rx.on_source(10_000, 1, 0, 0, &[]);
        rx.on_source(12_000, 1, 2, 2_000, &[]);
        assert_eq!(rx.drain(), vec![Delivery::Released(0)]);
        // 1 was sent between 0 (at 0) and 2 (at 2_000), so around 1_000,
        // which is 11_000 here.
        rx.poll(110_999);
        assert!(rx.drain().is_empty());
        rx.poll(111_000);
        assert_eq!(rx.drain(), vec![Delivery::Abandoned(1), Delivery::Released(2)]);
    }

    #[test]
    fn a_sender_clock_an_hour_ahead_changes_nothing() {
        let hour = 3_600_000_000_u64;
        let mut rx = CodedReceiver::new(ReceiverConfig { deadline_us: 100_000, ..Default::default() });
        rx.on_source(10_000, 1, 0, hour, &[]);
        rx.on_source(12_000, 1, 2, hour + 2_000, &[]);
        rx.poll(110_999);
        assert_eq!(rx.drain(), vec![Delivery::Released(0)]);
        rx.poll(111_000);
        assert_eq!(rx.drain(), vec![Delivery::Abandoned(1), Delivery::Released(2)]);
    }

    #[test]
    fn a_repair_fills_the_gap_before_the_deadline() {
        let mut rx = CodedReceiver::new(ReceiverConfig::default());
        rx.on_source(10_000, 1, 0, 0, &[]);
        rx.on_source(11_000, 1, 2, 1_000, &[]);
        rx.on_repair(30_000, 2, RepairHeader { first: 0, count: 3, seed: 1 }, 20_000, &[]);
        assert_eq!(
            rx.drain(),
            vec![Delivery::Released(0), Delivery::Released(1), Delivery::Released(2)]
        );
    }

    #[test]
    fn reports_overdue_originals_on_each_active_link() {
        let mut rx = CodedReceiver::new(ReceiverConfig::default());
        for (t, link, seq) in [(10_000, 1, 0), (11_000, 2, 1), (40_000, 1, 3)] {
            rx.on_source(t, link, seq, t - 10_000, &[]);
        }
        let reports = rx.poll(80_000);
        assert_eq!(reports.len(), 2);
        assert!(reports.iter().all(|(_, r)| r.missing == vec![2]));
    }

    #[test]
    fn every_report_counts_what_arrived_on_every_link() {
        let mut rx = CodedReceiver::new(ReceiverConfig::default());
        rx.on_source(10_000, 1, 0, 0, &[]);
        rx.on_probe(11_000, 1, 1_000);
        rx.on_source(12_000, 2, 1, 2_000, &[]);
        let reports = rx.poll(20_000);
        let expected = vec![
            LinkCounts { id: 1, newest_sent: 1_000, packets: 2, originals: 1 },
            LinkCounts { id: 2, newest_sent: 2_000, packets: 1, originals: 1 },
        ];
        assert!(reports.iter().all(|(_, r)| r.links == expected));
    }

    #[test]
    fn reports_survive_the_wire() {
        let report = Report {
            decoded_through: Some(41),
            missing: vec![42, 45],
            echo_us: 1_234_567_890,
            links: vec![
                LinkCounts { id: 1, newest_sent: 99, packets: 1_000, originals: 900 },
                LinkCounts { id: 7, newest_sent: 98, packets: 500, originals: 500 },
            ],
        };
        assert_eq!(Report::decode(&report.encode()), Some(report.clone()));
        let none = Report { decoded_through: None, ..report };
        assert_eq!(Report::decode(&none.encode()), Some(none.clone()));
        assert_eq!(Report::decode(&none.encode()[..20]), None);
    }

    #[test]
    fn a_stream_joined_mid_way_starts_from_the_first_sequence_seen() {
        let mut rx = CodedReceiver::new(ReceiverConfig::default());
        rx.on_source(10_000, 1, 70_000, 0, &[]);
        rx.on_source(11_000, 1, 70_001, 1_000, &[]);
        assert_eq!(rx.drain(), vec![Delivery::Released(70_000), Delivery::Released(70_001)]);
    }

    #[test]
    fn sequences_far_ahead_are_not_believed() {
        let mut rx = CodedReceiver::new(ReceiverConfig::default());
        rx.on_source(10_000, 1, 0, 0, &[]);
        rx.on_source(11_000, 1, 1_000_000, 1_000, &[]);
        assert_eq!(rx.drain(), vec![Delivery::Released(0)]);
        rx.poll(1_000_000);
        assert!(rx.drain().is_empty(), "a bogus sequence must not abandon everything before it");
    }
}
