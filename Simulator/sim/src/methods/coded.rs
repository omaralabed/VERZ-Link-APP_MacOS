//! The experimental coded method from `verz-bonding-core`.
//!
//! Originals are placed by the shipped Bonded Speed scheduler, so any
//! difference from Split comes from the new layer alone: failure detection
//! from feedback rhythm, and repair packets instead of copies or resends.

use super::{Log, Method, WIRE};
use crate::bonded::BondedSpeed;
use crate::link::LinkSpec;
use crate::net::{Kind, Net};
use verz_bonding_core::coding::RepairHeader;
use verz_bonding_core::receiver::{CodedReceiver, Delivery, ReceiverConfig, Report};
use verz_bonding_core::sender::{CodedSender, LinkInput, LinkState, RepairKind, SenderConfig};
use verz_link_core::scheduler::Link;

const PORT: u16 = 5_000;
/// Repair header: first sequence, count and seed.
const REPAIR_WIRE: usize = WIRE + 10;
const PROBE_WIRE: usize = verz_link_core::HEADER + verz_link_core::TAG;
const PROBE_IDLE_US: u64 = 50_000;
/// Capacity assumed until the scheduler has measured more. Real capacity
/// probing per link is still to be built; see the README.
const ASSUMED_CAPACITY_BPS: f64 = 10e6;

pub enum Up {
    Source { seq: u32, sent_us: u64 },
    Repair { header: RepairHeader, sent_us: u64 },
    Probe { sent_us: u64 },
}

pub type Down = Report;

struct TxLink {
    upstream: u32,
    cost: f64,
    rtt_ms: f64,
    jitter_ms: f64,
    last_sent: u64,
}

pub struct Coded {
    sender: CodedSender,
    placer: BondedSpeed,
    tx: Vec<TxLink>,
    receiver: CodedReceiver,
    /// Every repair sent: (time, link, first, last, kind), for stories.
    repairs: Vec<(u64, u8, u32, u32, RepairKind)>,
}

impl Coded {
    pub fn new(specs: &[LinkSpec], deadline_us: u64, protect_always: bool) -> Self {
        Self {
            sender: CodedSender::new(SenderConfig { deadline_us, protect_always, ..Default::default() }),
            placer: BondedSpeed::default(),
            tx: specs
                .iter()
                .map(|s| TxLink {
                    upstream: s.upstream,
                    cost: if s.metered { 5.0 } else { 1.0 },
                    rtt_ms: 0.0,
                    jitter_ms: 0.0,
                    last_sent: 0,
                })
                .collect(),
            receiver: CodedReceiver::new(ReceiverConfig { deadline_us, ..Default::default() }),
            repairs: Vec::new(),
        }
    }

    fn inputs(&self, now: u64, net: &Net<Up, Down>) -> Vec<LinkInput> {
        self.tx
            .iter()
            .enumerate()
            .map(|(i, tx)| {
                let id = i as u8 + 1;
                LinkInput {
                    id,
                    carrier: net.carrier(i, now),
                    upstream: Some(tx.upstream),
                    cost: tx.cost,
                    // The scheduler's estimate follows what it was offered, not
                    // what the link can carry, so it is only a lower bound.
                    capacity_bps: self.placer.capacity_bps(id).unwrap_or(0.0).max(ASSUMED_CAPACITY_BPS),
                    rtt_us: tx.rtt_ms * 1_000.0,
                    loss: 0.0,
                }
            })
            .collect()
    }

    /// The scheduler sees only links the detector trusts. If none are
    /// trusted, suspect links are better than nothing.
    fn placer_links(&self, now: u64, net: &Net<Up, Down>) -> Vec<Link> {
        let state = |i: usize| {
            if net.carrier(i, now) {
                self.sender.state(i as u8 + 1, now)
            } else {
                LinkState::Dead
            }
        };
        // Only the best tier present is offered: healthy links, else slow
        // ones (they deliver, late), else suspect ones, else links the
        // detector has given up on but that still have a carrier: sending
        // there costs nothing and the detector can be wrong.
        let tier = |i: usize| match state(i) {
            LinkState::Healthy => 0,
            LinkState::Slow => 1,
            LinkState::Suspect => 2,
            LinkState::Dead if net.carrier(i, now) => 3,
            LinkState::Dead => 4,
        };
        let best = (0..self.tx.len()).map(tier).min().unwrap_or(4);
        let status = self.sender.status(now);
        self.tx
            .iter()
            .enumerate()
            .map(|(i, tx)| {
                let id = i as u8 + 1;
                let view = status.iter().find(|s| s.id == id);
                let loss = view.map_or(0.0, |s| s.loss);
                // Bonded Speed aligns arrivals using half the RTT. Giving it
                // twice the predicted one-way delay makes a building queue
                // steer new packets away before anything is lost.
                let rtt = view.map_or(tx.rtt_ms, |s| 2.0 * s.predicted_owd_us / 1_000.0);
                let usable = best < 4 && tier(i) == best;
                Link {
                    id,
                    status: u8::from(usable),
                    disabled: false,
                    probed: tx.rtt_ms > 0.0,
                    rtt,
                    jitter: tx.jitter_ms,
                    variance: 0.0,
                    loss: loss * 100.0,
                    capacity: self.placer.capacity_bps(id).unwrap_or(0.0),
                    uptime: 1.0,
                }
            })
            .collect()
    }

    fn deliver(&mut self, now: u64, log: &mut Log) {
        for delivery in self.receiver.drain() {
            if let Delivery::Released(seq) = delivery {
                log.released(seq, now);
            }
        }
    }
}

impl Method for Coded {
    type Up = Up;
    type Down = Down;

    fn source(&mut self, now: u64, seq: u32, net: &mut Net<Up, Down>, log: &mut Log) {
        let mut links = self.placer_links(now, net);
        let bits = WIRE as f64 * 8.0;
        let mut first = None;
        let id = loop {
            let Some(id) = self.placer.select(&links, WIRE, now) else {
                // Every link is over its allowance: the first choice it is.
                break first;
            };
            if self.sender.admit_original(now, id, bits) {
                break Some(id);
            }
            first.get_or_insert(id);
            links.iter_mut().filter(|l| l.id == id).for_each(|l| l.status = 0);
        };
        let Some(id) = id else {
            return;
        };
        let link = usize::from(id) - 1;
        log.sent_on(seq, id);
        let sent_us = self.sender.on_source_sent(now, seq, id);
        net.up(now, link, WIRE, Kind::Original, Up::Source { seq, sent_us });
        self.placer.sent(PORT, seq, id, WIRE, now);
        self.tx[link].last_sent = now;
    }

    fn at_server(&mut self, now: u64, link: usize, msg: Up, _net: &mut Net<Up, Down>, log: &mut Log) {
        let id = link as u8 + 1;
        match msg {
            Up::Source { seq, sent_us } => {
                log.arrived(seq, now);
                self.receiver.on_source(now, id, seq, sent_us, &[]);
            }
            Up::Repair { header, sent_us } => self.receiver.on_repair(now, id, header, sent_us, &[]),
            Up::Probe { sent_us } => self.receiver.on_probe(now, id, sent_us),
        }
        self.deliver(now, log);
    }

    fn at_client(&mut self, now: u64, link: usize, report: Report, _net: &mut Net<Up, Down>) {
        let id = link as u8 + 1;
        self.sender.on_feedback(now, id, &report);
        let tx = &mut self.tx[link];
        let rtt = now.saturating_sub(report.echo_us) as f64 / 1_000.0;
        if tx.rtt_ms > 0.0 {
            tx.jitter_ms = 0.8 * tx.jitter_ms + 0.2 * (rtt - tx.rtt_ms).abs();
            tx.rtt_ms = 0.875 * tx.rtt_ms + 0.125 * rtt;
        } else {
            tx.rtt_ms = rtt;
        }
        if let Some(through) = report.decoded_through {
            self.placer.acknowledge(PORT, through, now);
        }
        if !report.missing.is_empty() {
            // Teaches the scheduler which path lost them; the repair itself
            // comes from the coded sender, not a resend.
            let _ = self.placer.nack(PORT, &report.missing, now);
        }
    }

    fn notes(&self) -> String {
        let s = &self.sender.stats;
        format!(
            "repairs proactive={} speculative={} reactive={}, rebuilt={}, slow episodes={:?}",
            s.proactive,
            s.speculative,
            s.reactive,
            self.receiver.rebuilt,
            self.sender.status(0).iter().map(|l| l.slow_episodes).collect::<Vec<_>>()
        )
    }

    fn between(&self, from_us: u64, to_us: u64) -> Vec<String> {
        let mut lines: Vec<(u64, String)> = self
            .sender
            .stats
            .covers
            .iter()
            .filter(|&&(t, ..)| from_us <= t && t <= to_us)
            .map(|&(t, link, first, wanted, sent)| {
                (t, format!("{:.3}s cover for L{link} from seq {first}: wanted {wanted}, sent {sent}", t as f64 / 1e6))
            })
            .collect();
        lines.extend(
            self.repairs
                .iter()
                .filter(|&&(t, ..)| from_us <= t && t <= to_us)
                .map(|&(t, link, first, last, kind)| {
                    (t, format!("{:.3}s {kind:?} repair on L{link} covering {first}..{last}", t as f64 / 1e6))
                }),
        );
        lines.sort_by_key(|(t, _)| *t);
        lines.into_iter().map(|(_, l)| l).collect()
    }

    fn story(&self, seq: u32) -> Vec<String> {
        self.repairs
            .iter()
            .filter(|&&(_, _, first, last, _)| first <= seq && seq <= last)
            .map(|&(t, link, first, last, kind)| {
                format!("{:.3}s {kind:?} repair on L{link} covering {first}..{last}", t as f64 / 1e6)
            })
            .collect()
    }

    fn trace(&self, now: u64) -> String {
        self.sender
            .status(now)
            .iter()
            .map(|l| {
                format!(
                    "L{} {:?}{} p={:.2} orig={:.0}/s rep={:.0}/s echo={}ms queue={}ms cap={} loss={:.1}%",
                    l.id,
                    l.state,
                    if l.congested { "(queue)" } else { "" },
                    l.p_dead,
                    l.placed_pps,
                    l.repair_pps,
                    l.median_echo_us.map_or(0, |e| e / 1_000),
                    l.queue_us / 1_000,
                    l.measured_capacity_bps.map_or("-".to_owned(), |c| format!("{:.1}M", c / 1e6)),
                    l.loss * 100.0
                )
            })
            .collect::<Vec<_>>()
            .join(" | ")
    }

    fn tick(&mut self, now: u64, net: &mut Net<Up, Down>, log: &mut Log) {
        // Client.
        let inputs = self.inputs(now, net);
        self.sender.update_links(now, &inputs);
        for link in 0..self.tx.len() {
            if now.saturating_sub(self.tx[link].last_sent) >= PROBE_IDLE_US && net.carrier(link, now) {
                let sent_us = self.sender.on_other_sent(now, link as u8 + 1);
                net.up(now, link, PROBE_WIRE, Kind::Probe, Up::Probe { sent_us });
                self.tx[link].last_sent = now;
            }
        }
        for order in self.sender.poll(now) {
            let link = usize::from(order.link) - 1;
            if net.carrier(link, now) {
                let sent_us = self.sender.on_other_sent(now, order.link);
                net.up(now, link, REPAIR_WIRE, Kind::Protection, Up::Repair { header: order.header, sent_us });
                self.tx[link].last_sent = now;
                self.repairs.push((now, order.link, order.header.first, order.header.last(), order.kind));
            }
        }
        // Server.
        let reports = self.receiver.poll(now);
        self.deliver(now, log);
        for (id, report) in reports {
            let link = usize::from(id) - 1;
            let bytes = verz_link_core::HEADER + verz_link_core::TAG + 14 + 4 * report.missing.len() + 17 * report.links.len();
            net.down(now, link, bytes, report);
        }
    }
}
