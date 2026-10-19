//! Single-owner engine, called only from the provider's serial queue. No TUN or route changes.
mod bonded;
mod coded;
mod gateway;
#[cfg(test)]
mod native_test;
mod reassembly;
pub mod secure;
mod wan;
use bonded::BondedSpeed;
use coded::{BLOCK, CODED_CLASS, MAX_PIECE, MORE, pack, report_of};
use secure::SecureSockets as Sockets;
use serde::Deserialize;
use std::{
    collections::{BTreeMap, VecDeque},
    net::{Ipv4Addr, SocketAddr},
    time::{Instant, SystemTime, UNIX_EPOCH},
};
use verz_bonding_core::{
    coding,
    sender::{CodedSender, LinkInput, LinkState, RepairOrder, SenderConfig},
};
use verz_link_core::{
    ACK, DOWNLINK, FEC, HEARTBEAT, NACK, Packet, decode_nack, encode_nack,
    recovery::Deduper,
    scheduler::{Config, Link},
    transport::{Sender, WanWriter},
};

const MODE_BONDED_SPEED: i32 = 1;
const MODE_CONTINUITY: i32 = 2;
const MODE_DATA_SAVER: i32 = 3;
const MODE_ADAPTIVE_PROTECTION: i32 = 4;
/// "Smart": repair packets instead of copies (`coded.rs`, `verz-bonding-core`).
/// Behaves as Continuity until the gateway announces support.
const MODE_CODED: i32 = 5;
const ADAPTIVE_CLASS: u16 = 5;
/// A coded link that carried nothing this long gets a probe, so its rhythm
/// stays observable.
const CODED_PROBE_IDLE_US: u64 = 50_000;
const CODED_FLOW_IDLE_US: u64 = 60_000_000;
/// Recent coded blocks kept per flow for building repairs.
const CODED_BLOCKS_KEPT: usize = 512;
/// Repairs leave at most this many per tick: a cover for a dead link can be
/// a hundred packets, and the host refuses sends during such a burst.
const CODED_REPAIRS_PER_TICK: usize = 32;
const CODED_REPAIR_QUEUE: usize = 1_024;

#[derive(Deserialize)]
struct Enrollment {
    gateway: SocketAddr,
    session: u32,
    key: String,
}
#[derive(Deserialize, Clone, PartialEq)]
struct Adapter {
    id: u8,
    name: String,
    address: Ipv4Addr,
}
struct Path {
    adapter: Adapter,
    last_reply: Option<Instant>,
    probes: BTreeMap<u32, Instant>,
    rtt: f64,
    jitter: f64,
    outcomes: VecDeque<bool>,
}
/// One Smart-mode stream (a local port): its own sequence space, repair
/// window and view of the links.
struct CodedFlow {
    sender: CodedSender,
    next_seq: u32,
    /// Coded blocks of recent originals, by sequence, for building repairs.
    blocks: BTreeMap<u32, Vec<u8>>,
    last_sent: BTreeMap<u8, u64>,
    last_original: u64,
    /// Repairs ordered but not yet on the wire.
    pending: VecDeque<RepairOrder>,
}
impl CodedFlow {
    fn new(now: u64) -> Self {
        Self {
            sender: CodedSender::new(SenderConfig::default()),
            next_seq: 0,
            blocks: BTreeMap::new(),
            last_sent: BTreeMap::new(),
            last_original: now,
            pending: VecDeque::new(),
        }
    }
}
#[derive(Default, serde::Serialize)]
struct CodedStats {
    originals: u64,
    repairs: u64,
    probes: u64,
    reports: u64,
    /// Repairs ordered for blocks no longer kept.
    unbuildable: u64,
    /// Repairs sent, per link.
    repairs_by_link: BTreeMap<u8, u64>,
}
pub struct Engine {
    enrollment: Enrollment,
    sender: Sender,
    sockets: Sockets,
    paths: BTreeMap<u8, Path>,
    dedup: Deduper,
    received: VecDeque<Packet>,
    start: Instant,
    heartbeat: Instant,
    probe: u32,
    pub upload: u64,
    pub download: u64,
    pub errors: u64,
    mode: i32,
    bonded: BondedSpeed,
    adaptive_supported: bool,
    adaptive_hold_us: u64,
    coded_supported: bool,
    coded_flows: BTreeMap<u16, CodedFlow>,
    coded_stats: CodedStats,
    /// Wall clock at start: coded send stamps are offset by it so a restarted
    /// engine's stamps are newer than the old one's.
    epoch_wall: i64,
}
fn stamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros() as i64
}
impl Engine {
    fn new(e: Enrollment) -> Result<Self, String> {
        if !e.gateway.is_ipv4() {
            return Err("IPv4 gateway required".into());
        }
        let sender = Sender::new(e.session, e.key.as_bytes().to_vec(), Config::default())
            .map_err(|e| e.to_string())?;
        let sockets = Sockets::new(&e.key, e.session).map_err(|e| e.to_string())?;
        Ok(Self {
            enrollment: e,
            sender,
            sockets,
            paths: BTreeMap::new(),
            dedup: Deduper::new(16384, 10_000_000),
            received: VecDeque::new(),
            start: Instant::now(),
            heartbeat: Instant::now() - std::time::Duration::from_secs(1),
            probe: 0,
            upload: 0,
            download: 0,
            errors: 0,
            mode: 0,
            bonded: BondedSpeed::default(),
            adaptive_supported: false,
            adaptive_hold_us: 0,
            coded_supported: false,
            coded_flows: BTreeMap::new(),
            coded_stats: CodedStats::default(),
            epoch_wall: stamp(),
        })
    }
    fn now_us(&self) -> u64 {
        self.start.elapsed().as_micros() as u64
    }
    fn coded_inputs(&self) -> Vec<LinkInput> {
        self.paths
            .iter()
            .map(|(&id, p)| LinkInput {
                id,
                carrier: self.sockets.carrier(id),
                upstream: None,
                cost: 1.0,
                // The scheduler's estimate follows what it was offered, so it
                // is only a lower bound.
                capacity_bps: self.bonded.capacity_bps(id).unwrap_or(0.0).max(10e6),
                rtt_us: p.rtt * 1_000.0,
                loss: 0.0,
            })
            .collect()
    }
    /// Links as the Bonded Speed placer should see them for a Smart flow:
    /// only the best tier is offered (healthy, else slow, else suspect, else
    /// anything with a carrier), each with its predicted delay.
    fn coded_links(
        paths: &BTreeMap<u8, Path>,
        sockets: &Sockets,
        bonded: &BondedSpeed,
        sender: &CodedSender,
        now: u64,
    ) -> Vec<Link> {
        let status = sender.status(now);
        let tier = |id: u8| match sender.state(id, now) {
            LinkState::Healthy => 0,
            LinkState::Slow => 1,
            LinkState::Suspect => 2,
            LinkState::Dead if sockets.carrier(id) => 3,
            LinkState::Dead => 4,
        };
        let best = paths.keys().map(|&id| tier(id)).min().unwrap_or(4);
        paths
            .iter()
            .map(|(&id, p)| {
                let view = status.iter().find(|s| s.id == id);
                Link {
                    id,
                    status: u8::from(best < 4 && tier(id) == best),
                    disabled: false,
                    probed: p.last_reply.is_some(),
                    // Twice the predicted one-way delay: a building queue
                    // steers new packets away before anything is late.
                    rtt: view.map_or(p.rtt, |s| 2.0 * s.predicted_owd_us / 1_000.0),
                    jitter: p.jitter,
                    variance: 0.0,
                    loss: view.map_or(0.0, |s| s.loss * 100.0),
                    capacity: bonded.capacity_bps(id).unwrap_or(0.0),
                    uptime: 1.0,
                }
            })
            .collect()
    }
    fn send_coded(&mut self, port: u16, ip: [u8; 4], remote: u16, payload: &[u8]) -> Result<(), String> {
        let now = self.now_us();
        let inputs = self.coded_inputs();
        let session = self.enrollment.session;
        let epoch = self.epoch_wall;
        let flow = self.coded_flows.entry(port).or_insert_with(|| CodedFlow::new(now));
        flow.sender.update_links(now, &inputs);
        let pieces = payload.chunks(MAX_PIECE).count().max(1);
        for i in 0..pieces {
            let piece = payload.chunks(MAX_PIECE).nth(i).unwrap_or(&[]);
            let wire_bytes = piece.len() + verz_link_core::HEADER + verz_link_core::TAG;
            let mut links = Self::coded_links(&self.paths, &self.sockets, &self.bonded, &flow.sender, now);
            let mut first = None;
            let chosen = loop {
                let Some(id) = self.bonded.select(&links, wire_bytes, now) else {
                    // Every link is over its allowance: the first choice it is.
                    break first;
                };
                if flow.sender.admit_original(now, id, wire_bytes as f64 * 8.0) {
                    break Some(id);
                }
                first.get_or_insert(id);
                links.iter_mut().filter(|l| l.id == id).for_each(|l| l.status = 0);
            };
            let Some(link) = chosen else {
                self.errors += 1;
                return Err("no healthy WAN for Smart mode".into());
            };
            let seq = flow.next_seq;
            flow.next_seq = flow.next_seq.wrapping_add(1);
            let sent = flow.sender.on_source_sent(now, seq, link);
            let packet = Packet {
                flags: if i + 1 < pieces { MORE } else { 0 },
                class: CODED_CLASS,
                session,
                sequence: seq,
                timestamp_us: epoch + sent as i64,
                link,
                destination: ip,
                destination_port: remote,
                local_port: port,
                payload: piece.to_vec(),
                ..Default::default()
            };
            let wire = packet.encode(self.enrollment.key.as_bytes()).map_err(|e| e.to_string())?;
            // A failed send is a loss the feedback will reveal; the stream goes on.
            if self.sockets.send(link, &wire).is_err() {
                self.errors += 1;
            }
            self.bonded.sent(port, seq, link, wire.len(), now);
            flow.last_sent.insert(link, now);
            flow.last_original = now;
            flow.blocks.insert(seq, pack(&packet).expect("a piece fits a block"));
            while flow.blocks.len() > CODED_BLOCKS_KEPT {
                flow.blocks.pop_first();
            }
            self.coded_stats.originals += 1;
        }
        self.upload += payload.len() as u64;
        Ok(())
    }
    /// Smart-mode housekeeping each tick: link views, probes on idle links,
    /// and the repairs the core asks for.
    fn tick_coded(&mut self) {
        if self.mode != MODE_CODED || !self.coded_supported || self.coded_flows.is_empty() {
            return;
        }
        let now = self.now_us();
        let inputs = self.coded_inputs();
        let session = self.enrollment.session;
        let epoch = self.epoch_wall;
        let ports: Vec<u16> = self.coded_flows.keys().copied().collect();
        for port in ports {
            if self.coded_flows[&port].last_original + CODED_FLOW_IDLE_US < now {
                self.coded_flows.remove(&port);
                continue;
            }
            let flow = self.coded_flows.get_mut(&port).expect("listed");
            flow.sender.update_links(now, &inputs);
            for &id in self.paths.keys() {
                let idle = now.saturating_sub(flow.last_sent.get(&id).copied().unwrap_or(0));
                if idle < CODED_PROBE_IDLE_US || !self.sockets.carrier(id) {
                    continue;
                }
                let sent = flow.sender.on_other_sent(now, id);
                let probe = Packet {
                    flags: FEC | MORE,
                    class: CODED_CLASS,
                    session,
                    timestamp_us: epoch + sent as i64,
                    link: id,
                    local_port: port,
                    ..Default::default()
                };
                if let Ok(wire) = probe.encode(self.enrollment.key.as_bytes())
                    && self.sockets.send(id, &wire).is_ok()
                {
                    flow.last_sent.insert(id, now);
                    self.coded_stats.probes += 1;
                }
            }
            flow.pending.extend(flow.sender.poll(now));
            while flow.pending.len() > CODED_REPAIR_QUEUE {
                flow.pending.pop_front();
            }
            let mut budget = CODED_REPAIRS_PER_TICK;
            while budget > 0
                && let Some(order) = flow.pending.pop_front()
            {
                let header = order.header;
                if (header.first..=header.last()).any(|seq| !flow.blocks.contains_key(&seq)) {
                    self.coded_stats.unbuildable += 1;
                    continue;
                }
                let mut payload = header.to_bytes().to_vec();
                payload.extend(coding::encode(header, |seq| flow.blocks[&seq].as_slice(), BLOCK));
                let mut repair = Packet {
                    flags: FEC,
                    class: CODED_CLASS,
                    session,
                    sequence: header.first,
                    link: order.link,
                    local_port: port,
                    payload,
                    ..Default::default()
                };
                // Stamp only what actually leaves; a refused send waits for
                // the next tick rather than counting as a loss.
                repair.timestamp_us = epoch + flow.sender.on_other_sent(now, order.link) as i64;
                let Ok(wire) = repair.encode(self.enrollment.key.as_bytes()) else {
                    continue;
                };
                match self.sockets.send(order.link, &wire) {
                    Ok(()) => {
                        flow.last_sent.insert(order.link, now);
                        self.coded_stats.repairs += 1;
                        *self.coded_stats.repairs_by_link.entry(order.link).or_default() += 1;
                        budget -= 1;
                    }
                    Err(_) => {
                        self.errors += 1;
                        flow.pending.push_front(order);
                        break;
                    }
                }
            }
        }
    }
    fn adapters(&mut self, adapters: Vec<Adapter>) -> Result<(), String> {
        let mut ids = std::collections::HashSet::new();
        if adapters.iter().any(|a| a.id == 0 || !ids.insert(a.id)) {
            return Err("invalid link IDs".into());
        }
        let removed: Vec<_> = self
            .paths
            .iter()
            .filter(|(_, p)| !adapters.contains(&p.adapter))
            .map(|(&id, _)| id)
            .collect();
        for id in removed {
            self.sockets.remove(id);
            self.paths.remove(&id);
            self.bonded.remove_path(id);
        }
        let mut failures = Vec::new();
        for a in adapters {
            if self.paths.contains_key(&a.id) {
                continue;
            }
            match self
                .sockets
                .add(a.id, &a.name, a.address, self.enrollment.gateway)
            {
                Ok(()) => {
                    self.bonded
                        .add_path(a.id, self.start.elapsed().as_micros() as u64);
                    self.paths.insert(
                        a.id,
                        Path {
                            adapter: a,
                            last_reply: None,
                            probes: BTreeMap::new(),
                            rtt: 0.0,
                            jitter: 0.0,
                            outcomes: VecDeque::new(),
                        },
                    );
                }
                Err(e) => failures.push(e.to_string()),
            }
        }
        self.heartbeat = Instant::now() - std::time::Duration::from_secs(1);
        if failures.is_empty() {
            Ok(())
        } else {
            Err(failures.join("; "))
        }
    }
    fn links(&self) -> Vec<Link> {
        self.paths
            .iter()
            .map(|(&id, p)| Link {
                id,
                status: if p.last_reply.is_some_and(|t| t.elapsed().as_millis() < 1000) {
                    1
                } else {
                    0
                },
                disabled: false,
                probed: p.last_reply.is_some(),
                rtt: p.rtt,
                jitter: p.jitter,
                variance: 0.0,
                loss: if p.outcomes.is_empty() {
                    0.0
                } else {
                    100.0 * p.outcomes.iter().filter(|v| !**v).count() as f64
                        / p.outcomes.len() as f64
                },
                capacity: if self.mode == MODE_BONDED_SPEED {
                    self.bonded.capacity_bps(id).unwrap_or(0.0)
                } else {
                    0.0
                },
                uptime: 1.0,
            })
            .collect()
    }
    fn send(&mut self, port: u16, ip: [u8; 4], remote: u16, payload: &[u8]) -> Result<(), String> {
        // DNS is a request and a reply, not a stream: it takes the proven
        // Continuity path, so lookups never wait behind stream sequencing.
        if self.mode == MODE_CODED && self.coded_supported && remote != 53 {
            return self.send_coded(port, ip, remote, payload);
        }
        // An older gateway does not understand class 5. Until the authenticated
        // heartbeat advertises support, requested Adaptive Protection safely
        // behaves as the existing Continuity mode and emits only class 4.
        let adaptive = self.mode == MODE_ADAPTIVE_PROTECTION && self.adaptive_supported;
        let p = Packet {
            // Class 3 is reserved here for capacity-weighted Bonded Speed.
            // Existing continuity/latency behavior remains class 4.
            class: if self.mode == MODE_BONDED_SPEED {
                3
            } else if adaptive {
                ADAPTIVE_CLASS
            } else {
                4
            },
            local_port: port,
            destination: ip,
            destination_port: remote,
            // The gateway uses only within-stream timestamp differences for
            // adaptive playout; clocks do not need to be synchronized. Keeping
            // the established timestamp also preserves restart detection.
            timestamp_us: stamp(),
            payload: payload.to_vec(),
            ..Default::default()
        };
        let links = self.links();
        let (result, bonded_send) = if self.mode == MODE_BONDED_SPEED {
            let now_us = self.start.elapsed().as_micros() as u64;
            let wire_bytes = payload
                .len()
                .saturating_add(verz_link_core::HEADER + verz_link_core::TAG);
            let preferred = self
                .bonded
                .select(&links, wire_bytes, now_us)
                .ok_or_else(|| "no healthy WAN for Bonded Speed".to_owned())?;
            (
                self.sender
                    .forward_on(p.clone(), &links, &mut self.sockets, preferred),
                Some((wire_bytes, now_us)),
            )
        } else if adaptive {
            let preferred = links
                .iter()
                .filter(|link| !link.disabled && link.status == 1)
                .min_by(|left, right| {
                    let left_arrival = left.rtt + left.jitter * 4.0;
                    let right_arrival = right.rtt + right.jitter * 4.0;
                    left_arrival
                        .total_cmp(&right_arrival)
                        .then_with(|| left.id.cmp(&right.id))
                })
                .map(|link| link.id)
                .ok_or_else(|| "no healthy WAN for Adaptive Protection".to_owned())?;
            (
                self.sender
                    .forward_on(p.clone(), &links, &mut self.sockets, preferred),
                None,
            )
        } else {
            // Keep the proven Continuity path on Sender::forward exactly as it
            // was before Bonded Speed was introduced.
            (
                self.sender.forward(p.clone(), &links, &mut self.sockets),
                None,
            )
        };
        let sent = result.map_err(|e| {
            self.errors += 1;
            e.to_string()
        })?;
        if let Some((wire_bytes, now_us)) = bonded_send {
            self.bonded
                .sent(port, sent.sequence, sent.primary, wire_bytes, now_us);
        }
        // Smart mode on a gateway without it behaves as Continuity.
        if self.mode == MODE_CONTINUITY || self.mode == MODE_ADAPTIVE_PROTECTION || self.mode == MODE_CODED {
            // Continuity preserves its existing immediate-copy behavior.
            // Adaptive Protection uses the same proven copy envelope, while its
            // isolated packet class gives the gateway a longer measured wait.
            for link in links
                .iter()
                .filter(|l| l.status == 1 && l.id != sent.primary && Some(l.id) != sent.duplicate)
            {
                let mut copy = p.clone();
                copy.session = self.enrollment.session;
                copy.sequence = sent.sequence;
                copy.link = link.id;
                copy.flags = verz_link_core::FEC;
                if let Ok(wire) = copy.encode(self.enrollment.key.as_bytes())
                    && self.sockets.send(link.id, &wire).is_err()
                {
                    self.errors += 1;
                }
            }
        }
        self.upload += payload.len() as u64;
        Ok(())
    }
    fn tick(&mut self) {
        self.tick_coded();
        if self.heartbeat.elapsed().as_millis() >= 100 {
            self.heartbeat = Instant::now();
            self.probe = self.probe.wrapping_add(1);
            // Preserve the exact legacy heartbeat payload outside the isolated
            // Adaptive Protection mode.
            let report = if self.mode == MODE_ADAPTIVE_PROTECTION {
                serde_json::to_vec(&serde_json::json!({"links": self.links()})).unwrap_or_default()
            } else {
                Vec::new()
            };
            for (&id, p) in &mut self.paths {
                p.probes.retain(|_, t| {
                    if t.elapsed().as_secs() >= 2 {
                        p.outcomes.push_back(false);
                        false
                    } else {
                        true
                    }
                });
                while p.outcomes.len() > 100 {
                    p.outcomes.pop_front();
                }
                let packet = Packet {
                    flags: HEARTBEAT,
                    session: self.enrollment.session,
                    sequence: self.probe,
                    link: id,
                    timestamp_us: stamp(),
                    payload: report.clone(),
                    ..Default::default()
                };
                if let Ok(w) = packet.encode(self.enrollment.key.as_bytes()) {
                    if self.sockets.send(id, &w).is_ok() {
                        p.probes.insert(self.probe, Instant::now());
                    } else {
                        self.errors += 1;
                    }
                }
            }
        }
        let mut incoming = Vec::new();
        if self
            .sockets
            .receive(|id, wire| incoming.push((id, wire.to_vec())))
            .is_err()
        {
            self.errors += 1;
        }
        for (id, wire) in incoming {
            let Ok(p) = Packet::decode(&wire, self.enrollment.key.as_bytes()) else {
                self.errors += 1;
                continue;
            };
            if p.session != self.enrollment.session {
                self.errors += 1;
                continue;
            }
            match p.flags {
                HEARTBEAT => {
                    if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&p.payload) {
                        if value.get("adaptive_protection").and_then(|value| value.as_u64()) == Some(1) {
                            self.adaptive_supported = true;
                            self.adaptive_hold_us = value
                                .get("protection_hold_us")
                                .and_then(|value| value.as_u64())
                                .unwrap_or(self.adaptive_hold_us);
                        }
                        if value.get("coded").and_then(|value| value.as_u64()) == Some(1) {
                            self.coded_supported = true;
                        }
                    }
                    if let Some(path) = self.paths.get_mut(&id)
                        && let Some(t) = path.probes.remove(&p.sequence)
                    {
                        let rtt = t.elapsed().as_secs_f64() * 1000.0;
                        if path.last_reply.is_some() {
                            path.jitter = 0.8 * path.jitter + 0.2 * (rtt - path.rtt).abs();
                        }
                        path.rtt = rtt;
                        path.last_reply = Some(Instant::now());
                        path.outcomes.push_back(true);
                        while path.outcomes.len() > 100 {
                            path.outcomes.pop_front();
                        }
                    }
                }
                ACK if p.class == CODED_CLASS => {
                    let now_us = self.now_us();
                    let epoch = self.epoch_wall as u64;
                    if let Some(mut report) = report_of(&p)
                        && let Some(flow) = self.coded_flows.get_mut(&p.local_port)
                    {
                        report.echo_us = report.echo_us.saturating_sub(epoch);
                        for counts in &mut report.links {
                            counts.newest_sent = counts.newest_sent.saturating_sub(epoch);
                        }
                        flow.sender.on_feedback(now_us, id, &report);
                        if let Some(through) = report.decoded_through {
                            self.bonded.acknowledge(p.local_port, through, now_us);
                        }
                        if !report.missing.is_empty() {
                            // Teaches the scheduler which path lost them; the
                            // repair itself comes from the coded sender.
                            let _ = self.bonded.nack(p.local_port, &report.missing, now_us);
                        }
                        self.coded_stats.reports += 1;
                    }
                }
                ACK | NACK if self.mode == MODE_BONDED_SPEED => {
                    let mut repairs = Vec::new();
                    let now_us = self.start.elapsed().as_micros() as u64;
                    if p.flags == ACK {
                        self.bonded.acknowledge(p.local_port, p.sequence, now_us);
                        let _ = self.sender.control(&wire, &self.links(), &mut self.sockets);
                    } else if let Ok(sequences) = decode_nack(&p.payload) {
                        let fresh = self.bonded.nack(p.local_port, &sequences, now_us);
                        if let Ok(payload) = encode_nack(&fresh) {
                            let mut control = p.clone();
                            control.payload = payload;
                            if let Ok(authenticated) =
                                control.encode(self.enrollment.key.as_bytes())
                                && let Ok(sent) = self.sender.control_on(
                                    &authenticated,
                                    &self.links(),
                                    &mut self.sockets,
                                    Some(id),
                                )
                            {
                                repairs = sent;
                            }
                        }
                    }
                    let now_us = self.start.elapsed().as_micros() as u64;
                    for repair in repairs {
                        self.bonded.repair_sent(
                            p.local_port,
                            repair.sequence,
                            repair.path,
                            repair.wire_bytes,
                            now_us,
                        );
                    }
                }
                ACK | NACK if self.mode == MODE_ADAPTIVE_PROTECTION => {
                    if p.flags == ACK {
                        let _ = self.sender.control(&wire, &self.links(), &mut self.sockets);
                    } else {
                        // A NACK arriving through one path is fresh proof that
                        // path can carry a repair around a silently failed peer.
                        let _ = self.sender.control_on(
                            &wire,
                            &self.links(),
                            &mut self.sockets,
                            Some(id),
                        );
                    }
                }
                ACK | NACK => {
                    // This is the exact pre-Bonded-Speed Continuity control path.
                    let _ = self.sender.control(&wire, &self.links(), &mut self.sockets);
                }
                DOWNLINK => {
                    if !self
                        .dedup
                        .seen_or_add((&p).into(), self.start.elapsed().as_micros() as u64)
                    {
                        if self.received.len() < 1024 {
                            self.download += p.payload.len() as u64;
                            self.received.push_back(p);
                        } else {
                            self.errors += 1;
                        }
                    }
                }
                _ => {
                    self.errors += 1;
                }
            }
        }
    }
}

// The Swift owner guarantees valid buffer lengths and serial access. No callbacks cross FFI.
unsafe fn bytes<'a>(p: *const u8, n: usize) -> &'a [u8] {
    if n == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(p, n) }
    }
}
/// # Safety
/// `p` must reference `n` readable bytes for this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn verz_create(p: *const u8, n: usize) -> *mut Engine {
    if p.is_null() || n > 4096 {
        return std::ptr::null_mut();
    }
    let result = serde_json::from_slice(unsafe { bytes(p, n) })
        .map_err(|e| e.to_string())
        .and_then(Engine::new);
    result
        .map(|e| Box::into_raw(Box::new(e)))
        .unwrap_or(std::ptr::null_mut())
}
/// # Safety
/// `e` must be null or an unfreed result of `verz_create`, exclusively owned by this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn verz_destroy(e: *mut Engine) {
    if !e.is_null() {
        drop(unsafe { Box::from_raw(e) });
    }
}
/// # Safety
/// `e` must be a live engine with serial exclusive access; `p` references `n` readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn verz_adapters(e: *mut Engine, p: *const u8, n: usize) -> i32 {
    if e.is_null() || p.is_null() || n > 65536 {
        return -1;
    }
    let Ok(a) = serde_json::from_slice(unsafe { bytes(p, n) }) else {
        return -1;
    };
    if unsafe { &mut *e }.adapters(a).is_ok() {
        0
    } else {
        -1
    }
}
/// # Safety
/// `e` must be a live engine with serial exclusive access; `p` references `n` readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn verz_send(
    e: *mut Engine,
    port: u16,
    ip: u32,
    remote: u16,
    p: *const u8,
    n: usize,
) -> i32 {
    if e.is_null()
        || (p.is_null() && n != 0)
        || n > verz_link_core::MAX_PAYLOAD
        || port == 0
        || remote == 0
    {
        return -1;
    }
    if unsafe { &mut *e }
        .send(port, ip.to_be_bytes(), remote, unsafe { bytes(p, n) })
        .is_ok()
    {
        0
    } else {
        -1
    }
}
/// # Safety
/// `e` must be null or a live engine with serial exclusive access.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn verz_tick(e: *mut Engine) {
    if !e.is_null() {
        unsafe { &mut *e }.tick();
    }
}
/// Returns 8-byte big-endian flow/destination header followed by UDP payload, or zero.
/// # Safety
/// `e` must be a live engine with serial exclusive access; `out` references `cap` writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn verz_receive(e: *mut Engine, out: *mut u8, cap: usize) -> usize {
    if e.is_null() || out.is_null() || cap < 16392 {
        return 0;
    }
    let Some(p) = unsafe { &mut *e }.received.pop_front() else {
        return 0;
    };
    let mut data = Vec::with_capacity(8 + p.payload.len());
    data.extend(p.local_port.to_be_bytes());
    data.extend(p.destination);
    data.extend(p.destination_port.to_be_bytes());
    data.extend(p.payload);
    unsafe {
        std::ptr::copy_nonoverlapping(data.as_ptr(), out, data.len());
    }
    data.len()
}
/// # Safety
/// `e` must be a live engine with serial exclusive access; `out` references `cap` writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn verz_status(e: *mut Engine, out: *mut u8, cap: usize) -> usize {
    if e.is_null() || out.is_null() {
        return 0;
    }
    let e = unsafe { &*e };
    let value = serde_json::json!({"upload":e.upload,"download":e.download,"errors":e.errors,"wire":e.sockets.bytes,"paths":e.links(),"mode":e.mode,"bonded_speed":e.bonded.status(),"adaptive_protection":{"supported":e.adaptive_supported,"hold_us":e.adaptive_hold_us},"smart":{"supported":e.coded_supported,"flows":e.coded_flows.len(),"stats":e.coded_stats},"adapters":e.paths.iter().map(|(id,p)|(id.to_string(),p.adapter.name.clone())).collect::<BTreeMap<_,_>>()});
    let data = serde_json::to_vec(&value).unwrap_or_default();
    if data.len() > cap {
        return 0;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(data.as_ptr(), out, data.len());
    }
    data.len()
}

/// # Safety
/// `e` must be null or a live engine with serial exclusive access.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn verz_mode(e: *mut Engine, mode: i32) {
    if e.is_null() || !(0..=MODE_CODED).contains(&mode) {
        return;
    }
    let e = unsafe { &mut *e };
    if e.mode != mode {
        e.bonded.reset_runtime(e.start.elapsed().as_micros() as u64);
        e.coded_flows.clear();
    }
    e.mode = mode;
    e.sender.set_config(Config {
        // Mode 1 chooses through BondedSpeed::select and deliberately avoids
        // duplicate payload. Modes 0/2/3 retain their previous core scheduler;
        // mode 4 uses explicit protection copies and its isolated class.
        bond_all: false,
        fec: mode != MODE_BONDED_SPEED
            && mode != MODE_DATA_SAVER
            && mode != MODE_ADAPTIVE_PROTECTION,
        ..Default::default()
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secure::SecureGateway as Gateway;
    use std::{net::UdpSocket, time::Duration};

    fn adapter(id: u8) -> Adapter {
        Adapter {
            id,
            name: if cfg!(target_os = "macos") {
                "lo0"
            } else {
                "lo"
            }
            .into(),
            address: Ipv4Addr::LOCALHOST,
        }
    }
    fn pump(e: &mut Engine, g: &mut Gateway) {
        e.tick();
        g.step().unwrap();
        e.tick();
    }
    #[test]
    fn real_udp_modes_and_path_removal_keep_egress_and_deduplicate() {
        let key = "test-key-not-a-secret-0123456789abcdef";
        let mut g = Gateway::bind("127.0.0.1:0".parse().unwrap(), key.into(), true).unwrap();
        let destination = UdpSocket::bind("127.0.0.1:0").unwrap();
        destination.set_nonblocking(true).unwrap();
        let port = destination.local_addr().unwrap().port();
        let mut e = Engine::new(Enrollment {
            gateway: g.address().unwrap(),
            session: 91,
            key: key.into(),
        })
        .unwrap();
        e.adapters(vec![adapter(1), adapter(2), adapter(3)])
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        while e.links().iter().filter(|l| l.status == 1).count() != 3 && Instant::now() < deadline {
            pump(&mut e, &mut g);
        }
        assert_eq!(e.links().iter().filter(|l| l.status == 1).count(), 3);
        let mut source = None;
        assert!(
            e.adaptive_supported,
            "new gateway capability was not authenticated"
        );
        for sequence in 0..15u8 {
            if sequence == 3 {
                e.adapters(vec![adapter(1), adapter(3)]).unwrap();
            }
            if sequence == 6 {
                e.adapters(vec![adapter(1), adapter(2), adapter(3)])
                    .unwrap();
            }
            // Change policy without resetting stream sequence or stable server egress.
            unsafe { verz_mode(&mut e, (sequence % 5) as i32) };
            e.send(32000, [127, 0, 0, 1], port, &[sequence]).unwrap();
            let deadline = Instant::now() + Duration::from_secs(1);
            let mut seen = 0;
            let mut buf = [0u8; 128];
            while Instant::now() < deadline {
                pump(&mut e, &mut g);
                if let Ok((n, from)) = destination.recv_from(&mut buf) {
                    assert_eq!(&buf[..n], &[sequence]);
                    seen += 1;
                    if let Some(source) = source {
                        assert_eq!(source, from);
                    } else {
                        source = Some(from);
                    }
                    destination.send_to(&buf[..n], from).unwrap();
                }
                if let Some(reply) = e.received.pop_front() {
                    assert_eq!(reply.local_port, 32000);
                    assert_eq!(reply.payload, vec![sequence]);
                    break;
                }
            }
            assert_eq!(seen, 1, "every payload must arrive once");
            for _ in 0..5 {
                pump(&mut e, &mut g);
            }
            assert!(e.received.is_empty(), "downlink copies delivered twice");
            assert!(
                destination.recv_from(&mut buf).is_err(),
                "uplink copies delivered twice"
            );
        }
        assert_eq!(g.counters()["udp"]["uplink_bytes"], 15);
        assert_eq!(e.download, 15);
    }
    #[test]
    fn wrong_key_never_reports_healthy_or_sends_payload() {
        let mut g = Gateway::bind("127.0.0.1:0".parse().unwrap(), "a".repeat(32), true).unwrap();
        let mut e = Engine::new(Enrollment {
            gateway: g.address().unwrap(),
            session: 91,
            key: "b".repeat(32),
        })
        .unwrap();
        e.adapters(vec![adapter(1)]).unwrap();
        for _ in 0..5 {
            pump(&mut e, &mut g);
        }
        assert_eq!(e.links()[0].status, 0);
        assert!(e.send(1, [1, 1, 1, 1], 53, b"no").is_err());
        assert_eq!(g.counters()["udp"]["uplink_bytes"], 0);
    }

    #[test]
    fn smart_mode_rebuilds_datagrams_lost_on_silently_cut_wans_without_copies() {
        use std::collections::HashMap;
        let key = "test-key-0123456789abcdef0123456789abcdef";
        let mut g = Gateway::bind("127.0.0.1:0".parse().unwrap(), key.into(), true).unwrap();
        let router = UdpSocket::bind("127.0.0.1:0").unwrap();
        router.set_nonblocking(true).unwrap();
        let destination = UdpSocket::bind("127.0.0.1:0").unwrap();
        destination.set_nonblocking(true).unwrap();
        let gateway = g.address().unwrap();
        let mut e = Engine::new(Enrollment {
            gateway: router.local_addr().unwrap(),
            session: 98,
            key: key.into(),
        })
        .unwrap();
        e.adapters(vec![adapter(1), adapter(2)]).unwrap();
        unsafe { verz_mode(&mut e, MODE_CODED) };
        let mut paths = HashMap::new();
        let tally = std::cell::RefCell::new(HashMap::<(bool, u8, bool), u64>::new());
        let mut route = |cut: u8| {
            let mut buf = [0u8; 17000];
            for _ in 0..256 {
                let Ok((n, from)) = router.recv_from(&mut buf) else {
                    break;
                };
                if n < 30 {
                    continue;
                };
                let id = buf[21];
                if from == gateway {
                    *tally.borrow_mut().entry((false, id, id != cut)).or_default() += 1;
                    if id != cut
                        && let Some(to) = paths.get(&id)
                    {
                        router.send_to(&buf[..n], to).unwrap();
                    }
                } else {
                    *tally.borrow_mut().entry((true, id, id != cut)).or_default() += 1;
                    paths.insert(id, from);
                    if id != cut {
                        router.send_to(&buf[..n], gateway).unwrap();
                    }
                }
            }
        };
        let deadline = Instant::now() + Duration::from_secs(2);
        while !(e.coded_supported && e.links().iter().filter(|p| p.status == 1).count() == 2)
            && Instant::now() < deadline
        {
            e.tick();
            route(0);
            g.step().unwrap();
            route(0);
            e.tick();
        }
        assert!(e.coded_supported, "gateway did not announce Smart mode");
        let mut delivered = std::collections::HashSet::new();
        let mut replies = std::collections::HashSet::new();
        let mut buf = [0; 17000];
        for sequence in 0u32..600 {
            let cut = if (100..300).contains(&sequence) {
                2
            } else if (400..500).contains(&sequence) {
                1
            } else {
                0
            };
            let mut payload = vec![0x5a; 1332];
            payload[..4].copy_from_slice(&sequence.to_be_bytes());
            e.send(32000, [127, 0, 0, 1], destination.local_addr().unwrap().port(), &payload)
                .unwrap();
            let until = Instant::now() + Duration::from_millis(400);
            while Instant::now() < until {
                e.tick();
                route(cut);
                g.step().unwrap();
                route(cut);
                e.tick();
                while let Ok((n, from)) = destination.recv_from(&mut buf) {
                    assert_eq!(n, 1332, "datagram was not reassembled from its pieces");
                    let seq = u32::from_be_bytes(buf[..4].try_into().unwrap());
                    assert!(delivered.insert(seq), "duplicate uplink delivery");
                    destination.send_to(&buf[..n], from).unwrap();
                }
                while let Some(p) = e.received.pop_front() {
                    let seq = u32::from_be_bytes(p.payload[..4].try_into().unwrap());
                    replies.insert(seq);
                }
                if replies.contains(&sequence) {
                    break;
                }
            }
            if !replies.contains(&sequence) {
                let counters = g.counters();
                let flow = e.coded_flows.get(&32000).unwrap();
                let now = e.now_us();
                eprintln!(
                    "STATE: delivered={} replies={} errors={} stats={} pending={} next_seq={} blocks={:?}..{:?}",
                    delivered.contains(&sequence),
                    replies.len(),
                    e.errors,
                    serde_json::to_string(&e.coded_stats).unwrap(),
                    flow.pending.len(),
                    flow.next_seq,
                    flow.blocks.keys().next(),
                    flow.blocks.keys().next_back(),
                );
                for l in flow.sender.status(now) {
                    eprintln!("STATE link {} {:?} p={:.3} placed={:.0}/s loss={:.3} owd={:.0}us", l.id, l.state, l.p_dead, l.placed_pps, l.loss, l.predicted_owd_us);
                }
                eprintln!("COVERS: {:?}", flow.sender.stats.covers.iter().rev().take(4).map(|&(t, l, f, w, s)| (now.saturating_sub(t) / 1000, l, f, w, s)).collect::<Vec<_>>());
                let u = &counters["udp"];
                eprintln!("GATEWAY: rebuilt={} repairs={} abandoned={} rejected={} uplink={} limits={}", u["coded_rebuilt"], u["coded_repairs"], u["coded_abandoned"], u["rejected"], u["uplink_bytes"], counters["limits"]);
                eprintln!("SECURE: transport rejected={} sessions={} engine wire={:?}", counters["rejected"], counters["sessions"], e.sockets.bytes.iter().map(|(id, b)| (*id, b.sent, b.received)).collect::<Vec<_>>());
                eprintln!("CODED_DETAIL: {}", counters["limits"]["coded_detail"]);
                eprintln!("BYLINK: repairs per link {:?}; speculative={} reactive={} proactive={}", e.coded_stats.repairs_by_link, flow.sender.stats.speculative, flow.sender.stats.reactive, flow.sender.stats.proactive);
            }
            assert!(replies.contains(&sequence), "datagram {sequence} stalled after path event");
        }
        assert_eq!(delivered.len(), 600);
        assert_eq!(e.coded_stats.originals, 1200, "every datagram is two pieces");
        assert!(e.coded_stats.reports > 0, "no reports came back");
        let counters = g.counters();
        assert!(counters["udp"]["coded_rebuilt"].as_u64().unwrap() > 0, "nothing was rebuilt from repairs");
        assert_eq!(counters["udp"]["uplink_bytes"], 600 * 1332);
        // Data cost: copies would double the bytes on the wire; repairs must not.
        let wire: u64 = e.sockets.bytes.values().map(|b| b.sent).sum();
        assert!(wire < 2 * 1200 * 1_300, "wire bytes {wire} look like copies, not repairs");
    }

    #[test]
    fn complete_srt_datagrams_survive_silent_wan_loss_and_return() {
        use std::collections::HashMap;
        let key = "test-key-0123456789abcdef0123456789abcdef";
        let mut g = Gateway::bind("127.0.0.1:0".parse().unwrap(), key.into(), true).unwrap();
        let router = UdpSocket::bind("127.0.0.1:0").unwrap();
        router.set_nonblocking(true).unwrap();
        let destination = UdpSocket::bind("127.0.0.1:0").unwrap();
        destination.set_nonblocking(true).unwrap();
        let gateway = g.address().unwrap();
        let mut e = Engine::new(Enrollment {
            gateway: router.local_addr().unwrap(),
            session: 97,
            key: key.into(),
        })
        .unwrap();
        e.adapters(vec![adapter(1), adapter(2)]).unwrap();
        unsafe { verz_mode(&mut e, 2) };
        let mut paths = HashMap::new();
        let mut route = |cut: u8| {
            let mut buf = [0u8; 17000];
            for _ in 0..256 {
                let Ok((n, from)) = router.recv_from(&mut buf) else {
                    break;
                };
                if n < 30 {
                    continue;
                };
                let id = buf[21];
                if from == gateway {
                    if id != cut
                        && let Some(to) = paths.get(&id)
                    {
                        router.send_to(&buf[..n], to).unwrap();
                    }
                } else {
                    paths.insert(id, from);
                    if id != cut {
                        router.send_to(&buf[..n], gateway).unwrap();
                    }
                }
            }
        };
        let deadline = Instant::now() + Duration::from_secs(2);
        while e.links().iter().filter(|p| p.status == 1).count() != 2 && Instant::now() < deadline {
            e.tick();
            route(0);
            g.step().unwrap();
            route(0);
            e.tick();
        }
        assert_eq!(e.links().iter().filter(|p| p.status == 1).count(), 2);
        let mut source = None;
        let mut delivered = std::collections::HashSet::new();
        let mut replies = std::collections::HashSet::new();
        let mut buf = [0; 17000];
        for sequence in 0u32..1200 {
            let cut = if (100..600).contains(&sequence) {
                2
            } else if (750..1050).contains(&sequence) {
                1
            } else {
                0
            };
            let mut payload = vec![0x5a; 1332];
            payload[..4].copy_from_slice(&sequence.to_be_bytes());
            e.send(
                32000,
                [127, 0, 0, 1],
                destination.local_addr().unwrap().port(),
                &payload,
            )
            .unwrap();
            let until = Instant::now() + Duration::from_millis(250);
            while Instant::now() < until {
                e.tick();
                route(cut);
                g.step().unwrap();
                route(cut);
                e.tick();
                while let Ok((n, from)) = destination.recv_from(&mut buf) {
                    assert_eq!(
                        n, 1332,
                        "datagram was fragmented at the application boundary"
                    );
                    let seq = u32::from_be_bytes(buf[..4].try_into().unwrap());
                    assert!(delivered.insert(seq), "duplicate uplink delivery");
                    if let Some(old) = source {
                        assert_eq!(old, from, "gateway egress identity changed");
                    } else {
                        source = Some(from);
                    }
                    destination.send_to(&buf[..n], from).unwrap();
                }
                while let Some(p) = e.received.pop_front() {
                    assert_eq!(p.payload.len(), 1332);
                    let seq = u32::from_be_bytes(p.payload[..4].try_into().unwrap());
                    assert!(replies.insert(seq), "duplicate downlink delivery");
                }
                if replies.contains(&sequence) {
                    break;
                }
            }
            assert!(
                replies.contains(&sequence),
                "datagram {sequence} stalled after path event"
            );
        }
        assert_eq!(delivered.len(), 1200);
        assert_eq!(replies.len(), 1200);
    }
}
