//! The methods shipped today, driven through their real code:
//!
//! - **Split** = Bonded Speed: `UdpEngine/src/bonded.rs` picks the link,
//!   the shared-core `Sender` sends and resends, and the gateway's repairing
//!   `reassembly::Stream` (class 3) puts packets back in order.
//! - **Copy** = Continuity: shared-core `Sender::forward` plus a copy on every
//!   other live link, received by the class-4 `reassembly::Stream`.
//!
//! Only the glue that lives in `UdpEngine/src/lib.rs` and `gateway.rs` is
//! re-expressed here: 100 ms heartbeats, "healthy = a heartbeat reply within
//! the last second", ACK/NACK fan-out to every known path, and the 10 ms
//! gateway sweep. Constants match those files.

use super::{Log, Method, PAYLOAD, WIRE};
use crate::bonded::BondedSpeed;
use crate::net::{Kind, Net};
use crate::reassembly::{Output, Stream};
use std::collections::{HashMap, VecDeque};
use std::io;
use verz_link_core::scheduler::{Config, Link};
use verz_link_core::transport::{Sender, WanWriter};
use verz_link_core::{ACK, FEC, HEARTBEAT, NACK, Packet, RESEND, decode_nack, encode_nack};

const KEY: [u8; 32] = [7; 32];
const SESSION: u32 = 123;
const PORT: u16 = 5_000;
const HEARTBEAT_US: u64 = 100_000;
const REPLY_FRESH_US: u64 = 1_000_000;
const PROBE_LOST_US: u64 = 2_000_000;
const PATH_FRESH_US: u64 = 30_000_000;
const SWEEP_US: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Split,
    Copy,
}

#[derive(Default)]
struct Path {
    probes: HashMap<u32, u64>,
    last_reply: Option<u64>,
    rtt: f64,
    jitter: f64,
    outcomes: VecDeque<bool>,
}

pub struct Shipped {
    mode: Mode,
    // Client (lib.rs).
    sender: Sender,
    bonded: BondedSpeed,
    paths: Vec<Path>,
    probe: u32,
    next_heartbeat: u64,
    // Server (gateway.rs).
    stream: Stream,
    server_paths: HashMap<u8, u64>,
    next_sweep: u64,
}

/// The client's sockets: a send fails only when the interface has no carrier.
struct Wans<'a> {
    net: &'a mut Net<Vec<u8>, Vec<u8>>,
    now: u64,
}

impl WanWriter for Wans<'_> {
    fn carrier(&self, id: u8) -> bool {
        self.net.carrier(usize::from(id) - 1, self.now)
    }

    fn send(&mut self, id: u8, wire: &[u8]) -> io::Result<()> {
        let flags = wire[5];
        let kind = if flags & HEARTBEAT != 0 {
            Kind::Probe
        } else if flags & (FEC | RESEND) != 0 {
            Kind::Protection
        } else {
            Kind::Original
        };
        if self.net.up(self.now, usize::from(id) - 1, wire.len(), kind, wire.to_vec()) {
            Ok(())
        } else {
            Err(io::Error::new(io::ErrorKind::NotConnected, "no carrier"))
        }
    }
}

impl Shipped {
    pub fn new(mode: Mode, links: usize) -> Self {
        let (budget, grace, capacity) = match mode {
            Mode::Split => (30_000, 50_000, 1_024),
            Mode::Copy => (50_000, 25_000, 64),
        };
        Self {
            mode,
            sender: Sender::new(SESSION, KEY.to_vec(), Config::default()).expect("valid session"),
            bonded: BondedSpeed::default(),
            paths: (0..links).map(|_| Path::default()).collect(),
            probe: 0,
            next_heartbeat: 0,
            stream: match mode {
                Mode::Split => Stream::new_repairing(budget, grace, capacity),
                Mode::Copy => Stream::new(budget, grace, capacity),
            },
            server_paths: HashMap::new(),
            next_sweep: 0,
        }
    }

    fn links(&self, now: u64) -> Vec<Link> {
        self.paths
            .iter()
            .enumerate()
            .map(|(i, p)| {
                let id = i as u8 + 1;
                Link {
                    id,
                    status: u8::from(p.last_reply.is_some_and(|t| now - t < REPLY_FRESH_US)),
                    disabled: false,
                    probed: p.last_reply.is_some(),
                    rtt: p.rtt,
                    jitter: p.jitter,
                    variance: 0.0,
                    loss: if p.outcomes.is_empty() {
                        0.0
                    } else {
                        100.0 * p.outcomes.iter().filter(|v| !**v).count() as f64 / p.outcomes.len() as f64
                    },
                    capacity: match self.mode {
                        Mode::Split => self.bonded.capacity_bps(id).unwrap_or(0.0),
                        Mode::Copy => 0.0,
                    },
                    uptime: 1.0,
                }
            })
            .collect()
    }

    fn heartbeat(&mut self, now: u64, net: &mut Net<Vec<u8>, Vec<u8>>) {
        self.probe = self.probe.wrapping_add(1);
        for (i, path) in self.paths.iter_mut().enumerate() {
            path.probes.retain(|_, &mut t| {
                if now - t >= PROBE_LOST_US {
                    path.outcomes.push_back(false);
                    false
                } else {
                    true
                }
            });
            while path.outcomes.len() > 100 {
                path.outcomes.pop_front();
            }
            let packet = Packet {
                flags: HEARTBEAT,
                session: SESSION,
                sequence: self.probe,
                link: i as u8 + 1,
                timestamp_us: now as i64 + 1,
                ..Default::default()
            };
            let wire = packet.encode(&KEY).expect("encodes");
            let mut wans = Wans { net, now };
            if wans.send(i as u8 + 1, &wire).is_ok() {
                path.probes.insert(self.probe, now);
            }
        }
    }

    fn fanout(&self, now: u64, packet: &Packet, net: &mut Net<Vec<u8>, Vec<u8>>) {
        let wire = packet.encode(&KEY).expect("encodes");
        for (&id, &at) in &self.server_paths {
            if now - at < PATH_FRESH_US {
                net.down(now, usize::from(id) - 1, wire.len(), wire.clone());
            }
        }
    }

    fn output(&self, now: u64, result: Output, net: &mut Net<Vec<u8>, Vec<u8>>, log: &mut Log) {
        for p in &result.ready {
            log.released(u32::from_be_bytes(p.payload[..4].try_into().expect("seq")), now);
        }
        if let Some(sequence) = result.ack {
            let ack = Packet { flags: ACK, session: SESSION, sequence, local_port: PORT, ..Default::default() };
            self.fanout(now, &ack, net);
        }
        if !result.nack.is_empty() {
            let nack = Packet {
                flags: NACK,
                session: SESSION,
                local_port: PORT,
                payload: encode_nack(&result.nack).expect("at most 32"),
                ..Default::default()
            };
            self.fanout(now, &nack, net);
        }
    }
}

impl Method for Shipped {
    type Up = Vec<u8>;
    type Down = Vec<u8>;

    fn source(&mut self, now: u64, seq: u32, net: &mut Net<Vec<u8>, Vec<u8>>, log: &mut Log) {
        let links = self.links(now);
        // The simulator's own sequence rides in the payload: the Sender
        // numbers packets itself and skips numbers when a send fails.
        let mut payload = vec![0; PAYLOAD];
        payload[..4].copy_from_slice(&seq.to_be_bytes());
        let packet = Packet {
            class: if self.mode == Mode::Split { 3 } else { 4 },
            local_port: PORT,
            destination: [93, 184, 216, 34],
            destination_port: 9_000,
            protocol: 17,
            timestamp_us: now as i64 + 1,
            payload,
            ..Default::default()
        };
        let mut wans = Wans { net, now };
        match self.mode {
            Mode::Split => {
                let Some(preferred) = self.bonded.select(&links, WIRE, now) else {
                    return;
                };
                if let Ok(sent) = self.sender.forward_on(packet, &links, &mut wans, preferred) {
                    self.bonded.sent(PORT, sent.sequence, sent.primary, WIRE, now);
                    log.sent_on(seq, sent.primary);
                }
            }
            Mode::Copy => {
                let Ok(sent) = self.sender.forward(packet.clone(), &links, &mut wans) else {
                    return;
                };
                log.sent_on(seq, sent.primary);
                for link in links
                    .iter()
                    .filter(|l| l.status == 1 && l.id != sent.primary && Some(l.id) != sent.duplicate)
                {
                    let mut copy = packet.clone();
                    copy.session = SESSION;
                    copy.sequence = sent.sequence;
                    copy.link = link.id;
                    copy.flags = FEC;
                    let wire = copy.encode(&KEY).expect("encodes");
                    let _ = wans.send(link.id, &wire);
                }
            }
        }
    }

    fn at_server(&mut self, now: u64, _link: usize, wire: Vec<u8>, net: &mut Net<Vec<u8>, Vec<u8>>, log: &mut Log) {
        let Ok(p) = Packet::decode(&wire, &KEY) else {
            return;
        };
        if p.flags == HEARTBEAT {
            self.server_paths.insert(p.link, now);
            let reply = Packet {
                flags: HEARTBEAT,
                class: p.class,
                session: SESSION,
                sequence: p.sequence,
                timestamp_us: now as i64 + 1,
                link: p.link,
                ..Default::default()
            };
            let wire = reply.encode(&KEY).expect("encodes");
            net.down(now, usize::from(p.link) - 1, wire.len(), wire);
            return;
        }
        if !p.is_data() {
            return;
        }
        self.server_paths.insert(p.link, now);
        if p.flags & (FEC | RESEND) == 0 {
            log.arrived(u32::from_be_bytes(p.payload[..4].try_into().expect("seq")), now);
        }
        if let Ok(result) = self.stream.insert(p, now) {
            self.output(now, result, net, log);
        }
    }

    fn at_client(&mut self, now: u64, link: usize, wire: Vec<u8>, net: &mut Net<Vec<u8>, Vec<u8>>) {
        let Ok(p) = Packet::decode(&wire, &KEY) else {
            return;
        };
        let id = link as u8 + 1;
        match p.flags {
            HEARTBEAT => {
                let path = &mut self.paths[link];
                if let Some(t) = path.probes.remove(&p.sequence) {
                    let rtt = (now - t) as f64 / 1_000.0;
                    if path.last_reply.is_some() {
                        path.jitter = 0.8 * path.jitter + 0.2 * (rtt - path.rtt).abs();
                    }
                    path.rtt = rtt;
                    path.last_reply = Some(now);
                    path.outcomes.push_back(true);
                    while path.outcomes.len() > 100 {
                        path.outcomes.pop_front();
                    }
                }
            }
            ACK | NACK if self.mode == Mode::Split => {
                let links = self.links(now);
                let mut wans = Wans { net, now };
                let mut repairs = Vec::new();
                if p.flags == ACK {
                    self.bonded.acknowledge(p.local_port, p.sequence, now);
                    let _ = self.sender.control(&wire, &links, &mut wans);
                } else if let Ok(sequences) = decode_nack(&p.payload) {
                    let fresh = self.bonded.nack(p.local_port, &sequences, now);
                    if let Ok(payload) = encode_nack(&fresh) {
                        let mut control = p.clone();
                        control.payload = payload;
                        if let Ok(authenticated) = control.encode(&KEY)
                            && let Ok(sent) = self.sender.control_on(&authenticated, &links, &mut wans, Some(id))
                        {
                            repairs = sent;
                        }
                    }
                }
                for repair in repairs {
                    self.bonded.repair_sent(p.local_port, repair.sequence, repair.path, repair.wire_bytes, now);
                }
            }
            ACK | NACK => {
                let links = self.links(now);
                let _ = self.sender.control(&wire, &links, &mut Wans { net, now });
            }
            _ => {}
        }
    }

    fn notes(&self) -> String {
        format!(
            "scheduled={} nacks={} resends={}",
            self.bonded.scheduled_packets, self.bonded.nack_events, self.bonded.repair_packets
        )
    }

    fn tick(&mut self, now: u64, net: &mut Net<Vec<u8>, Vec<u8>>, log: &mut Log) {
        if now >= self.next_heartbeat {
            self.next_heartbeat = now + HEARTBEAT_US;
            self.heartbeat(now, net);
        }
        if now >= self.next_sweep {
            self.next_sweep = now + SWEEP_US;
            let result = self.stream.tick(now);
            self.output(now, result, net, log);
        }
    }
}
