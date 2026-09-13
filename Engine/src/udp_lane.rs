//! Adapter for the UDP sender from MacOS-2 commit 654232a. UDP never enters
//! bond::Scheduler's pending/cwnd queues. The runtime encrypts every core wire
//! packet inside the existing Noise session before touching a WAN socket.
use crate::{
    bond::{BOND_MTU, Policy, Scheduler},
    udp_reassembly::{Output, Stream},
};
use serde::Serialize;
use std::{
    collections::{HashMap, VecDeque},
    io,
};
use verz_link_core::{
    ACK, FEC, NACK, Packet, TUN, encode_nack,
    recovery::{Deduper, DeliveryKey},
    scheduler::{Config, Link},
    transport::{Sender, WanWriter},
};

const MAX_FLOWS: usize = 4096;
const MAX_STREAMS: usize = 256;
// The reference admits 64 complete application datagrams. A normal SRT
// datagram is two TUN fragments here; retain that effective admission budget.
const STREAM_CAPACITY: usize = 128;
const DELIVERY_CAPACITY: usize = 1024;
const FLOW_TTL: u64 = 120_000;

#[derive(Default, Serialize)]
pub struct Counters {
    pub payload_sent_bytes: u64,
    pub payload_unmeasured_packets: u64,
    pub submitted_packets: u64,
    pub sent_packets: u64,
    pub send_failures: u64,
    pub delivered_packets: u64,
    pub delivered_bytes: u64,
    pub duplicate_packets: u64,
    pub protection_copies: u64,
    pub repairs: u64,
    pub receive_backpressure: u64,
    pub flow_limit_drops: u64,
    pub reassembly_rejections: u64,
}

pub fn is_udp(ip: &[u8]) -> bool {
    ip.len() >= 20 && ip[0] >> 4 == 4 && ip[9] == 17
}

/// This uses path health only, deliberately not TCP cwnd, inflight, pacing,
/// or the primary-path latency cutoff. A slow healthy backup still sends.
pub fn links(scheduler: &Scheduler, now: u64) -> Vec<Link> {
    scheduler
        .paths
        .iter()
        .map(|p| Link {
            id: p.id,
            status: u8::from(p.ready(now)),
            disabled: !p.enabled,
            probed: p.rtt_ms.is_some(),
            rtt: p.rtt_ms.unwrap_or(1000.0),
            jitter: p.jitter_ms,
            variance: 0.0,
            loss: 0.0,
            // Probes do not measure link capacity or packet loss. Don't manufacture
            // estimates from TCP's ACK window; retain the reference unknown value.
            capacity: 0.0,
            uptime: 1.0,
        })
        .collect()
}

struct ReceiveStream {
    stream: Stream,
    last: u64,
}
pub struct UdpLane {
    sender: Sender,
    key: Vec<u8>,
    policy: Policy,
    // Full UDP flow tuples; fragment associations keep all pieces on that flow.
    flows: HashMap<[u8; 12], (u16, u64)>,
    fragments: HashMap<[u8; 10], ([u8; 12], u64)>,
    next_flow: u32,
    streams: HashMap<u16, ReceiveStream>,
    dedup: Deduper,
    delivered: VecDeque<Vec<u8>>,
    pub counters: Counters,
}
impl UdpLane {
    pub fn new(secret: &[u8; 32], session: &[u8; 16], policy: Policy) -> io::Result<Self> {
        // Each outer Noise session already has independent directional AEAD
        // keys/replay windows. Derive the core's inner authentication key too.
        let mut key = vec![0; 32];
        hkdf::Hkdf::<sha2::Sha256>::new(Some(session), secret)
            .expand(b"VERZ repo UDP lane v1", &mut key)
            .map_err(|_| io::Error::other("UDP key derivation"))?;
        Ok(Self {
            sender: Sender::new(1, key.clone(), Self::config(policy))?,
            key,
            policy,
            flows: HashMap::new(),
            fragments: HashMap::new(),
            next_flow: 1,
            streams: HashMap::new(),
            dedup: Deduper::new(16384, 10_000_000),
            delivered: VecDeque::new(),
            counters: Counters::default(),
        })
    }
    fn config(policy: Policy) -> Config {
        Config {
            bond_all: policy == Policy::Performance,
            fec: policy != Policy::DataSaver,
            ..Config::default()
        }
    }
    fn flow(&mut self, ip: &[u8], now: u64) -> io::Result<u16> {
        let ihl = usize::from(ip[0] & 15) * 4;
        let fragment = u16::from_be_bytes([ip[6], ip[7]]);
        let mut tuple = [0; 12];
        tuple[..8].copy_from_slice(&ip[12..20]);
        let mut fragment_key = [0; 10];
        fragment_key[..8].copy_from_slice(&ip[12..20]);
        fragment_key[8..].copy_from_slice(&ip[4..6]);
        if fragment & 0x1fff == 0 && ip.len() >= ihl + 8 {
            tuple[8..].copy_from_slice(&ip[ihl..ihl + 4]);
            if fragment & 0x2000 != 0 {
                self.fragments
                    .retain(|_, (_, at)| now.saturating_sub(*at) < 2000);
                if self.fragments.len() < MAX_FLOWS {
                    self.fragments.insert(fragment_key, (tuple, now));
                }
            }
        } else if let Some((known, at)) = self.fragments.get(&fragment_key)
            && now.saturating_sub(*at) < 2000
        {
            tuple = *known;
        }
        if let Some((id, at)) = self.flows.get_mut(&tuple) {
            *at = now;
            return Ok(*id);
        }
        self.flows
            .retain(|_, (_, at)| now.saturating_sub(*at) < FLOW_TTL);
        if self.flows.len() >= MAX_FLOWS || self.next_flow > u32::from(u16::MAX) {
            self.counters.flow_limit_drops += 1;
            return Err(io::Error::other("UDP flow identity limit reached"));
        }
        let id = self.next_flow as u16;
        self.next_flow += 1;
        self.flows.insert(tuple, (id, now));
        Ok(id)
    }
    pub fn send(
        &mut self,
        ip: &[u8],
        paths: &[Link],
        policy: Policy,
        now: u64,
        writer: &mut impl WanWriter,
    ) -> io::Result<()> {
        if !is_udp(ip) || ip.len() > BOND_MTU {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "not an MTU-bounded IPv4 UDP packet",
            ));
        }
        if self.policy != policy {
            self.policy = policy;
            self.sender.set_config(Self::config(policy));
        }
        self.counters.submitted_packets += 1;
        let port = self.flow(ip, now)?;
        let mut packet = Packet {
            flags: TUN,
            class: 4,
            local_port: port,
            protocol: 17,
            timestamp_us: (now.saturating_mul(1000).min(i64::MAX as u64)) as i64,
            payload: ip.to_vec(),
            ..Packet::default()
        };
        let sent = match self.sender.forward(packet.clone(), paths, writer) {
            Ok(sent) => sent,
            Err(e) => {
                self.counters.send_failures += 1;
                return Err(e);
            }
        };
        self.counters.sent_packets += 1;
        if let Some(bytes) = crate::payload_meter::udp_payload_len(ip) {
            self.counters.payload_sent_bytes += bytes;
        } else {
            self.counters.payload_unmeasured_packets += 1;
        }
        if sent.duplicate.is_some() {
            self.counters.protection_copies += 1;
        }
        // Reference Engine::send Continuity fanout: same sequence, every
        // reachable path, immediate writes, no wait for primary ACK/failure.
        // Smart protects relayed UDP as well; Performance/Data Saver retain
        // the reference scheduler's non-replicating/bounded-copy selection.
        if matches!(policy, Policy::Smart | Policy::Continuity) {
            packet.session = 1;
            packet.sequence = sent.sequence;
            packet.flags = TUN | FEC;
            for path in paths.iter().filter(|p| {
                !p.disabled
                    && matches!(p.status, 1 | 2)
                    && p.id != sent.primary
                    && Some(p.id) != sent.duplicate
            }) {
                packet.link = path.id;
                if writer.carrier(path.id) && writer.send(path.id, &self.encode(&packet)?).is_ok() {
                    self.counters.protection_copies += 1;
                }
            }
        }
        Ok(())
    }
    pub fn decode(&self, wire: &[u8]) -> io::Result<Packet> {
        let p = Packet::decode(wire, &self.key).map_err(io::Error::other)?;
        if p.session != 1
            || (p.flags != ACK
                && p.flags != NACK
                && (!p.is_data()
                    || p.flags & TUN == 0
                    || p.protocol != 17
                    || !is_udp(&p.payload)
                    || p.payload.len() > BOND_MTU))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid UDP lane packet",
            ));
        }
        Ok(p)
    }
    pub fn encode(&self, p: &Packet) -> io::Result<Vec<u8>> {
        p.encode(&self.key).map_err(io::Error::other)
    }
    pub fn control(
        &mut self,
        wire: &[u8],
        paths: &[Link],
        writer: &mut impl WanWriter,
    ) -> io::Result<()> {
        self.counters.repairs += self.sender.control(wire, paths, writer)? as u64;
        Ok(())
    }
    fn output(&mut self, port: u16, output: Output) -> Vec<Packet> {
        for p in output.ready {
            self.counters.delivered_packets += 1;
            self.counters.delivered_bytes += p.payload.len() as u64;
            self.delivered.push_back(p.payload);
        }
        let mut controls = Vec::new();
        if let Some(sequence) = output.ack {
            controls.push(Packet {
                flags: ACK,
                session: 1,
                local_port: port,
                sequence,
                ..Packet::default()
            });
        }
        if !output.nack.is_empty() {
            controls.push(Packet {
                flags: NACK,
                session: 1,
                local_port: port,
                payload: encode_nack(&output.nack).expect("reference NACK is bounded"),
                ..Packet::default()
            });
        }
        controls
    }
    pub fn receive(&mut self, p: Packet, now: u64) -> io::Result<Vec<Packet>> {
        // One insertion/tick can release the two bounded reorder/copy buffers.
        // Refuse before mutation or ACK when the delivery queue cannot own it.
        if self.delivered.len() + 2 * STREAM_CAPACITY + 1 > DELIVERY_CAPACITY {
            self.counters.receive_backpressure += 1;
            return Ok(Vec::new());
        }
        let port = p.local_port;
        if !self.streams.contains_key(&port) {
            self.streams
                .retain(|_, s| now.saturating_sub(s.last) < FLOW_TTL);
            if self.streams.len() >= MAX_STREAMS {
                self.counters.flow_limit_drops += 1;
                return Ok(Vec::new());
            }
            self.streams.insert(
                port,
                ReceiveStream {
                    stream: Stream::new(50_000, 25_000, STREAM_CAPACITY),
                    last: now,
                },
            );
        }
        let key = DeliveryKey::from(&p);
        let state = self.streams.get_mut(&port).expect("created stream");
        state.last = now;
        let out = match state.stream.insert(p, now.saturating_mul(1000)) {
            Ok(out) => out,
            Err(error) => {
                self.counters.reassembly_rejections += 1;
                // A refused packet is not delivered/seen. Another copy or
                // resend must still be eligible once capacity is available.
                return Err(io::Error::other(error));
            }
        };
        // Stream owns ordering and duplicate suppression (as in the reference
        // gateway). This ledger is telemetry only, AFTER successful admission.
        // A repeated packet can also release older queued packets, so never
        // discard the stream's output merely because this key was seen before.
        if self.dedup.seen_or_add(key, now.saturating_mul(1000)) {
            self.counters.duplicate_packets += 1;
        }
        Ok(self.output(port, out))
    }
    pub fn tick(&mut self, now: u64) -> Vec<Packet> {
        let mut controls = Vec::new();
        let ports: Vec<_> = self.streams.keys().copied().collect();
        for port in ports {
            if self.delivered.len() + 2 * STREAM_CAPACITY + 1 > DELIVERY_CAPACITY {
                break;
            }
            let out = self
                .streams
                .get_mut(&port)
                .unwrap()
                .stream
                .tick(now.saturating_mul(1000));
            controls.extend(self.output(port, out));
        }
        controls
    }
    pub fn front(&self) -> Option<&Vec<u8>> {
        self.delivered.front()
    }
    pub fn pop(&mut self) -> Option<Vec<u8>> {
        self.delivered.pop_front()
    }
}
