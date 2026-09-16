//! Non-TUN UDP egress: stable socket per (session, local port, remote IP/port).
//! Removing a WAN return path does not replace that socket or the reassembly stream.
use crate::reassembly::{Output, Stream};
use std::{
    collections::{HashMap, VecDeque},
    io,
    net::{Ipv4Addr, SocketAddr, UdpSocket},
    os::fd::AsRawFd,
    time::{Instant, SystemTime, UNIX_EPOCH},
};
use verz_link_core::{ACK, DOWNLINK, HEARTBEAT, NACK, Packet, TUN, encode_nack, recovery::Deduper};

fn stamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros() as i64
}
type FlowKey = (u32, u16, [u8; 4], u16);
const MAX_FLOWS: usize = 1024;
const MAX_STREAMS: usize = 1024;
const MAX_BUFFERED_BYTES: usize = 32 * 1024 * 1024;
const UDP_IDLE_US: u64 = 300_000_000;
const DNS_PENDING_IDLE_US: u64 = 30_000_000;
const DNS_COMPLETE_IDLE_US: u64 = 2_000_000;
const ADAPTIVE_CLASS: u16 = 5;
const ADAPTIVE_NACK_US: u64 = 30_000;
const ADAPTIVE_MIN_HOLD_US: u64 = 80_000;
const ADAPTIVE_MAX_HOLD_US: u64 = 2_000_000;
const ADAPTIVE_MARGIN_US: u64 = 50_000;
const ADAPTIVE_SAMPLE_LIMIT: usize = 256;
const ADAPTIVE_SAMPLE_MAX_AGE_US: u64 = 10_000_000;
const ADAPTIVE_ARRIVAL_LIMIT: usize = 4_096;

#[derive(Clone, Copy)]
struct PathTiming {
    rtt_us: u64,
    jitter_us: u64,
    updated_us: u64,
}

struct FirstArrival {
    path: u8,
    at_us: u64,
    observed_paths: Vec<u8>,
}

#[derive(Default)]
struct ProtectionTiming {
    paths: HashMap<u8, PathTiming>,
    arrivals: HashMap<(u16, u32), FirstArrival>,
    arrival_order: VecDeque<(u16, u32)>,
    skew_samples: VecDeque<(u64, u64)>,
}

impl ProtectionTiming {
    fn update_links(&mut self, value: &serde_json::Value, now_us: u64) {
        let Some(links) = value.get("links").and_then(|links| links.as_array()) else {
            return;
        };
        for link in links {
            let Some(id) = link.get("id").and_then(|id| id.as_u64()) else {
                continue;
            };
            let status = link.get("status").and_then(|status| status.as_u64());
            let disabled = link
                .get("disabled")
                .and_then(|disabled| disabled.as_bool())
                .unwrap_or(false);
            let rtt = link.get("rtt").and_then(|rtt| rtt.as_f64());
            let jitter = link
                .get("jitter")
                .and_then(|jitter| jitter.as_f64())
                .unwrap_or(0.0);
            if id == 0
                || id > u8::MAX as u64
                || disabled
                || !matches!(status, Some(1 | 2))
                || rtt.is_none_or(|rtt| !rtt.is_finite() || rtt <= 0.0)
                || !jitter.is_finite()
            {
                continue;
            }
            self.paths.insert(
                id as u8,
                PathTiming {
                    rtt_us: (rtt.unwrap().clamp(0.0, 10_000.0) * 1_000.0) as u64,
                    jitter_us: (jitter.clamp(0.0, 10_000.0) * 1_000.0) as u64,
                    updated_us: now_us,
                },
            );
        }
        self.paths
            .retain(|_, timing| now_us.saturating_sub(timing.updated_us) < 2_000_000);
    }

    fn observe_copy(&mut self, packet: &Packet, now_us: u64) {
        if packet.class != ADAPTIVE_CLASS || packet.link == 0 {
            return;
        }
        let key = (packet.local_port, packet.sequence);
        if let Some(first) = self.arrivals.get_mut(&key) {
            if packet.link != first.path && !first.observed_paths.contains(&packet.link) {
                first.observed_paths.push(packet.link);
                self.skew_samples
                    .push_back((now_us, now_us.saturating_sub(first.at_us)));
                while self.skew_samples.len() > ADAPTIVE_SAMPLE_LIMIT {
                    self.skew_samples.pop_front();
                }
            }
            return;
        }
        self.arrivals.insert(
            key,
            FirstArrival {
                path: packet.link,
                at_us: now_us,
                observed_paths: vec![packet.link],
            },
        );
        self.arrival_order.push_back(key);
        while self.arrivals.len() > ADAPTIVE_ARRIVAL_LIMIT {
            if let Some(oldest) = self.arrival_order.pop_front() {
                self.arrivals.remove(&oldest);
            }
        }
        while self.arrival_order.len() > ADAPTIVE_ARRIVAL_LIMIT * 2 {
            if let Some(oldest) = self.arrival_order.pop_front()
                && self.arrivals.contains_key(&oldest)
            {
                self.arrival_order.push_back(oldest);
                break;
            }
        }
    }

    fn hold_us(&self, now_us: u64) -> u64 {
        let recent: Vec<_> = self
            .paths
            .values()
            .filter(|timing| now_us.saturating_sub(timing.updated_us) < 2_000_000)
            .collect();
        let reported_skew = if recent.len() >= 2 {
            let fastest = recent
                .iter()
                .map(|timing| timing.rtt_us / 2)
                .min()
                .unwrap_or(0);
            recent
                .iter()
                .map(|timing| timing.rtt_us / 2 + timing.jitter_us.saturating_mul(4))
                .max()
                .unwrap_or(fastest)
                .saturating_sub(fastest)
        } else {
            0
        };
        let mut samples: Vec<_> = self
            .skew_samples
            .iter()
            .filter(|(at, _)| now_us.saturating_sub(*at) <= ADAPTIVE_SAMPLE_MAX_AGE_US)
            .map(|(_, skew)| *skew)
            .collect();
        let measured_skew = if samples.is_empty() {
            0
        } else {
            samples.sort_unstable();
            let rank = (samples.len() * 99).div_ceil(100).saturating_sub(1);
            samples[rank]
        };
        reported_skew
            .max(measured_skew)
            .saturating_add(ADAPTIVE_MARGIN_US)
            .clamp(ADAPTIVE_MIN_HOLD_US, ADAPTIVE_MAX_HOLD_US)
    }

    fn recent_sample_count(&self, now_us: u64) -> usize {
        self.skew_samples
            .iter()
            .filter(|(at, _)| now_us.saturating_sub(*at) <= ADAPTIVE_SAMPLE_MAX_AGE_US)
            .count()
    }
}

// UDP has no remote FIN. Only validated DNS request/response exchanges use a
// short idle timer; arbitrary UDP retains a five-minute idle mapping. See
// RFC 4787 section 4.3 (well-known application-specific timeout exception).
struct DnsActivity {
    pending: std::collections::HashSet<u16>,
}
fn dns_id(payload: &[u8], response: bool) -> Option<u16> {
    if payload.len() < 12
        || (payload[2] & 0x80 != 0) != response
        || payload[2] & 0x78 != 0
        || payload[4..6] == [0, 0]
    {
        return None;
    }
    Some(u16::from_be_bytes([payload[0], payload[1]]))
}
struct Flow {
    socket: UdpSocket,
    class: u16,
    protocol: u8,
    last: u64,
    dns: Option<DnsActivity>,
}
impl Flow {
    fn sent(&mut self, payload: &[u8], now: u64) {
        self.last = now;
        if let Some(dns) = &mut self.dns {
            if let Some(id) = dns_id(payload, false)
                && (dns.pending.len() < 64 || dns.pending.contains(&id))
            {
                dns.pending.insert(id);
            } else {
                // Unknown/malformed traffic on port 53 is not declared complete.
                self.dns = None;
            }
        }
    }
    fn received(&mut self, payload: &[u8], now: u64) {
        self.last = now;
        if let Some(dns) = &mut self.dns
            && let Some(id) = dns_id(payload, true)
        {
            dns.pending.remove(&id);
        }
    }
    fn expired(&self, now: u64) -> bool {
        let idle = match &self.dns {
            Some(dns) if dns.pending.is_empty() => DNS_COMPLETE_IDLE_US,
            Some(_) => DNS_PENDING_IDLE_US,
            None => UDP_IDLE_US,
        };
        now.saturating_sub(self.last) >= idle
    }
}
struct Peer {
    key: Vec<u8>,
    paths: HashMap<u8, (SocketAddr, u64)>,
    disabled: HashMap<u8, bool>,
    sequence: u32,
    protection: ProtectionTiming,
}
struct Ordered {
    stream: Stream,
    last: u64,
    class: u16,
}
#[derive(Default, serde::Serialize)]
pub struct Counters {
    pub uplink_bytes: u64,
    pub downlink_bytes: u64,
    pub rejected: u64,
    pub send_errors: u64,
    pub flows_expired: u64,
    pub dns_flows_expired: u64,
    pub capacity_rejections: u64,
    pub buffer_rejections: u64,
    pub peak_flows: usize,
    pub adaptive_hold_us: u64,
    pub adaptive_skew_samples: usize,
}
pub struct Gateway {
    socket: UdpSocket,
    peers: HashMap<u32, Peer>,
    flows: HashMap<FlowKey, Flow>,
    streams: HashMap<(u32, u16), Ordered>,
    sip: Deduper,
    start: Instant,
    last_sweep: u64,
    last_expire: u64,
    buffered_bytes: usize,
    pub counters: Counters,
    allow_private: bool,
}
impl Gateway {
    pub fn bind(
        listen: SocketAddr,
        identities: Vec<(u32, Vec<u8>)>,
        allow_private: bool,
    ) -> io::Result<Self> {
        let socket = UdpSocket::bind(listen)?;
        socket.set_nonblocking(true)?;
        let mut peers = HashMap::new();
        for (id, key) in identities {
            if id == 0 || key.len() < 32 || peers.contains_key(&id) {
                return Err(io::Error::other("invalid/duplicate enrollment"));
            }
            peers.insert(
                id,
                Peer {
                    key,
                    paths: HashMap::new(),
                    disabled: HashMap::new(),
                    sequence: 0,
                    protection: ProtectionTiming::default(),
                },
            );
        }
        Ok(Self {
            socket,
            peers,
            flows: HashMap::new(),
            streams: HashMap::new(),
            sip: Deduper::new(8192, 10_000_000),
            start: Instant::now(),
            last_sweep: 0,
            last_expire: 0,
            buffered_bytes: 0,
            counters: Counters::default(),
            allow_private,
        })
    }
    pub fn address(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }
    // Only the authenticated Noise front-end can create or remove enrollments.
    pub fn enroll(&mut self, id: u32, key: Vec<u8>) -> io::Result<()> {
        if id == 0 || key.len() < 32 || self.peers.contains_key(&id) {
            return Err(io::Error::other("invalid enrollment"));
        }
        self.peers.insert(
            id,
            Peer {
                key,
                paths: HashMap::new(),
                disabled: HashMap::new(),
                sequence: 0,
                protection: ProtectionTiming::default(),
            },
        );
        Ok(())
    }
    pub fn forget(&mut self, id: u32) {
        self.peers.remove(&id);
        self.flows.retain(|key, _| key.0 != id);
        self.streams.retain(|key, _| key.0 != id);
        self.buffered_bytes = self
            .streams
            .values()
            .map(|s| s.stream.buffered_bytes())
            .sum();
    }
    pub fn flow_count(&self) -> usize {
        self.flows.len()
    }
    pub fn limits(&self) -> serde_json::Value {
        serde_json::json!({"max_flows":MAX_FLOWS,"streams":self.streams.len(),
            "max_streams":MAX_STREAMS,"buffered_bytes":self.buffered_bytes,
            "max_buffered_bytes":MAX_BUFFERED_BYTES})
    }
    fn expire(&mut self, now: u64) {
        // Reclaim before admission as well as during maintenance. Never evict an
        // active flow to make room; both received and sent payload refresh it.
        self.flows.retain(|_, flow| {
            if flow.expired(now) {
                self.counters.flows_expired += 1;
                self.counters.dns_flows_expired += u64::from(flow.dns.is_some());
                false
            } else {
                true
            }
        });
        let active: std::collections::HashSet<_> = self.flows.keys().map(|k| (k.0, k.1)).collect();
        self.streams.retain(|key, ordered| {
            // Preserve sequencing even for download-only streams. The old code
            // timed reorder state from uplink alone, independently of egress.
            active.contains(key) || now.saturating_sub(ordered.last) < UDP_IDLE_US
        });
        self.buffered_bytes = self
            .streams
            .values()
            .map(|s| s.stream.buffered_bytes())
            .sum();
    }
    fn reject_capacity(&mut self) {
        self.counters.capacity_rejections += 1;
        self.counters.rejected += 1;
    }
    fn fanout(&self, session: u32, packet: &Packet, now: u64) {
        let peer = &self.peers[&session];
        if let Ok(wire) = packet.encode(&peer.key) {
            for (&id, (address, at)) in &peer.paths {
                if now.saturating_sub(*at) < 30_000_000
                    && !peer.disabled.get(&id).copied().unwrap_or(false)
                {
                    let _ = self.socket.send_to(&wire, address);
                }
            }
        }
    }
    fn egress(&mut self, p: &Packet, now: u64) -> io::Result<()> {
        let key = (p.session, p.local_port, p.destination, p.destination_port);
        if !self.flows.contains_key(&key) {
            if self.flows.len() >= MAX_FLOWS {
                self.expire(now);
            }
            if self.flows.len() >= MAX_FLOWS {
                self.reject_capacity();
                return Err(io::Error::other("egress capacity reached"));
            }
            let socket = UdpSocket::bind("0.0.0.0:0")?;
            socket.connect((Ipv4Addr::from(p.destination), p.destination_port))?;
            socket.set_nonblocking(true)?;
            self.flows.insert(
                key,
                Flow {
                    socket,
                    class: p.class,
                    protocol: p.protocol,
                    last: now,
                    dns: (p.destination_port == 53).then(|| DnsActivity {
                        pending: Default::default(),
                    }),
                },
            );
            self.counters.peak_flows = self.counters.peak_flows.max(self.flows.len());
        }
        let flow = self.flows.get_mut(&key).unwrap();
        flow.socket.send(&p.payload)?;
        flow.sent(&p.payload, now);
        self.counters.uplink_bytes += p.payload.len() as u64;
        Ok(())
    }
    fn output(&mut self, session: u32, port: u16, result: Output, now: u64) {
        for p in &result.ready {
            if self.egress(p, now).is_err() {
                self.counters.send_errors += 1;
            }
        }
        if let Some(sequence) = result.ack {
            self.fanout(
                session,
                &Packet {
                    flags: ACK,
                    session,
                    sequence,
                    local_port: port,
                    ..Default::default()
                },
                now,
            );
        }
        if !result.nack.is_empty() {
            self.fanout(
                session,
                &Packet {
                    flags: NACK,
                    session,
                    local_port: port,
                    payload: encode_nack(&result.nack).unwrap(),
                    ..Default::default()
                },
                now,
            );
        }
    }
    fn ingress(&mut self, wire: &[u8], remote: SocketAddr, now: u64) {
        if wire.len() < 38 {
            self.counters.rejected += 1;
            return;
        }
        let session = u32::from_be_bytes(wire[8..12].try_into().unwrap());
        let Some(peer) = self.peers.get_mut(&session) else {
            self.counters.rejected += 1;
            return;
        };
        let p = match Packet::decode(wire, &peer.key) {
            Ok(p) => p,
            Err(_) => {
                self.counters.rejected += 1;
                return;
            }
        };
        if p.link == 0 {
            self.counters.rejected += 1;
            return;
        }
        if p.flags == HEARTBEAT {
            peer.paths.insert(p.link, (remote, now));
            if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&p.payload)
                && let Some(links) = value.get("links").and_then(|v| v.as_array())
            {
                for link in links {
                    if let (Some(id), Some(disabled)) = (
                        link.get("id").and_then(|v| v.as_u64()),
                        link.get("disabled").and_then(|v| v.as_bool()),
                    ) && id > 0
                        && id <= 255
                    {
                        peer.disabled.insert(id as u8, disabled);
                    }
                }
                peer.protection.update_links(&value, now);
            }
            let adaptive_hold_us = peer.protection.hold_us(now);
            self.counters.adaptive_hold_us = adaptive_hold_us;
            self.counters.adaptive_skew_samples = peer.protection.recent_sample_count(now);
            let reply = Packet {
                flags: HEARTBEAT,
                class: p.class,
                session,
                sequence: p.sequence,
                timestamp_us: stamp(),
                link: p.link,
                protocol: p.protocol,
                payload: serde_json::to_vec(&serde_json::json!({
                    "adaptive_protection": 1,
                    "protection_hold_us": adaptive_hold_us
                }))
                .unwrap_or_default(),
                ..Default::default()
            };
            if let Ok(wire) = reply.encode(&peer.key) {
                let _ = self.socket.send_to(&wire, remote);
            }
            return;
        }
        if !p.is_data()
            || p.flags & TUN != 0
            || p.destination_port == 0
            || !destination_allowed(p.destination, self.allow_private)
        {
            self.counters.rejected += 1;
            return;
        }
        peer.paths.insert(p.link, (remote, now));
        let port = p.local_port;
        let class = p.normalized_class();
        let adaptive_hold_us = if class == ADAPTIVE_CLASS {
            peer.protection.observe_copy(&p, now);
            let hold = peer.protection.hold_us(now);
            self.counters.adaptive_hold_us = hold;
            self.counters.adaptive_skew_samples = peer.protection.recent_sample_count(now);
            Some(hold)
        } else {
            None
        };
        if class != ADAPTIVE_CLASS
            && (p.protocol == 4 || (5100..=5134).contains(&port) || p.destination_port == 53)
        {
            // DNS transactions are independently matched by their IDs. They do
            // not need a ten-minute reorder stream, but copies still deduplicate.
            let mut result = Output {
                ack: Some(p.sequence),
                ..Default::default()
            };
            if !self.sip.seen_or_add((&p).into(), now) {
                result.ready.push(p);
            }
            self.output(session, port, result, now);
            return;
        }
        let new_stream = !self.streams.contains_key(&(session, port));
        let new_flow =
            !self
                .flows
                .contains_key(&(session, port, p.destination, p.destination_port));
        if (new_stream && self.streams.len() >= MAX_STREAMS)
            || (new_flow && self.flows.len() >= MAX_FLOWS)
        {
            self.expire(now);
        }
        if (new_stream && self.streams.len() >= MAX_STREAMS)
            || (new_flow && self.flows.len() >= MAX_FLOWS)
        {
            self.reject_capacity();
            return;
        }
        if self.buffered_bytes.saturating_add(p.payload.len()) > MAX_BUFFERED_BYTES {
            self.counters.buffer_rejections += 1;
            self.counters.rejected += 1;
            return;
        }
        let (budget, grace, capacity) = match class {
            // Bonded Speed stripes one flow across unequal paths. At 20 Mbps a
            // 100 ms path skew can hold roughly 200 full-sized datagrams, so its
            // per-flow buffer must be larger than Continuity's duplicate lane.
            // Request a repair after 30 ms; waiting 100 ms here caused the media
            // receiver to exhaust its own latency budget during a silent cut.
            3 => (30_000, 50_000, 1_024),
            // Adaptive Protection keeps early repair requests but delays final
            // release long enough for a proactively duplicated high-latency
            // copy. The wait is derived from live path evidence and bounded.
            ADAPTIVE_CLASS => (ADAPTIVE_NACK_US, 50_000, 8_192),
            4 => (50_000, 25_000, 64),
            2 => (2_000_000, 200_000, 64),
            _ => (5_000_000, 200_000, 64),
        };
        let ordered = self
            .streams
            .entry((session, port))
            .or_insert_with(|| Ordered {
                stream: if matches!(class, 3 | ADAPTIVE_CLASS) {
                    Stream::new_repairing(budget, grace, capacity)
                } else {
                    Stream::new(budget, grace, capacity)
                },
                last: now,
                class,
            });
        if ordered.class != class && (ordered.class == ADAPTIVE_CLASS || class == ADAPTIVE_CLASS) {
            ordered.stream = if matches!(class, 3 | ADAPTIVE_CLASS) {
                Stream::new_repairing_from(p.sequence, budget, grace, capacity)
            } else {
                Stream::new_from(p.sequence, budget, grace, capacity)
            };
            ordered.class = class;
        }
        if class == ADAPTIVE_CLASS {
            ordered.stream.set_adaptive_window(
                ADAPTIVE_NACK_US,
                adaptive_hold_us.unwrap_or(ADAPTIVE_MIN_HOLD_US),
            );
        }
        ordered.last = now;
        let before = ordered.stream.buffered_bytes();
        let result = ordered.stream.insert(p, now);
        self.buffered_bytes = self.buffered_bytes - before + ordered.stream.buffered_bytes();
        match result {
            Ok(result) => self.output(session, port, result, now),
            Err(_) => self.counters.rejected += 1,
        }
    }
    /// One bounded poll iteration, also used by the integration tests.
    pub fn step(&mut self, timeout_ms: i32) -> io::Result<()> {
        let mut polls = vec![libc::pollfd {
            fd: self.socket.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        }];
        let polled: Vec<_> = self.flows.keys().copied().collect();
        polls.extend(polled.iter().map(|key| libc::pollfd {
            fd: self.flows[key].socket.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        }));
        // SAFETY: polls remains allocated for the entire call; every fd is owned by self.
        let rc = unsafe {
            libc::poll(
                polls.as_mut_ptr(),
                polls.len() as libc::nfds_t,
                timeout_ms.clamp(0, 10),
            )
        };
        if rc < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
            return Err(io::Error::last_os_error());
        }
        let now = self.start.elapsed().as_micros() as u64;
        let mut buf = [0u8; 16_439];
        for _ in 0..256 {
            match self.socket.recv_from(&mut buf) {
                Ok((n, remote)) => self.ingress(&buf[..n], remote, now),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(e),
            }
        }
        let mut replies = Vec::new();
        let mut dead = Vec::new();
        for (key, poll) in polled.into_iter().zip(polls.iter().skip(1)) {
            if poll.revents == 0 {
                continue;
            }
            let Some(flow) = self.flows.get_mut(&key) else {
                continue;
            };
            for _ in 0..32 {
                match flow.socket.recv(&mut buf) {
                    Ok(n) if n <= verz_link_core::MAX_PAYLOAD => {
                        flow.received(&buf[..n], now);
                        self.counters.downlink_bytes += n as u64;
                        let peer = self.peers.get_mut(&key.0).unwrap();
                        peer.sequence = peer.sequence.wrapping_add(1);
                        replies.push(Packet {
                            flags: DOWNLINK,
                            class: flow.class,
                            session: key.0,
                            sequence: peer.sequence,
                            timestamp_us: stamp(),
                            protocol: flow.protocol,
                            local_port: key.1,
                            destination: key.2,
                            destination_port: key.3,
                            payload: buf[..n].to_vec(),
                            ..Default::default()
                        });
                    }
                    Ok(_) => {
                        self.counters.rejected += 1;
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(_) => {
                        dead.push(key);
                        break;
                    }
                }
            }
        }
        for key in dead {
            self.flows.remove(&key);
        }
        for p in replies {
            self.fanout(p.session, &p, now);
        }
        if now.saturating_sub(self.last_sweep) >= 10_000 {
            if now.saturating_sub(self.last_expire) >= 250_000 {
                self.expire(now);
                self.last_expire = now;
            }
            let outputs: Vec<_> = self
                .streams
                .iter_mut()
                .map(|(&(sid, port), s)| {
                    let before = s.stream.buffered_bytes();
                    let output = s.stream.tick(now);
                    self.buffered_bytes = self.buffered_bytes - before + s.stream.buffered_bytes();
                    (sid, port, output)
                })
                .collect();
            for (sid, port, result) in outputs {
                self.output(sid, port, result, now);
            }
            self.last_sweep = now;
        }
        Ok(())
    }
}
fn destination_allowed(bytes: [u8; 4], allow_private: bool) -> bool {
    let ip = Ipv4Addr::from(bytes);
    if ip.is_unspecified() || ip.is_multicast() || ip.is_broadcast() || bytes[0] >= 240 {
        return false;
    }
    allow_private
        || (!ip.is_private()
            && !ip.is_loopback()
            && !ip.is_link_local()
            && bytes[0] != 0
            && !(bytes[0] == 100 && (64..=127).contains(&bytes[1])))
}

#[cfg(test)]
mod lifecycle_tests {
    use super::*;
    use std::time::Duration;

    const KEY: [u8; 32] = [7; 32];
    fn setup() -> (Gateway, UdpSocket) {
        let g = Gateway::bind(
            "127.0.0.1:0".parse().unwrap(),
            vec![(1, KEY.to_vec())],
            true,
        )
        .unwrap();
        let sink = UdpSocket::bind("127.0.0.1:0").unwrap();
        sink.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        (g, sink)
    }
    fn packet(port: u16, destination: u16, seq: u32) -> Packet {
        Packet {
            session: 1,
            local_port: port,
            destination: [127, 0, 0, 1],
            destination_port: destination,
            sequence: seq,
            link: 1,
            class: 4,
            timestamp_us: i64::from(seq) + 1,
            payload: vec![42; 100],
            ..Default::default()
        }
    }
    fn ingest(g: &mut Gateway, p: &Packet, now: u64) {
        g.ingress(
            &p.encode(&KEY).unwrap(),
            "127.0.0.1:9".parse().unwrap(),
            now,
        );
    }
    fn dns(id: u16, response: bool) -> Vec<u8> {
        let mut data = vec![0; 12];
        data[..2].copy_from_slice(&id.to_be_bytes());
        data[2] = if response { 0x81 } else { 0x01 };
        data[5] = 1;
        // One root-name A/IN question, a complete valid DNS message.
        data.extend_from_slice(&[0, 0, 1, 0, 1]);
        data
    }
    fn dns_flow(destination: SocketAddr, now: u64) -> Flow {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.connect(destination).unwrap();
        Flow {
            socket,
            class: 4,
            protocol: 0,
            last: now,
            dns: Some(DnsActivity {
                pending: Default::default(),
            }),
        }
    }

    fn unequal_path_report() -> serde_json::Value {
        serde_json::json!({"links":[
            {"id":1,"status":1,"disabled":false,"rtt":50.0,"jitter":2.0},
            {"id":2,"status":1,"disabled":false,"rtt":600.0,"jitter":10.0}
        ]})
    }

    #[test]
    fn adaptive_hold_uses_reported_latency_spread_and_jitter() {
        let mut timing = ProtectionTiming::default();
        timing.update_links(&unequal_path_report(), 1_000_000);
        // Fastest one-way estimate: 25 ms. Slow estimate plus four jitter
        // deviations: 340 ms. Add the bounded 50 ms protection margin.
        assert_eq!(timing.hold_us(1_000_000), 365_000);
    }

    #[test]
    fn adaptive_hold_is_data_driven_for_two_or_more_arbitrary_wans() {
        let profiles = [
            (
                serde_json::json!({"links":[
                    {"id":1,"status":1,"disabled":false,"rtt":20.0,"jitter":1.0},
                    {"id":2,"status":1,"disabled":false,"rtt":20.0,"jitter":1.0}
                ]}),
                80_000,
            ),
            (
                serde_json::json!({"links":[
                    {"id":4,"status":1,"disabled":false,"rtt":40.0,"jitter":2.0},
                    {"id":9,"status":1,"disabled":false,"rtt":120.0,"jitter":8.0}
                ]}),
                122_000,
            ),
            (
                serde_json::json!({"links":[
                    {"id":2,"status":1,"disabled":false,"rtt":80.0,"jitter":4.0},
                    {"id":7,"status":1,"disabled":false,"rtt":300.0,"jitter":20.0},
                    {"id":11,"status":1,"disabled":false,"rtt":45.0,"jitter":3.0}
                ]}),
                257_500,
            ),
        ];
        for (profile, expected) in profiles {
            let mut timing = ProtectionTiming::default();
            timing.update_links(&profile, 1_000_000);
            assert_eq!(timing.hold_us(1_000_000), expected);
        }
    }

    #[test]
    fn observed_copy_arrival_skew_can_extend_the_reported_hold() {
        let mut timing = ProtectionTiming::default();
        let mut p = packet(10000, 9000, 7);
        p.class = ADAPTIVE_CLASS;
        p.link = 1;
        timing.observe_copy(&p, 1_000_000);
        p.flags = verz_link_core::FEC;
        p.link = 2;
        timing.observe_copy(&p, 1_700_000);
        assert_eq!(timing.hold_us(1_700_000), 750_000);
        assert_eq!(timing.skew_samples.len(), 1);
        timing.update_links(
            &serde_json::json!({"links":[
                {"id":1,"status":1,"disabled":false,"rtt":20.0,"jitter":1.0},
                {"id":2,"status":1,"disabled":false,"rtt":20.0,"jitter":1.0}
            ]}),
            11_700_001,
        );
        assert_eq!(
            timing.hold_us(11_700_001),
            ADAPTIVE_MIN_HOLD_US,
            "expired path skew must not permanently inflate the buffer"
        );
        assert_eq!(timing.recent_sample_count(11_700_001), 0);
    }

    #[test]
    fn adaptive_stream_waits_for_delayed_cross_wan_copy() {
        let (mut g, sink) = setup();
        let destination = sink.local_addr().unwrap().port();
        g.peers
            .get_mut(&1)
            .unwrap()
            .protection
            .update_links(&unequal_path_report(), 0);

        let mut later = packet(10000, destination, 1);
        later.class = ADAPTIVE_CLASS;
        later.payload = vec![1];
        ingest(&mut g, &later, 0);
        let request = g.streams.get_mut(&(1, 10000)).unwrap().stream.tick(100_000);
        assert!(
            request.ready.is_empty(),
            "later packet escaped before protection deadline"
        );

        let mut delayed = packet(10000, destination, 0);
        delayed.class = ADAPTIVE_CLASS;
        delayed.flags = verz_link_core::FEC;
        delayed.link = 2;
        delayed.payload = vec![0];
        ingest(&mut g, &delayed, 300_000);
        assert_eq!(
            g.counters.uplink_bytes, 0,
            "adaptive traffic escaped before the playout deadline"
        );
        let result = g.streams.get_mut(&(1, 10000)).unwrap().stream.tick(365_000);
        g.output(1, 10000, result, 365_000);

        let mut payload = [0u8; 8];
        assert_eq!(sink.recv_from(&mut payload).unwrap().0, 1);
        assert_eq!(payload[0], 0);
        assert_eq!(sink.recv_from(&mut payload).unwrap().0, 1);
        assert_eq!(payload[0], 1);
    }

    #[test]
    fn dns_cleanup_waits_for_all_replies_and_keeps_pending_requests() {
        let (_, sink) = setup();
        let mut f = dns_flow(sink.local_addr().unwrap(), 0);
        f.sent(&dns(1, false), 0);
        f.sent(&dns(2, false), 100);
        f.received(&dns(99, true), 200); // Unmatched reply must not complete either query.
        f.received(&dns(1, true), 300);
        assert!(!f.expired(DNS_COMPLETE_IDLE_US + 300));
        assert!(!f.expired(DNS_PENDING_IDLE_US + 299));
        f.received(&dns(2, true), DNS_PENDING_IDLE_US + 299);
        assert!(!f.expired(DNS_PENDING_IDLE_US + DNS_COMPLETE_IDLE_US + 298));
        assert!(f.expired(DNS_PENDING_IDLE_US + DNS_COMPLETE_IDLE_US + 299));
        f.sent(
            &dns(3, false),
            DNS_PENDING_IDLE_US + DNS_COMPLETE_IDLE_US + 299,
        );
        assert!(!f.expired(DNS_PENDING_IDLE_US + 2 * DNS_COMPLETE_IDLE_US + 299));
    }

    #[test]
    fn malformed_dns_uses_general_udp_idle_lifetime() {
        let (_, sink) = setup();
        let mut f = dns_flow(sink.local_addr().unwrap(), 0);
        f.sent(b"not DNS", 0);
        assert!(f.dns.is_none());
        assert!(!f.expired(UDP_IDLE_US - 1));
        assert!(f.expired(UDP_IDLE_US));
    }

    #[test]
    fn dns_does_not_consume_ordered_stream_slots_and_delayed_copy_deduplicates() {
        let (mut g, _) = setup();
        let mut p = packet(10000, 53, 0);
        p.payload = dns(1, false);
        ingest(&mut g, &p, 0); // Loopback-only DNS destination, no external query.
        assert_eq!(g.flows.len(), 1);
        assert!(g.streams.is_empty());
        g.flows
            .values_mut()
            .next()
            .unwrap()
            .received(&dns(1, true), 0);
        g.expire(DNS_COMPLETE_IDLE_US);
        assert!(g.flows.is_empty());
        p.flags = verz_link_core::FEC;
        p.link = 2;
        ingest(&mut g, &p, DNS_COMPLETE_IDLE_US + 1);
        assert!(
            g.flows.is_empty(),
            "late redundant copy resurrected expired DNS mapping"
        );
        assert_eq!(g.counters.uplink_bytes, dns(1, false).len() as u64);
    }

    #[test]
    fn completed_dns_churn_reclaims_slots_without_changing_live_socket() {
        let (mut g, sink) = setup();
        let destination = sink.local_addr().unwrap();
        let active = (1, 10000, [127, 0, 0, 1], destination.port());
        let mut p = packet(10000, destination.port(), 0);
        ingest(&mut g, &p, 0);
        let mut buf = [0; 128];
        let (_, source) = sink.recv_from(&mut buf).unwrap();
        for i in 0..5000u16 {
            let now = u64::from(i) * 4000;
            g.expire(now);
            let mut f = dns_flow(destination, now);
            f.sent(&dns(i, false), now);
            f.received(&dns(i, true), now);
            g.flows.insert((1, 20000 + i, [127, 0, 0, 1], 53), f);
            assert!(g.flows.len() < MAX_FLOWS);
            if i % 100 == 0 {
                p.sequence += 1;
                p.timestamp_us += 1;
                ingest(&mut g, &p, now);
                assert_eq!(sink.recv_from(&mut buf).unwrap().1, source);
            }
        }
        assert!(g.counters.dns_flows_expired > 4000);
        assert_eq!(g.counters.capacity_rejections, 0);
        assert_eq!(
            g.flows[&active].socket.local_addr().unwrap().port(),
            source.port()
        );
        assert_eq!(g.streams.len(), 1);
    }

    #[test]
    fn full_table_rejects_new_flows_but_preserves_existing_stream_and_identity() {
        let (mut g, sink) = setup();
        let dest = sink.local_addr().unwrap().port();
        let mut buf = [0; 128];
        let mut source = None;
        for i in 0..MAX_FLOWS as u16 {
            ingest(&mut g, &packet(10000 + i, dest, 0), 0);
            let (_, from) = sink.recv_from(&mut buf).unwrap();
            if i == 0 {
                source = Some(from);
            }
        }
        assert_eq!(g.flows.len(), MAX_FLOWS);
        assert_eq!(g.streams.len(), MAX_STREAMS);
        assert_eq!(
            g.counters.rejected, 0,
            "old 256-flow admission failure returned"
        );
        ingest(&mut g, &packet(30000, dest, 0), 1);
        assert_eq!(g.counters.capacity_rejections, 1);
        ingest(&mut g, &packet(10000, dest, 1), 2);
        assert_eq!(sink.recv_from(&mut buf).unwrap().1, source.unwrap());
        assert_eq!(g.counters.uplink_bytes, (MAX_FLOWS as u64 + 1) * 100);
    }

    #[test]
    fn downstream_activity_preserves_socket_and_reorder_state_during_cleanup() {
        let (mut g, sink) = setup();
        let p = packet(10000, sink.local_addr().unwrap().port(), 0);
        ingest(&mut g, &p, 0);
        let flow = g.flows.values_mut().next().unwrap();
        let source = flow.socket.local_addr().unwrap();
        flow.received(b"ongoing downstream", UDP_IDLE_US - 1);
        g.expire(UDP_IDLE_US + 1);
        assert_eq!(
            g.flows
                .values()
                .next()
                .unwrap()
                .socket
                .local_addr()
                .unwrap(),
            source
        );
        assert!(g.streams.contains_key(&(1, 10000)));
        g.expire(2 * UDP_IDLE_US);
        assert!(g.flows.is_empty());
        assert!(g.streams.is_empty());
    }

    #[test]
    fn bonded_speed_restores_cross_wan_packet_order_before_udp_egress() {
        let (mut g, sink) = setup();
        let destination = sink.local_addr().unwrap().port();
        let mut second = packet(10000, destination, 1);
        second.class = 3;
        second.link = 2;
        second.payload = vec![1];
        ingest(&mut g, &second, 1_000);
        assert_eq!(g.counters.uplink_bytes, 0, "sequence 1 must wait for 0");

        let mut first = packet(10000, destination, 0);
        first.class = 3;
        first.link = 1;
        first.payload = vec![0];
        ingest(&mut g, &first, 2_000);
        assert_eq!(g.counters.uplink_bytes, 2);

        let mut payload = [0u8; 8];
        assert_eq!(sink.recv_from(&mut payload).unwrap().0, 1);
        assert_eq!(payload[0], 0);
        assert_eq!(sink.recv_from(&mut payload).unwrap().0, 1);
        assert_eq!(payload[0], 1);
    }

    #[test]
    fn global_reorder_memory_is_bounded_and_released_on_session_close() {
        let (mut g, sink) = setup();
        let destination = sink.local_addr().unwrap().port();
        for stream in 0..32u16 {
            for seq in 1..=64 {
                let mut p = packet(10000 + stream, destination, seq);
                p.payload = vec![42; 16384];
                ingest(&mut g, &p, 0); // Missing sequence 0 forces buffering.
            }
        }
        assert_eq!(g.buffered_bytes, MAX_BUFFERED_BYTES);
        ingest(&mut g, &packet(15000, destination, 1), 0);
        assert_eq!(g.counters.buffer_rejections, 1);
        assert_eq!(g.buffered_bytes, MAX_BUFFERED_BYTES);
        g.forget(1);
        assert_eq!(g.buffered_bytes, 0);
        assert!(g.streams.is_empty());
    }
}
