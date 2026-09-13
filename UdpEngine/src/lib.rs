//! Single-owner engine, called only from the provider's serial queue. No TUN or route changes.
mod gateway;
#[cfg(test)]
mod native_test;
mod reassembly;
pub mod secure;
mod wan;
use secure::SecureSockets as Sockets;
use serde::Deserialize;
use std::{
    collections::{BTreeMap, VecDeque},
    net::{Ipv4Addr, SocketAddr},
    time::{Instant, SystemTime, UNIX_EPOCH},
};
use verz_link_core::{
    ACK, DOWNLINK, HEARTBEAT, NACK, Packet,
    recovery::Deduper,
    scheduler::{Config, Link},
    transport::{Sender, WanWriter},
};

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
        })
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
                capacity: 0.0,
                uptime: 1.0,
            })
            .collect()
    }
    fn send(&mut self, port: u16, ip: [u8; 4], remote: u16, payload: &[u8]) -> Result<(), String> {
        let p = Packet {
            class: 4,
            local_port: port,
            destination: ip,
            destination_port: remote,
            timestamp_us: stamp(),
            payload: payload.to_vec(),
            ..Default::default()
        };
        let links = self.links();
        let sent = self
            .sender
            .forward(p.clone(), &links, &mut self.sockets)
            .map_err(|e| {
                self.errors += 1;
                e.to_string()
            })?;
        if self.mode == 2 {
            // Redundancy mode sends a copy immediately, rather than waiting for failure detection.
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
        if self.heartbeat.elapsed().as_millis() >= 100 {
            self.heartbeat = Instant::now();
            self.probe = self.probe.wrapping_add(1);
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
                ACK | NACK => {
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
    let value = serde_json::json!({"upload":e.upload,"download":e.download,"errors":e.errors,"wire":e.sockets.bytes,"paths":e.links(),"mode":e.mode,"adapters":e.paths.iter().map(|(id,p)|(id.to_string(),p.adapter.name.clone())).collect::<BTreeMap<_,_>>()});
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
    if e.is_null() || !(0..=3).contains(&mode) {
        return;
    }
    let e = unsafe { &mut *e };
    e.mode = mode;
    e.sender.set_config(Config {
        bond_all: mode == 1,
        fec: mode != 3,
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
        for sequence in 0..12u8 {
            if sequence == 3 {
                e.adapters(vec![adapter(1), adapter(3)]).unwrap();
            }
            if sequence == 6 {
                e.adapters(vec![adapter(1), adapter(2), adapter(3)])
                    .unwrap();
            }
            // Change policy without resetting stream sequence or stable server egress.
            unsafe { verz_mode(&mut e, (sequence % 3) as i32) };
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
        assert_eq!(g.counters()["udp"]["uplink_bytes"], 12);
        assert_eq!(e.download, 12);
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
