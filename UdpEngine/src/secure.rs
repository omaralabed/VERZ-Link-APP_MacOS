//! Encrypted carrier around the unchanged repository UDP envelope.
//! One Noise session outlives all individual WAN sockets. Plaintext gateway
//! plumbing is loopback-only; public sockets never send bare BDLK packets.
use crate::wan::Sockets;
use sha2::{Digest, Sha256};
use snow::{HandshakeState, StatelessTransportState};
use std::{
    collections::{BTreeSet, HashMap, HashSet},
    io,
    net::{Ipv4Addr, SocketAddr, UdpSocket},
    time::{Duration, Instant},
};
use verz_link_core::{Packet, transport::WanWriter};

const HEADER: usize = 30;
const MAX_CLEAR: usize = verz_link_core::HEADER + verz_link_core::MAX_PAYLOAD + verz_link_core::TAG;
const MAX_WIRE: usize = HEADER + 1 + MAX_CLEAR + 16;
const HELLO: u8 = 1;
const WELCOME: u8 = 2;
const DATA: u8 = 3;

fn error(message: impl ToString) -> io::Error {
    io::Error::other(message.to_string())
}
fn handshake(key: &str, session: &[u8; 16], initiator: bool) -> io::Result<HandshakeState> {
    if key.len() < 32 {
        return Err(error("UDP encryption key too short"));
    }
    let psk: [u8; 32] = Sha256::digest(key.as_bytes()).into();
    let mut prologue = b"VERZ isolated UDP proxy v1 / ".to_vec();
    prologue.extend_from_slice(session);
    let builder = snow::Builder::new(
        "Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s"
            .parse()
            .map_err(error)?,
    )
    .psk(0, &psk)
    .map_err(error)?
    .prologue(&prologue)
    .map_err(error)?;
    if initiator {
        builder.build_initiator()
    } else {
        builder.build_responder()
    }
    .map_err(error)
}
fn wrap(kind: u8, session: &[u8; 16], path: u8, counter: u64, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER + body.len());
    out.extend_from_slice(b"VZU1");
    out.push(kind);
    out.extend_from_slice(session);
    out.push(path);
    out.extend_from_slice(&counter.to_be_bytes());
    out.extend_from_slice(body);
    out
}
fn header(wire: &[u8]) -> io::Result<(u8, [u8; 16], u8, u64)> {
    if !(HEADER..=MAX_WIRE).contains(&wire.len())
        || &wire[..4] != b"VZU1"
        || !(1..=3).contains(&wire[4])
        || wire[21] == 0
    {
        return Err(error("invalid encrypted UDP header"));
    }
    Ok((
        wire[4],
        wire[5..21].try_into().unwrap(),
        wire[21],
        u64::from_be_bytes(wire[22..30].try_into().unwrap()),
    ))
}
struct Cipher {
    noise: StatelessTransportState,
    session: [u8; 16],
    tx: u64,
    highest: u64,
    seen: HashSet<u64>,
}
impl Cipher {
    fn new(noise: HandshakeState, session: [u8; 16]) -> io::Result<Self> {
        Ok(Self {
            noise: noise.into_stateless_transport_mode().map_err(error)?,
            session,
            tx: 0,
            highest: 0,
            seen: HashSet::new(),
        })
    }
    fn seal(&mut self, path: u8, packet: &[u8]) -> io::Result<Vec<u8>> {
        if packet.len() > MAX_CLEAR || path == 0 {
            return Err(error("UDP carrier payload limit"));
        }
        let counter = self.tx;
        self.tx = self
            .tx
            .checked_add(1)
            .ok_or_else(|| error("nonce exhausted"))?;
        let mut plain = Vec::with_capacity(packet.len() + 1);
        plain.push(path);
        plain.extend_from_slice(packet);
        let mut encrypted = vec![0; plain.len() + 16];
        let n = self
            .noise
            .write_message(counter, &plain, &mut encrypted)
            .map_err(error)?;
        Ok(wrap(DATA, &self.session, path, counter, &encrypted[..n]))
    }
    fn open(&mut self, wire: &[u8]) -> io::Result<(u8, Vec<u8>)> {
        let (kind, session, path, counter) = header(wire)?;
        if kind != DATA
            || session != self.session
            || self.seen.contains(&counter)
            || counter.saturating_add(8192) <= self.highest
        {
            return Err(error("wrong session or replayed UDP packet"));
        }
        let mut plain = vec![0; MAX_CLEAR + 1];
        let n = self
            .noise
            .read_message(counter, &wire[HEADER..], &mut plain)
            .map_err(error)?;
        if n == 0 || plain[0] != path {
            return Err(error("unauthenticated WAN identity"));
        }
        self.highest = self.highest.max(counter);
        self.seen.insert(counter);
        if self.seen.len() > 8192 {
            let floor = self.highest.saturating_sub(8191);
            self.seen.retain(|n| *n >= floor);
        }
        Ok((path, plain[1..n].to_vec()))
    }
}

#[derive(Default, serde::Serialize)]
pub struct WireBytes {
    sent: u64,
    received: u64,
}
pub struct SecureSockets {
    sockets: Sockets,
    session: [u8; 16],
    handshake: Option<HandshakeState>,
    hello: Vec<u8>,
    cipher: Option<Cipher>,
    last_hello: HashMap<u8, Instant>,
    pub bytes: HashMap<u8, WireBytes>,
}
impl SecureSockets {
    pub fn new(key: &str, flow_session: u32) -> io::Result<Self> {
        let session = rand::random();
        let mut hs = handshake(key, &session, true)?;
        let mut hello = vec![0; 256];
        let n = hs
            .write_message(&flow_session.to_be_bytes(), &mut hello)
            .map_err(error)?;
        hello.truncate(n);
        Ok(Self {
            sockets: Sockets::new(),
            session,
            handshake: Some(hs),
            hello,
            cipher: None,
            last_hello: HashMap::new(),
            bytes: HashMap::new(),
        })
    }
    pub fn add(
        &mut self,
        id: u8,
        name: &str,
        address: Ipv4Addr,
        gateway: SocketAddr,
    ) -> io::Result<()> {
        self.sockets.add(id, name, address, gateway)
    }
    pub fn remove(&mut self, id: u8) {
        self.sockets.remove(id);
        self.last_hello.remove(&id);
    }
    pub fn receive(&mut self, mut accept: impl FnMut(u8, &[u8])) -> io::Result<usize> {
        let mut packets = Vec::new();
        // Encrypted framing is larger than the repo's raw receive buffer.
        self.sockets
            .receive_sized(MAX_WIRE + 1, |id, wire| packets.push((id, wire.to_vec())))?;
        let mut count = 0;
        for (id, wire) in packets {
            let Ok((kind, session, path, _)) = header(&wire) else {
                continue;
            };
            if session != self.session || path != id {
                continue;
            }
            if kind == WELCOME && self.cipher.is_none() {
                if let Some(mut hs) = self.handshake.take() {
                    let mut plain = [0; 256];
                    match hs.read_message(&wire[HEADER..], &mut plain) {
                        Ok(0) => {
                            self.cipher = Some(Cipher::new(hs, self.session)?);
                        }
                        _ => {
                            self.handshake = Some(hs);
                        }
                    }
                }
            } else if let Some(cipher) = &mut self.cipher
                && let Ok((_, plain)) = cipher.open(&wire)
            {
                self.bytes.entry(id).or_default().received += wire.len() as u64;
                accept(id, &plain);
                count += 1;
            }
        }
        Ok(count)
    }
}
impl WanWriter for SecureSockets {
    fn carrier(&self, id: u8) -> bool {
        self.sockets.carrier(id)
    }
    fn send(&mut self, id: u8, wire: &[u8]) -> io::Result<()> {
        if let Some(cipher) = &mut self.cipher {
            let encrypted = cipher.seal(id, wire)?;
            self.sockets.send(id, &encrypted)?;
            self.bytes.entry(id).or_default().sent += encrypted.len() as u64;
            return Ok(());
        }
        if self
            .last_hello
            .get(&id)
            .is_none_or(|at| at.elapsed() >= Duration::from_millis(200))
        {
            self.sockets
                .send(id, &wrap(HELLO, &self.session, id, 0, &self.hello))?;
            self.last_hello.insert(id, Instant::now());
        }
        Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "UDP handshake pending",
        ))
    }
}

struct ReturnPath {
    bridge: UdpSocket,
    address: SocketAddr,
    last: Instant,
}
struct Peer {
    cipher: Cipher,
    paths: HashMap<u8, ReturnPath>,
    flow_session: u32,
    hello: Vec<u8>,
    welcome: Vec<u8>,
    last: Instant,
}
pub struct SecureGateway {
    socket: UdpSocket,
    gateway: crate::gateway::Gateway,
    key: String,
    peers: HashMap<[u8; 16], Peer>,
    last_sweep: Instant,
    pub rejected: u64,
}
impl SecureGateway {
    pub fn bind(address: SocketAddr, key: String, allow_private: bool) -> io::Result<Self> {
        if key.len() < 32 || !address.is_ipv4() {
            return Err(error("invalid UDP gateway configuration"));
        }
        let socket = UdpSocket::bind(address)?;
        socket.set_nonblocking(true)?;
        let gateway =
            crate::gateway::Gateway::bind("127.0.0.1:0".parse().unwrap(), vec![], allow_private)?;
        Ok(Self {
            socket,
            gateway,
            key,
            peers: HashMap::new(),
            last_sweep: Instant::now(),
            rejected: 0,
        })
    }
    pub fn address(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }
    pub fn counters(&self) -> serde_json::Value {
        serde_json::json!({"sessions":self.peers.len(),"flows":self.gateway.flow_count(),"udp":self.gateway.counters,"rejected":self.rejected,"limits":self.gateway.limits()})
    }
    fn ingress(&mut self, wire: &[u8], address: SocketAddr) -> io::Result<()> {
        let (kind, session, id, _) = header(wire)?;
        if kind == HELLO {
            if let Some(peer) = self.peers.get(&session) {
                if peer.hello == wire[HEADER..] {
                    self.socket
                        .send_to(&wrap(WELCOME, &session, id, 0, &peer.welcome), address)?;
                }
                return Ok(());
            }
            if self.peers.len() >= 128 {
                return Err(error("UDP session capacity"));
            }
            let mut hs = handshake(&self.key, &session, false)?;
            let mut plain = [0; 256];
            if hs
                .read_message(&wire[HEADER..], &mut plain)
                .map_err(error)?
                != 4
            {
                return Err(error("invalid enrollment"));
            }
            let flow_session = u32::from_be_bytes(plain[..4].try_into().unwrap());
            if flow_session == 0 || self.peers.values().any(|p| p.flow_session == flow_session) {
                return Err(error("duplicate enrollment"));
            }
            let n = hs.write_message(&[], &mut plain).map_err(error)?;
            let welcome = plain[..n].to_vec();
            self.gateway
                .enroll(flow_session, self.key.as_bytes().to_vec())?;
            let peer = Peer {
                cipher: Cipher::new(hs, session)?,
                paths: HashMap::new(),
                flow_session,
                hello: wire[HEADER..].to_vec(),
                welcome,
                last: Instant::now(),
            };
            self.socket
                .send_to(&wrap(WELCOME, &session, id, 0, &peer.welcome), address)?;
            self.peers.insert(session, peer);
            return Ok(());
        }
        let peer = self
            .peers
            .get_mut(&session)
            .ok_or_else(|| error("unknown UDP session"))?;
        let (_, clear) = peer.cipher.open(wire)?;
        let p = Packet::decode(&clear, self.key.as_bytes()).map_err(error)?;
        if p.session != peer.flow_session || p.link != id {
            return Err(error("UDP flow ownership mismatch"));
        }
        if !peer.paths.contains_key(&id) && peer.paths.len() >= 16 {
            return Err(error("UDP WAN capacity"));
        }
        if let std::collections::hash_map::Entry::Vacant(entry) = peer.paths.entry(id) {
            let bridge = UdpSocket::bind("127.0.0.1:0")?;
            bridge.connect(self.gateway.address()?)?;
            bridge.set_nonblocking(true)?;
            entry.insert(ReturnPath {
                bridge,
                address,
                last: Instant::now(),
            });
        }
        let path = peer.paths.get_mut(&id).unwrap();
        path.address = address;
        path.last = Instant::now();
        peer.last = Instant::now();
        path.bridge.send(&clear)?;
        Ok(())
    }
    pub fn step(&mut self) -> io::Result<()> {
        let mut wire = vec![0; MAX_WIRE + 1];
        for _ in 0..256 {
            match self.socket.recv_from(&mut wire) {
                Ok((n, address)) => {
                    if self.ingress(&wire[..n], address).is_err() {
                        self.rejected += 1;
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(e),
            }
        }
        self.gateway.step(0)?;
        for peer in self.peers.values_mut() {
            for (&id, path) in &mut peer.paths {
                for _ in 0..64 {
                    match path.bridge.recv(&mut wire) {
                        Ok(n) => {
                            if path.last.elapsed() < Duration::from_secs(30) {
                                let encrypted = peer.cipher.seal(id, &wire[..n])?;
                                let _ = self.socket.send_to(&encrypted, path.address);
                            }
                        }
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                        Err(_) => break,
                    }
                }
            }
        }
        if self.last_sweep.elapsed() >= Duration::from_secs(5) {
            self.last_sweep = Instant::now();
            let expired: BTreeSet<_> = self
                .peers
                .values()
                .filter(|p| p.last.elapsed() >= Duration::from_secs(120))
                .map(|p| p.flow_session)
                .collect();
            self.peers.retain(|_, p| !expired.contains(&p.flow_session));
            for id in expired {
                self.gateway.forget(id);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn noise_authentication_replay_and_mtu() {
        let session = [8; 16];
        let key = "test-key-0123456789abcdef0123456789abcdef";
        let mut a = handshake(key, &session, true).unwrap();
        let mut b = handshake(key, &session, false).unwrap();
        let mut buf = [0; 256];
        let mut plain = [0; 256];
        let n = a.write_message(&[1, 2, 3, 4], &mut buf).unwrap();
        b.read_message(&buf[..n], &mut plain).unwrap();
        let n = b.write_message(&[], &mut buf).unwrap();
        a.read_message(&buf[..n], &mut plain).unwrap();
        let mut a = Cipher::new(a, session).unwrap();
        let mut b = Cipher::new(b, session).unwrap();
        let clear = vec![42; 1332 + verz_link_core::HEADER + verz_link_core::TAG];
        let wire = a.seal(2, &clear).unwrap();
        assert!(wire.len() + 28 <= 1500);
        let mut bad = wire.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert!(b.open(&bad).is_err());
        let mut bad = wire.clone();
        bad[21] = 1;
        assert!(b.open(&bad).is_err());
        assert_eq!(b.open(&wire).unwrap(), (2, clear));
        assert!(b.open(&wire).is_err());
    }
}
