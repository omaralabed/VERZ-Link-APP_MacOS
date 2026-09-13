//! Multi-client IPv4 tunnel transport. Noise provides authenticated ephemeral
//! key exchange; every connection has fresh directional keys and a replay window.
use anyhow::{Context, Result, bail, ensure};
use snow::{Builder, HandshakeState, StatelessTransportState};

use crate::ReplayWindow;

pub const MTU: usize = 1280;
pub const HEADER: usize = 29;
// A multipath frame wraps a full inner IP packet. Keep that framing budget
// separate from the legacy tunnel's IP MTU; every transport enforces its own
// authenticated protocol's payload limit in both directions.
pub const MAX_PAYLOAD: usize = MTU + 96;
pub const MAX_WIRE: usize = HEADER + 1 + MAX_PAYLOAD + 16;
pub const HELLO: u8 = 1;
pub const WELCOME: u8 = 2;
pub const TRANSPORT: u8 = 3;
pub const IP: u8 = 1;
pub const PING: u8 = 2;
pub const PONG: u8 = 3;
pub const CLOSE: u8 = 4;
pub const CLIENT_IP: [u8; 4] = [10, 77, 0, 2];
pub const SERVER_IP: [u8; 4] = [10, 77, 0, 1];

pub fn allocate_client_ip(used: impl Iterator<Item = [u8; 4]>) -> Option<[u8; 4]> {
    let mut occupied = [false; 256];
    for ip in used {
        if ip[..3] == [10, 77, 0] {
            occupied[ip[3] as usize] = true;
        }
    }
    (2..=254)
        .find(|&last| !occupied[last as usize])
        .map(|last| [10, 77, 0, last])
}

/// Allow this client's private server endpoint and public internet addresses;
/// deny loopback, metadata/link-local, LAN, multicast, and special-use targets.
pub fn internet_destination_allowed(packet: &[u8]) -> bool {
    if packet.len() < 20 {
        return false;
    }
    let octets: [u8; 4] = packet[16..20].try_into().expect("four bytes");
    if octets == SERVER_IP {
        return true;
    }
    let ip = std::net::Ipv4Addr::from(octets);
    !ip.is_private()
        && !ip.is_loopback()
        && !ip.is_link_local()
        && !ip.is_multicast()
        && !ip.is_broadcast()
        && !ip.is_unspecified()
        && !ip.is_documentation()
        && octets[0] != 0
        && octets[0] < 224
        && !(octets[0] == 100 && (64..=127).contains(&octets[1]))
        && !(octets[0] == 198 && (18..=19).contains(&octets[1]))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Header {
    pub kind: u8,
    pub session: [u8; 16],
    pub counter: u64,
}

impl Header {
    pub fn parse(packet: &[u8]) -> Result<Self> {
        ensure!(
            (HEADER..=MAX_WIRE).contains(&packet.len()),
            "invalid wire length"
        );
        ensure!(&packet[..4] == b"VZT2", "wrong tunnel protocol");
        ensure!(
            (HELLO..=TRANSPORT).contains(&packet[4]),
            "invalid wire type"
        );
        Ok(Self {
            kind: packet[4],
            session: packet[5..21].try_into()?,
            counter: u64::from_be_bytes(packet[21..29].try_into()?),
        })
    }

    pub fn wrap(self, body: &[u8]) -> Vec<u8> {
        let mut packet = Vec::with_capacity(HEADER + body.len());
        packet.extend_from_slice(b"VZT2");
        packet.push(self.kind);
        packet.extend_from_slice(&self.session);
        packet.extend_from_slice(&self.counter.to_be_bytes());
        packet.extend_from_slice(body);
        packet
    }
}

pub fn handshake(secret: &[u8; 32], session: &[u8; 16], initiator: bool) -> Result<HandshakeState> {
    let mut prologue =
        b"VERZ IPv4 tunnel v2 / MTU1280 / authenticated lease 10.77.0.0-24 / ".to_vec();
    prologue.extend_from_slice(session);
    let builder = Builder::new("Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s".parse()?)
        .psk(0, secret)?
        .prologue(&prologue)?;
    Ok(if initiator {
        builder.build_initiator()?
    } else {
        builder.build_responder()?
    })
}

pub struct Transport {
    pub session: [u8; 16],
    max_payload: usize,
    noise: StatelessTransportState,
    tx_counter: u64,
    replay: ReplayWindow,
}

impl Transport {
    pub fn new(session: [u8; 16], noise: HandshakeState) -> Result<Self> {
        Self::with_payload_limit(session, noise, MTU)
    }

    pub fn with_payload_limit(
        session: [u8; 16],
        noise: HandshakeState,
        max_payload: usize,
    ) -> Result<Self> {
        ensure!(
            (1..=MAX_PAYLOAD).contains(&max_payload),
            "invalid payload limit"
        );
        Ok(Self {
            session,
            max_payload,
            noise: noise.into_stateless_transport_mode()?,
            tx_counter: 0,
            replay: ReplayWindow::new(8192),
        })
    }

    pub fn seal(&mut self, kind: u8, payload: &[u8]) -> Result<Vec<u8>> {
        ensure!((IP..=CLOSE).contains(&kind), "invalid encrypted type");
        ensure!(
            payload.len() <= self.max_payload,
            "payload exceeds transport limit"
        );
        ensure!(
            kind == IP || payload.is_empty(),
            "control payload must be empty"
        );
        let counter = self.tx_counter;
        self.tx_counter = counter.checked_add(1).context("nonce exhausted")?;
        let mut plaintext = Vec::with_capacity(1 + payload.len());
        plaintext.push(kind);
        plaintext.extend_from_slice(payload);
        let mut ciphertext = [0; MAX_PAYLOAD + 17];
        let len = self
            .noise
            .write_message(counter, &plaintext, &mut ciphertext)?;
        Ok(Header {
            kind: TRANSPORT,
            session: self.session,
            counter,
        }
        .wrap(&ciphertext[..len]))
    }

    pub fn open(&mut self, packet: &[u8]) -> Result<(u8, Vec<u8>)> {
        let header = Header::parse(packet)?;
        ensure!(
            packet.len() <= HEADER + 1 + self.max_payload + 16,
            "payload exceeds transport limit"
        );
        ensure!(
            header.kind == TRANSPORT && header.session == self.session,
            "wrong transport session"
        );
        ensure!(
            !self.replay.contains(header.counter),
            "replayed transport packet"
        );
        let mut plaintext = [0; MAX_PAYLOAD + 17];
        let len = self
            .noise
            .read_message(header.counter, &packet[HEADER..], &mut plaintext)?;
        ensure!(
            len >= 1 && (IP..=CLOSE).contains(&plaintext[0]),
            "invalid encrypted type"
        );
        ensure!(plaintext[0] == IP || len == 1, "invalid control body");
        self.replay.mark(header.counter);
        Ok((plaintext[0], plaintext[1..len].to_vec()))
    }
}

pub fn validate_ipv4(
    packet: &[u8],
    source: Option<[u8; 4]>,
    destination: Option<[u8; 4]>,
) -> Result<()> {
    ensure!((20..=MTU).contains(&packet.len()), "invalid IPv4 length");
    ensure!(packet[0] >> 4 == 4, "IPv4 only");
    let header_len = (packet[0] as usize & 15) * 4;
    ensure!(
        header_len >= 20 && header_len <= packet.len(),
        "invalid IPv4 header"
    );
    ensure!(
        u16::from_be_bytes([packet[2], packet[3]]) as usize == packet.len(),
        "IPv4 length mismatch"
    );
    if source.is_some_and(|address| packet[12..16] != address) {
        bail!("source address outside authenticated client assignment");
    }
    if destination.is_some_and(|address| packet[16..20] != address) {
        bail!("destination outside tunnel assignment");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unique_leases_reuse_only_free_addresses() {
        assert_eq!(allocate_client_ip([].into_iter()), Some([10, 77, 0, 2]));
        assert_eq!(
            allocate_client_ip([[10, 77, 0, 2], [10, 77, 0, 3]].into_iter()),
            Some([10, 77, 0, 4])
        );
        assert_eq!(allocate_client_ip((2..=254).map(|n| [10, 77, 0, n])), None);
        assert_eq!(
            allocate_client_ip([[10, 77, 0, 3]].into_iter()),
            Some([10, 77, 0, 2])
        );
    }

    #[test]
    fn internet_policy_blocks_private_metadata_and_other_clients() {
        let mut packet = [0; 20];
        for address in [[1, 1, 1, 1], [8, 8, 8, 8], SERVER_IP] {
            packet[16..20].copy_from_slice(&address);
            assert!(internet_destination_allowed(&packet));
        }
        for address in [
            [169, 254, 169, 254],
            [10, 77, 0, 3],
            [127, 0, 0, 1],
            [192, 168, 1, 1],
            [224, 0, 0, 1],
            [100, 64, 0, 1],
            [0, 0, 0, 0],
            [255, 255, 255, 255],
        ] {
            packet[16..20].copy_from_slice(&address);
            assert!(!internet_destination_allowed(&packet));
        }
    }

    fn pair() -> (Transport, Transport) {
        pair_for_session(rand::random())
    }

    fn pair_for_session(session: [u8; 16]) -> (Transport, Transport) {
        let secret = [41; 32];
        let mut client = handshake(&secret, &session, true).unwrap();
        let mut server = handshake(&secret, &session, false).unwrap();
        let mut buf = [0; 256];
        let mut plain = [0; 256];
        let len = client.write_message(&[], &mut buf).unwrap();
        server.read_message(&buf[..len], &mut plain).unwrap();
        let len = server.write_message(&[], &mut buf).unwrap();
        client.read_message(&buf[..len], &mut plain).unwrap();
        (
            Transport::new(session, client).unwrap(),
            Transport::new(session, server).unwrap(),
        )
    }

    #[test]
    fn bidirectional_packets_tamper_and_replay() {
        let (mut client, mut server) = pair();
        let first = client.seal(IP, b"first IP packet").unwrap();
        let second = client.seal(IP, b"second IP packet").unwrap();
        assert_eq!(server.open(&second).unwrap().1, b"second IP packet");
        assert_eq!(server.open(&first).unwrap().1, b"first IP packet");
        assert!(server.open(&first).is_err());
        let good = server.seal(IP, b"server response").unwrap();
        let mut bad = good.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert!(client.open(&bad).is_err());
        assert_eq!(client.open(&good).unwrap().1, b"server response");
    }

    #[test]
    fn incorrect_key_and_wrong_session_rejected() {
        let session = [1; 16];
        let mut client = handshake(&[1; 32], &session, true).unwrap();
        let mut server = handshake(&[2; 32], &session, false).unwrap();
        let mut packet = [0; 256];
        let len = client.write_message(&[], &mut packet).unwrap();
        assert!(server.read_message(&packet[..len], &mut [0; 256]).is_err());
        let (mut client, mut server) = pair();
        let mut packet = client.seal(PING, &[]).unwrap();
        packet[5] ^= 1;
        assert!(server.open(&packet).is_err());
    }

    #[test]
    fn fresh_handshake_rejects_previous_connection_ciphertext() {
        // Even an accidentally repeated connection ID must not reuse Noise keys.
        let (mut client1, _) = pair_for_session([13; 16]);
        let (_, mut server2) = pair_for_session([13; 16]);
        let packet = client1.seal(IP, b"old connection").unwrap();
        assert!(server2.open(&packet).is_err());
    }

    #[test]
    fn changed_nonce_and_truncated_datagrams_are_rejected_without_consuming_window() {
        let (mut client, mut server) = pair();
        let packet = client.seal(PING, &[]).unwrap();
        let mut altered = packet.clone();
        altered[28] ^= 1;
        assert!(server.open(&altered).is_err());
        for len in 0..packet.len() {
            assert!(server.open(&packet[..len]).is_err());
        }
        assert_eq!(server.open(&packet).unwrap().0, PING);
    }

    #[test]
    fn rejects_spoofed_source_and_malformed_ip() {
        let mut ip = [0; 20];
        ip[0] = 0x45;
        ip[3] = 20;
        ip[12..16].copy_from_slice(&CLIENT_IP);
        ip[16..20].copy_from_slice(&SERVER_IP);
        assert!(validate_ipv4(&ip, Some(CLIENT_IP), Some(SERVER_IP)).is_ok());
        ip[12] = 127;
        assert!(validate_ipv4(&ip, Some(CLIENT_IP), None).is_err());
        assert!(validate_ipv4(&ip[..10], None, None).is_err());
    }
}
