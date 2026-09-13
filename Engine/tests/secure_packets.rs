//! Real Noise/framing/scheduler round trips. These packet-level checks are not
//! a substitute for native OBS/VLC, browser QUIC, or physical WAN-cut tests.
use anyhow::Result;
use verz_link_lab::{
    bond::{self, BOND_MTU, Frame, Kind, Policy, Scheduler},
    tunnel::{self, HEADER, IP, Transport},
};

fn pair() -> Result<(Transport, Transport)> {
    let session = [27; 16];
    let secret = [91; 32];
    let mut client = bond::handshake(&secret, &session, true)?;
    let mut server = bond::handshake(&secret, &session, false)?;
    let mut wire = [0; 256];
    let mut plain = [0; 256];
    let len = client.write_message(&[], &mut wire)?;
    server.read_message(&wire[..len], &mut plain)?;
    let len = server.write_message(&[], &mut wire)?;
    client.read_message(&wire[..len], &mut plain)?;
    Ok((
        bond::transport(session, client)?,
        bond::transport(session, server)?,
    ))
}

fn packet(protocol: u8, size: usize) -> Vec<u8> {
    let mut ip = vec![0xa5; size];
    ip[..40.min(size)].fill(0);
    ip[0] = 0x45;
    ip[2..4].copy_from_slice(&(size as u16).to_be_bytes());
    ip[8] = 64;
    ip[9] = protocol;
    ip[12..16].copy_from_slice(&[10, 78, 0, 2]);
    ip[16..20].copy_from_slice(&[1, 1, 1, 1]);
    ip[20..22].copy_from_slice(&50000_u16.to_be_bytes());
    ip[22..24].copy_from_slice(&443_u16.to_be_bytes());
    if protocol == 17 {
        ip[24..26].copy_from_slice(&((size - 20) as u16).to_be_bytes());
    } else {
        ip[32] = 0x50;
        ip[33] = 0x18;
    }
    ip
}

fn ready() -> Scheduler {
    let mut scheduler = Scheduler::new(vec![("test-uplink".into(), false)], Policy::Smart).unwrap();
    for now in [10, 20, 30] {
        scheduler.receive(&Frame::control(Kind::Pong, 0, now, now - 5), now);
    }
    scheduler
}

#[test]
fn full_mtu_tcp_and_quic_sized_udp_survive_encryption_both_directions() -> Result<()> {
    // QUIC's 1,200-byte minimum is UDP payload, not total IP length.
    for (protocol, size) in [(6, BOND_MTU), (17, 1200 + 28), (17, BOND_MTU), (17, 200)] {
        let (mut client, mut server) = pair()?;
        for reverse in [false, true] {
            let mut original = packet(protocol, size);
            if reverse {
                original[12..16].copy_from_slice(&[1, 1, 1, 1]);
                original[16..20].copy_from_slice(&[10, 78, 0, 2]);
            }
            tunnel::validate_ipv4(&original, None, None)?;
            let mut tx = ready();
            let mut rx = ready();
            tx.enqueue(original.clone());
            let frame = tx
                .tick(31)
                .into_iter()
                .find(|f| f.kind == Kind::Data)
                .unwrap();
            let (sender, receiver) = if reverse {
                (&mut server, &mut client)
            } else {
                (&mut client, &mut server)
            };
            let wire = sender.seal(IP, &frame.encode())?;
            assert!(wire.len() <= tunnel::MAX_WIRE);
            assert!(
                wire.len() + 28 <= 1500,
                "outer IPv4/UDP needs an explicit MTU budget"
            );
            assert_eq!(wire.len(), HEADER + 1 + 18 + original.len() + 16);
            let decoded = Frame::decode(&receiver.open(&wire)?.1)?;
            let (delivered, replies) = rx.receive(&decoded, 36);
            assert_eq!(delivered.as_deref(), Some(original.as_slice()));
            for reply in replies {
                let ack = receiver.seal(IP, &reply.encode())?;
                let decoded_ack = Frame::decode(&sender.open(&ack)?.1)?;
                tx.receive(&decoded_ack, 41);
            }
            assert_eq!(tx.pending_packets(), 0);
            assert!(
                receiver.open(&wire).is_err(),
                "ciphertext replay must still be rejected"
            );
        }
    }
    Ok(())
}

#[test]
fn oversized_frames_are_rejected_without_truncation() -> Result<()> {
    let (mut tx, _) = pair()?;
    let mut oversized = Frame {
        kind: Kind::Data,
        path: 0,
        id: 0,
        stamp: 0,
        body: packet(17, BOND_MTU + 1),
    };
    assert!(Frame::decode(&oversized.encode()).is_err());
    // The authenticated envelope now also fits the repo UDP header. Data's
    // own MTU is still enforced by Frame::decode, not the outer AEAD size.
    assert!(Frame::decode(&oversized.encode()).is_err());
    oversized
        .body
        .resize(BOND_MTU + verz_link_lab::bond::UDP_ENVELOPE + 1, 0);
    assert!(tx.seal(IP, &oversized.encode()).is_err());
    let mut scheduler = ready();
    scheduler.enqueue(oversized.body);
    assert_eq!(scheduler.counters.queue_drops, 1);
    assert!(!scheduler.tick(31).iter().any(|f| f.kind == Kind::Data));
    Ok(())
}

#[test]
fn larger_udp_datagram_fragments_survive_without_payload_changes() -> Result<()> {
    // IPv4 UDP applications may emit datagrams larger than the utun MTU.
    // Exercise kernel-shaped fragments, including a short non-UDP-header tail.
    // This is packet preservation, not a claim to implement SRT itself.
    let original = packet(17, 1428);
    let chunk = ((BOND_MTU - 20) / 8) * 8;
    let mut fragments = Vec::new();
    for (index, body) in original[20..].chunks(chunk).enumerate() {
        let mut fragment = original[..20].to_vec();
        fragment.extend_from_slice(body);
        let size = fragment.len() as u16;
        fragment[2..4].copy_from_slice(&size.to_be_bytes());
        fragment[4..6].copy_from_slice(&42_u16.to_be_bytes());
        let more = (index + 1) * chunk < original.len() - 20;
        let flags_offset = ((index * chunk / 8) as u16) | if more { 0x2000 } else { 0 };
        fragment[6..8].copy_from_slice(&flags_offset.to_be_bytes());
        tunnel::validate_ipv4(&fragment, None, None)?;
        fragments.push(fragment);
    }
    let (mut client, mut server) = pair()?;
    let mut tx = ready();
    let mut rx = ready();
    for fragment in &fragments {
        tx.enqueue(fragment.clone());
    }
    let frames: Vec<_> = (31..40)
        .flat_map(|now| tx.tick(now))
        .filter(|frame| frame.kind == Kind::Data)
        .collect();
    assert_eq!(frames.len(), fragments.len());
    let mut payload = Vec::new();
    for (frame, original_fragment) in frames.iter().zip(&fragments) {
        let wire = client.seal(IP, &frame.encode())?;
        let decoded = Frame::decode(&server.open(&wire)?.1)?;
        let delivered = rx.receive(&decoded, 40).0.unwrap();
        assert_eq!(delivered, *original_fragment);
        payload.extend_from_slice(&delivered[20..]);
    }
    assert_eq!(payload, original[20..]);
    Ok(())
}

#[test]
fn legacy_transport_keeps_its_original_payload_limit() -> Result<()> {
    // Enlarging the shared receive allocation must not enlarge legacy V2's
    // accepted payload. Nor may the scheduler framing budget disappear again.
    let session = [31; 16];
    let mut a = tunnel::handshake(&[9; 32], &session, true)?;
    let mut b = tunnel::handshake(&[9; 32], &session, false)?;
    let mut buf = [0; 256];
    let mut plain = [0; 256];
    let n = a.write_message(&[], &mut buf)?;
    b.read_message(&buf[..n], &mut plain)?;
    let n = b.write_message(&[], &mut buf)?;
    a.read_message(&buf[..n], &mut plain)?;
    let mut larger = Transport::with_payload_limit(session, a, tunnel::MTU + 18)?;
    let mut legacy = Transport::new(session, b)?;
    assert!(legacy.seal(IP, &vec![0; tunnel::MTU + 1]).is_err());
    let oversized = larger.seal(IP, &vec![0; tunnel::MTU + 1])?;
    assert!(legacy.open(&oversized).is_err());
    let valid = larger.seal(IP, &vec![7; tunnel::MTU])?;
    assert_eq!(legacy.open(&valid)?.1, vec![7; tunnel::MTU]);
    Ok(())
}
