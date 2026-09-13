use std::io;
use verz_link_core::{ACK, NACK, Packet, encode_nack, transport::WanWriter};
use verz_link_lab::{
    bond::{Frame, Kind, MAX_PENDING, Policy, Scheduler},
    udp_lane::{UdpLane, links},
};

#[derive(Default)]
struct Wire {
    packets: Vec<(u8, Vec<u8>)>,
    failed: Option<u8>,
    silent: Option<u8>,
}
impl WanWriter for Wire {
    fn carrier(&self, _id: u8) -> bool {
        true
    }
    fn send(&mut self, id: u8, bytes: &[u8]) -> io::Result<()> {
        if self.failed == Some(id) {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "injected full socket",
            ));
        }
        if self.silent != Some(id) {
            self.packets.push((id, bytes.to_vec()));
        }
        Ok(())
    }
}
fn scheduler() -> Scheduler {
    let mut s = Scheduler::new(
        vec![("wifi".into(), false), ("lan".into(), false)],
        Policy::Smart,
    )
    .unwrap();
    for at in [10, 20, 30] {
        for id in 0..2 {
            s.receive(&Frame::control(Kind::Pong, id, 0, at - 5), at);
        }
    }
    s
}
fn lane() -> UdpLane {
    UdpLane::new(&[42; 32], &[17; 16], Policy::Smart).unwrap()
}

#[test]
fn fragmented_stream_tolerates_one_delayed_copy_without_poisoning_recovery() {
    // The proxy reference orders datagrams. This adapter orders IP fragments:
    // 45 SRT datagrams become 90 entries, even though only 45 ms elapsed.
    // Model a delayed first Wi-Fi copy at LAN removal, not an all-links outage.
    let mut tx = lane();
    let mut rx = lane();
    let mut wire = Wire::default();
    let paths = links(&scheduler(), 30);
    let mut packets = Vec::new();
    let mut paths = paths;
    paths[0].rtt = 45.0;
    paths[0].jitter = 10.0;
    paths[1].rtt = 5.0;
    paths[1].jitter = 1.0;
    for n in 0..45 {
        wire.packets.clear();
        for offset in [0x2000, 157] {
            tx.send(
                &ip(50000, n, offset),
                &paths,
                Policy::Continuity,
                100 + n as u64,
                &mut wire,
            )
            .unwrap();
        }
        // Only the surviving Wi-Fi lane arrives; LAN copies are absent.
        for (path, bytes) in &wire.packets {
            if *path == 0 {
                packets.push(tx.decode(bytes).unwrap());
            }
        }
    }
    packets.sort_by_key(|p| p.sequence);
    assert_eq!(packets.len(), 90);
    let delayed = packets.remove(0);
    let mut rejected = 0;
    for p in &packets {
        if rx
            .receive(p.clone(), 100 + u64::from(p.sequence) / 2)
            .is_err()
        {
            rejected += 1;
        }
    }
    rx.receive(delayed, 145).unwrap();
    for now in 145..350 {
        rx.tick(now);
    }
    let before_retry = rx.counters.delivered_packets;
    // Retransmission/copy identity must remain eligible after a refused insert.
    for p in packets {
        let _ = rx.receive(p, 350);
    }
    for now in 350..600 {
        rx.tick(now);
    }
    eprintln!(
        "short-jitter fragment audit: rejects={rejected}, delivered before retry={before_retry}, after retry={}",
        rx.counters.delivered_packets
    );
    assert_eq!(
        rejected, 0,
        "fragmentation exhausted the reference's datagram-sized admission bound"
    );
    assert_eq!(
        rx.counters.delivered_packets, 90,
        "a short reorder event lost fragments"
    );
}
fn ip(port: u16, id: u16, offset: u16) -> Vec<u8> {
    let mut p = vec![0; if offset & 0x1fff == 0 { 1276 } else { 104 }];
    p[0] = 0x45;
    let len = p.len() as u16;
    p[2..4].copy_from_slice(&len.to_be_bytes());
    p[4..6].copy_from_slice(&id.to_be_bytes());
    p[6..8].copy_from_slice(&offset.to_be_bytes());
    p[9] = 17;
    p[12..16].copy_from_slice(&[10, 78, 0, 2]);
    p[16..20].copy_from_slice(&[1, 1, 1, 1]);
    p[20..22].copy_from_slice(&port.to_be_bytes());
    p[22..24].copy_from_slice(&9000u16.to_be_bytes());
    p
}

#[test]
fn udp_continues_with_all_tcp_windows_and_queues_full_without_any_acks() {
    for failed in [0, 1] {
        let mut s = scheduler();
        // Deliberately reproduce the old failure mechanism: global queue full,
        // preferred and backup cwnds full, and no UDP ACK ever delivered.
        for _ in 0..MAX_PENDING {
            let mut p = ip(100, 0, 0);
            p[9] = 6;
            s.enqueue(p);
        }
        for p in &mut s.paths {
            p.in_flight = p.congestion_window;
        }
        let before = s.pending_packets();
        let paths = links(&s, 30);
        let (mut tx, mut rx) = (lane(), lane());
        let mut wire = Wire::default();
        let mut last = None;
        let mut max_gap = 0;
        for at in 0..12_000u64 {
            // Failure initially reports successful socket writes. Later the
            // socket errors, then reappears. Neither resets session or flows.
            wire.silent = (2000..6000).contains(&at).then_some(failed);
            wire.failed = (6000..10_000).contains(&at).then_some(failed);
            for offset in [0x2000, 157] {
                tx.send(
                    &ip(50000, at as u16, offset),
                    &paths,
                    Policy::Smart,
                    at,
                    &mut wire,
                )
                .unwrap();
            }
            for (_, bytes) in wire.packets.drain(..) {
                rx.receive(rx.decode(&bytes).unwrap(), at).unwrap();
            }
            rx.tick(at);
            let mut count = 0;
            while rx.pop().is_some() {
                count += 1;
            }
            assert_eq!(
                count, 2,
                "missing IP fragment at {at}, failed path {failed}"
            );
            if let Some(last) = last {
                max_gap = max_gap.max(at - last);
            }
            last = Some(at);
        }
        assert_eq!(max_gap, 1);
        assert_eq!(tx.counters.sent_packets, 24_000);
        assert_eq!(rx.counters.delivered_packets, 24_000);
        assert_eq!(
            s.pending_packets(),
            before,
            "UDP modified TCP pending state"
        );
        assert_eq!(tx.counters.send_failures, 0);
    }
}

#[test]
fn explicit_nack_recovers_cached_identity_over_alternate_socket() {
    let paths = links(&scheduler(), 30);
    let mut tx = lane();
    let mut wire = Wire::default();
    tx.send(&ip(50000, 1, 0), &paths, Policy::Smart, 40, &mut wire)
        .unwrap();
    let original = tx.decode(&wire.packets[0].1).unwrap();
    wire.packets.clear();
    let nack = Packet {
        flags: NACK,
        session: 1,
        local_port: original.local_port,
        payload: encode_nack(&[original.sequence]).unwrap(),
        ..Packet::default()
    };
    wire.failed = Some(original.link);
    tx.control(&tx.encode(&nack).unwrap(), &paths, &mut wire)
        .unwrap();
    assert_eq!(wire.packets.len(), 1);
    let recovered = tx.decode(&wire.packets[0].1).unwrap();
    assert_ne!(recovered.link, original.link);
    assert_eq!(recovered.sequence, original.sequence);
    assert_eq!(recovered.local_port, original.local_port);
    assert_eq!(recovered.payload, original.payload);
    assert_eq!(tx.counters.repairs, 1);
    let ack = Packet {
        flags: ACK,
        session: 1,
        local_port: original.local_port,
        sequence: original.sequence,
        ..Packet::default()
    };
    tx.control(&tx.encode(&ack).unwrap(), &paths, &mut wire)
        .unwrap();
    wire.packets.clear();
    tx.control(&tx.encode(&nack).unwrap(), &paths, &mut wire)
        .unwrap();
    assert!(wire.packets.is_empty());
}

#[test]
fn refused_copy_is_not_marked_delivered_and_can_retry_after_gap_fill() {
    let mut rx = lane();
    let make = |sequence| Packet {
        flags: verz_link_core::FEC | verz_link_core::TUN,
        class: 4,
        session: 1,
        local_port: 1,
        sequence,
        protocol: 17,
        timestamp_us: sequence as i64 + 1,
        payload: ip(50000, sequence as u16, 0),
        ..Packet::default()
    };
    for seq in 1..=128 {
        rx.receive(make(seq), 1).unwrap();
    }
    assert!(rx.receive(make(129), 1).is_err());
    assert_eq!(rx.counters.reassembly_rejections, 1);
    rx.receive(make(0), 2).unwrap();
    assert_eq!(rx.counters.delivered_packets, 129);
    while rx.pop().is_some() {}
    rx.receive(make(129), 3).unwrap();
    assert_eq!(rx.counters.delivered_packets, 130);
    assert_eq!(
        rx.counters.duplicate_packets, 0,
        "refusal poisoned retry eligibility"
    );
    rx.receive(make(129), 4).unwrap();
    assert_eq!(rx.counters.delivered_packets, 130, "retry delivered twice");
}

#[test]
fn flows_and_fragment_ids_survive_mode_changes_and_path_return() {
    let mut tx = lane();
    let paths = links(&scheduler(), 30);
    let mut wire = Wire::default();
    for (n, policy) in [
        Policy::Smart,
        Policy::Continuity,
        Policy::Performance,
        Policy::DataSaver,
    ]
    .into_iter()
    .enumerate()
    {
        wire.packets.clear();
        tx.send(
            &ip(50000, n as u16, 0x2000),
            &paths,
            policy,
            40 + n as u64,
            &mut wire,
        )
        .unwrap();
        let head = tx.decode(&wire.packets[0].1).unwrap();
        wire.packets.clear();
        tx.send(
            &ip(50000, n as u16, 157),
            &paths,
            policy,
            40 + n as u64,
            &mut wire,
        )
        .unwrap();
        let tail = tx.decode(&wire.packets[0].1).unwrap();
        assert_eq!(head.local_port, 1);
        assert_eq!(tail.local_port, 1);
        assert_eq!(head.sequence, n as u32 * 2);
        assert_eq!(tail.sequence, head.sequence + 1);
    }
    wire.packets.clear();
    tx.send(&ip(50001, 30, 0), &paths, Policy::Smart, 100, &mut wire)
        .unwrap();
    let other = tx.decode(&wire.packets[0].1).unwrap();
    assert_ne!(other.local_port, 1);
    assert_eq!(other.sequence, 0);
}

#[test]
fn reject_tcp_and_wrong_session_key_and_bound_receive_memory() {
    let mut tx = lane();
    let mut rx = lane();
    let paths = links(&scheduler(), 30);
    let mut wire = Wire::default();
    let mut tcp = ip(50000, 0, 0);
    tcp[9] = 6;
    assert!(tx.send(&tcp, &paths, Policy::Smart, 30, &mut wire).is_err());
    for n in 0..2000 {
        tx.send(&ip(50000, n, 0), &paths, Policy::Smart, n as u64, &mut wire)
            .unwrap();
    }
    let wrong = UdpLane::new(&[42; 32], &[18; 16], Policy::Smart).unwrap();
    assert!(wrong.decode(&wire.packets[0].1).is_err());
    for (_, bytes) in wire.packets {
        rx.receive(rx.decode(&bytes).unwrap(), 2000).unwrap();
    }
    assert!(rx.counters.receive_backpressure > 0);
    let mut count = 0;
    while rx.pop().is_some() {
        count += 1;
    }
    assert!(count <= 1024);
}
