//! Scheduler-only audit: 1332-byte SRT UDP payload fragmented at the tunnel MTU.
//! Does not model macOS sockets, IP reassembly deadlines, or SRT retransmission.
use std::collections::{BTreeMap, BTreeSet};
use verz_link_lab::bond::{Frame, Kind, Policy, Scheduler};

fn header(len: usize, id: u16, offset: u16) -> Vec<u8> {
    let mut p = vec![0; len];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&(len as u16).to_be_bytes());
    p[4..6].copy_from_slice(&id.to_be_bytes());
    p[6..8].copy_from_slice(&offset.to_be_bytes());
    p[9] = 17;
    p[12..16].copy_from_slice(&[10, 78, 0, 2]);
    p[16..20].copy_from_slice(&[69, 164, 208, 201]);
    if offset & 0x1fff == 0 {
        p[20..22].copy_from_slice(&50000u16.to_be_bytes());
        p[22..24].copy_from_slice(&9000u16.to_be_bytes());
        p[24..26].copy_from_slice(&1340u16.to_be_bytes());
    }
    p
}

#[test]
fn queued_protection_uses_wifi_before_the_repair_timer() {
    let mut tx = Scheduler::new(
        vec![("wifi".into(), false), ("lan".into(), false)],
        Policy::Continuity,
    )
    .unwrap();
    for now in [10, 20, 30] {
        for path in 0..2 {
            tx.receive(&Frame::control(Kind::Pong, path, now, now - 5), now);
        }
    }
    let mut control = header(44, 0, 0);
    control[28] = 0x80;
    tx.enqueue(control);
    for f in tx.tick(32).into_iter().filter(|f| f.kind == Kind::Data) {
        tx.receive(&Frame::control(Kind::Ack, f.path, f.id, f.stamp), 40);
    }
    tx.paths[0].in_flight = tx.paths[0].congestion_window;
    let packet = header(1276, 100, 0x2000);
    tx.enqueue(packet.clone());
    let sent: Vec<_> = tx
        .tick(42)
        .into_iter()
        .filter(|f| f.kind == Kind::Data)
        .collect();
    // The primary must not wait for the backup window.
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].path, 1);
    let first = &sent[0];
    tx.paths[0].in_flight = 0;
    let backup = tx.tick(44);
    assert!(
        backup
            .iter()
            .any(|f| f.kind == Kind::Data && f.path == 0 && f.id == first.id && f.body == packet),
        "backup must not wait for LAN repair timeout"
    );
    assert_eq!(tx.counters.repairs, 0);
}

#[test]
fn audit_fragmented_srt_upload_under_silent_loss_and_rejoin() {
    for policy in [Policy::Smart, Policy::Continuity] {
        for lost in [None, Some(0u8), Some(1u8)] {
            let mut tx =
                Scheduler::new(vec![("wifi".into(), false), ("lan".into(), false)], policy)
                    .unwrap();
            let mut rx =
                Scheduler::new(vec![("wifi".into(), false), ("lan".into(), false)], policy)
                    .unwrap();
            let mut wire: Vec<(u64, bool, Frame)> = Vec::new();
            let mut fragments: BTreeMap<u16, u8> = BTreeMap::new();
            let mut complete = BTreeSet::new();
            let mut copies: BTreeMap<u64, BTreeSet<u8>> = BTreeMap::new();
            let mut last = None;
            let mut max_gap = 0;
            for now in 0..9000u64 {
                if now == 200 {
                    let mut control = header(44, 0, 0);
                    control[28] = 0x80;
                    tx.enqueue(control);
                }
                if now == 4500
                    && let Some(path) = lost
                {
                    let name = if path == 0 { "wifi" } else { "lan" };
                    tx.add_path(name.into(), false).unwrap();
                    rx.add_path(name.into(), false).unwrap();
                }
                if (1000..8000).contains(&now) {
                    // One 1332-byte UDP payload per millisecond: 10.656 Mbps.
                    tx.enqueue(header(1276, now as u16, 0x2000));
                    tx.enqueue(header(104, now as u16, 157));
                }
                if now % 2 == 0 {
                    for (to_receiver, side) in [(true, &mut tx), (false, &mut rx)] {
                        for frame in side.tick(now) {
                            if to_receiver
                                && frame.kind == Kind::Data
                                && (1500..2500).contains(&now)
                            {
                                copies.entry(frame.id).or_default().insert(frame.path);
                            }
                            if lost == Some(frame.path) && (3000..4500).contains(&now) {
                                continue;
                            }
                            let delay = if frame.path == 0 { 10 } else { 6 };
                            wire.push((now + delay, to_receiver, frame));
                        }
                    }
                }
                let due: Vec<_> = wire.extract_if(.., |(at, _, _)| *at <= now).collect();
                for (_, to_receiver, frame) in due {
                    if lost == Some(frame.path) && (3000..4500).contains(&now) {
                        continue;
                    }
                    let side = if to_receiver { &mut rx } else { &mut tx };
                    let (body, replies) = side.receive(&frame, now);
                    for reply in replies {
                        let delay = if reply.path == 0 { 10 } else { 6 };
                        wire.push((now + delay, !to_receiver, reply));
                    }
                    if to_receiver && let Some(body) = body {
                        let id = u16::from_be_bytes([body[4], body[5]]);
                        if id == 0 {
                            continue;
                        }
                        let offset = u16::from_be_bytes([body[6], body[7]]) & 0x1fff;
                        let parts = fragments.entry(id).or_default();
                        *parts |= if offset == 0 { 1 } else { 2 };
                        if *parts == 3 && complete.insert(id) {
                            if let Some(previous) = last {
                                max_gap = max_gap.max(now - previous);
                            }
                            last = Some(now);
                        }
                    }
                }
            }
            let both = copies.values().filter(|paths| paths.len() == 2).count();
            eprintln!(
                "{policy:?} lost={lost:?}: complete={}/7000 max_gap={max_gap}ms two_path_packets={both}/{} repairs={} queue_drops={}",
                complete.len(),
                copies.len(),
                tx.counters.repairs,
                tx.counters.queue_drops
            );
            assert_eq!(complete.len(), 7000, "scheduler lost complete datagrams");
        }
    }
}
