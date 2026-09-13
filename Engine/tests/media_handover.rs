//! Deterministic bidirectional UDP delivery across silent loss and rejoin.
//! No physical interfaces, user streams, or servers are touched.
use std::collections::BTreeSet;
use verz_link_lab::bond::{Frame, Kind, Policy, Scheduler};

fn voice(sequence: u32, direction: usize) -> Vec<u8> {
    let mut p = vec![0; 200];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&200u16.to_be_bytes());
    p[9] = 17;
    p[12..16].copy_from_slice(&[1, 1, 1, 1 + direction as u8]);
    p[16..20].copy_from_slice(&[2, 2, 2, 2]);
    p[20..22].copy_from_slice(&5000u16.to_be_bytes());
    p[22..24].copy_from_slice(&5002u16.to_be_bytes());
    p[28] = 0x80;
    p[29] = 96; // RTP payload type; not an SRT control type.
    p[32..36].copy_from_slice(&sequence.to_be_bytes());
    p
}

fn exercise_handover(
    policy: Policy,
    lost: usize,
    packet_len: usize,
    one_way_ms: [u64; 2],
    gap_limit: u64,
) {
    let mut sides = [0, 1].map(|_| {
        Scheduler::new(vec![("wifi".into(), false), ("lan".into(), false)], policy).unwrap()
    });
    let mut wire: Vec<(u64, usize, Frame)> = Vec::new();
    let mut received: [BTreeSet<u32>; 2] = Default::default();
    let mut last = [None; 2];
    let mut max_gap = [0; 2];
    for now in 0..8000u64 {
        if now == 4000 {
            for side in &mut sides {
                side.add_path(if lost == 0 { "wifi" } else { "lan" }.into(), false)
                    .unwrap();
            }
        }
        if (500..7500).contains(&now) && now % 20 == 0 {
            for (direction, side) in sides.iter_mut().enumerate() {
                let mut packet = voice((now / 20) as u32, direction);
                // Large packets have no learned SRT control header.
                packet.resize(packet_len, 0x11);
                packet[2..4].copy_from_slice(&(packet_len as u16).to_be_bytes());
                if packet_len >= 500 {
                    packet[28] = 0x11; // Arbitrary bulk UDP, no SRT control bit.
                }
                side.enqueue(packet);
            }
        }
        for (direction, side) in sides.iter_mut().enumerate() {
            for frame in side.tick(now) {
                let path = usize::from(frame.path);
                if path == lost && (2000..4000).contains(&now) {
                    continue;
                }
                wire.push((now + one_way_ms[path], 1 - direction, frame));
            }
        }
        let due: Vec<_> = wire.extract_if(.., |(at, _, _)| *at <= now).collect();
        for (_, destination, frame) in due {
            if usize::from(frame.path) == lost && (2000..4000).contains(&now) {
                continue;
            }
            let (packet, replies) = sides[destination].receive(&frame, now);
            for reply in replies {
                wire.push((
                    now + one_way_ms[usize::from(reply.path)],
                    1 - destination,
                    reply,
                ));
            }
            if let Some(packet) = packet {
                assert_eq!(frame.kind, Kind::Data);
                let seq = u32::from_be_bytes(packet[32..36].try_into().unwrap());
                assert!(
                    received[destination].insert(seq),
                    "duplicate media delivery"
                );
                if let Some(previous) = last[destination] {
                    max_gap[destination] = max_gap[destination].max(now - previous);
                }
                last[destination] = Some(now);
            }
        }
    }
    for direction in 0..2 {
        assert_eq!(
            received[direction].len(),
            350,
            "lost media: {policy:?}, path {lost}"
        );
        eprintln!(
            "{policy:?} size={packet_len} delay={one_way_ms:?} lost={lost} direction={direction}: received={} max_gap={}ms",
            received[direction].len(),
            max_gap[direction]
        );
        assert!(
            max_gap[direction] <= gap_limit,
            "media gap {} ms",
            max_gap[direction]
        );
        assert_eq!(sides[direction].counters.queue_drops, 0);
    }
}

#[test]
fn bidirectional_voice_survives_either_cable_loss_and_return() {
    for policy in [Policy::Smart, Policy::Continuity] {
        for lost in [0usize, 1] {
            exercise_handover(policy, lost, 200, [6, 18], 60);
        }
    }
}

#[test]
fn bidirectional_udp_uses_high_latency_backup_during_silent_loss_and_rejoin() {
    for policy in [Policy::Smart, Policy::Continuity] {
        for lost in [0usize, 1] {
            // 120 ms RTT is above the preferred-primary cutoff. Backup
            // delivery must still work in both directions; the allowed gap
            // includes the extra physical propagation delay, not seconds of
            // loss detection. This is a simulation, not a physical NIC test.
            exercise_handover(policy, lost, 200, [6, 60], 100);
            if policy == Policy::Continuity {
                exercise_handover(policy, lost, 1200, [6, 60], 100);
            }
        }
    }
}
