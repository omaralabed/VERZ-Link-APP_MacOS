//! Deterministic regressions: no sockets, app sessions, or live WAN changes.
use super::*;
use crate::reorder::TcpReorder;

fn tcp(seq: u32, port: u16) -> Vec<u8> {
    let mut ip = vec![0; BOND_MTU];
    ip[0] = 0x45;
    ip[2..4].copy_from_slice(&(BOND_MTU as u16).to_be_bytes());
    ip[9] = 6;
    ip[12..20].copy_from_slice(&[10, 0, 0, 1, 10, 0, 0, 2]);
    ip[20..22].copy_from_slice(&port.to_be_bytes());
    ip[22..24].copy_from_slice(&443_u16.to_be_bytes());
    ip[24..28].copy_from_slice(&seq.to_be_bytes());
    ip[32] = 0x50;
    ip[33] = 0x10;
    ip
}

fn refresh(s: &mut Scheduler, now: u64, rtts: &[u64]) {
    for (i, &rtt) in rtts.iter().enumerate() {
        s.receive(&Frame::control(Kind::Pong, i as u8, now, now - rtt), now);
    }
}

fn ready(rtts: &[u64]) -> Scheduler {
    let mut s = Scheduler::new(
        rtts.iter()
            .enumerate()
            .map(|(i, _)| (format!("path{i}"), false))
            .collect(),
        Policy::Continuity,
    )
    .unwrap();
    for now in [200, 210, 220] {
        refresh(&mut s, now, rtts);
    }
    for (p, &rtt) in s.paths.iter_mut().zip(rtts) {
        p.rtt_ms = Some(rtt as f64);
        p.minimum_rtt_ms = rtt as f64;
        p.jitter_ms = 0.0;
        p.congestion_window = 512 * 1024;
    }
    s
}

fn data(s: &mut Scheduler, now: u64) -> Vec<Frame> {
    s.tick(now)
        .into_iter()
        .filter(|f| f.kind == Kind::Data)
        .collect()
}

#[test]
fn tcp_brief_path_silence_does_not_repair_a_young_packet() {
    let mut s = ready(&[40, 6]);
    s.policy = Policy::Smart;
    s.paths[1].next_send = 1_000.0;
    s.enqueue(tcp(0, 5000));
    let original = data(&mut s, 275).remove(0);
    assert_eq!(original.path, 0);
    s.paths[1].next_send = 0.0;
    s.receive(&Frame::control(Kind::Pong, 1, 0, 276), 282);
    assert!(!s.data_paths(282).contains(&0));
    assert!(s.paths[0].ready(282));
    assert!(
        data(&mut s, 282).is_empty(),
        "a 7 ms old packet is not lost because its path is quiet for 62 ms"
    );
    assert!(data(&mut s, 284).is_empty());
    assert_eq!(s.counters.tcp_early_repairs_deferred, 1);
    s.receive(
        &Frame::control(Kind::Ack, 0, original.id, original.stamp),
        300,
    );
    assert_eq!(s.pending_packets(), 0);
    assert_eq!(s.counters.repairs, 0);
    assert_eq!(s.counters.tcp_early_deferrals_acked, 1);
}

#[test]
fn tcp_policy_exclusion_is_not_packet_loss() {
    let mut s = ready(&[6, 10]);
    s.paths[0].metered = true;
    s.enqueue(tcp(0, 5000));
    let original = data(&mut s, 230).remove(0);
    assert_eq!(original.path, 0);
    s.policy = Policy::DataSaver;
    assert!(!s.data_paths(232).contains(&0));
    assert!(data(&mut s, 232).is_empty());
    s.receive(
        &Frame::control(Kind::Ack, 0, original.id, original.stamp),
        236,
    );
    assert_eq!(s.counters.repairs, 0);
    assert_eq!(s.pending_packets(), 0);
}

#[test]
fn tcp_silent_path_still_recovers_at_packet_deadline() {
    let mut s = ready(&[40, 6]);
    s.policy = Policy::Smart;
    s.paths[1].next_send = 1_000.0;
    s.enqueue(tcp(0, 5000));
    let original = data(&mut s, 275).remove(0);
    s.paths[1].next_send = 0.0;
    for now in [282, 300, 320, 344] {
        s.receive(&Frame::control(Kind::Pong, 1, 0, now - 6), now);
        assert!(data(&mut s, now).is_empty());
    }
    let recovered = data(&mut s, 345);
    assert_eq!(recovered.len(), 1);
    assert_eq!((recovered[0].id, recovered[0].path), (original.id, 1));
    assert_eq!(s.counters.tcp_deadline_repairs, 1);
    s.receive(&Frame::control(Kind::Ack, 1, original.id, 345), 351);
    assert_eq!(s.pending_packets(), 0);
    assert_eq!(s.counters.tcp_early_deferrals_acked, 0);
}

#[test]
fn continuity_with_one_path_does_not_create_a_same_path_protection_copy() {
    let mut s = ready(&[24, 8]);
    s.remove_path(1);
    s.enqueue(tcp(0, 5000));
    let original = data(&mut s, 230).remove(0);
    assert_eq!(original.path, 0);

    refresh(&mut s, 242, &[24]);
    assert!(data(&mut s, 242).is_empty());
    assert_eq!(s.counters.repairs, 0);
}

#[test]
fn tcp_physical_failure_repairs_without_waiting_for_packet_deadline() {
    for removed in [false, true] {
        let mut s = ready(&[6, 40]);
        s.policy = Policy::Smart;
        s.enqueue(tcp(0, 5000));
        let original = data(&mut s, 230).remove(0);
        if removed {
            s.remove_path(0);
        } else {
            s.fail_path(0);
        }
        let repaired = data(&mut s, 232);
        assert_eq!(repaired.len(), 1);
        assert_eq!((repaired[0].id, repaired[0].path), (original.id, 1));
        assert_eq!(s.counters.tcp_unavailable_path_repairs, 1);
    }
}

#[test]
fn physical_failure_is_announced_redundantly_on_the_surviving_path() {
    let mut s = ready(&[6, 40]);
    s.fail_path(0);

    let notices = s.path_failure_notices(true, 232);
    assert_eq!(
        notices.len(),
        3,
        "repeat the tiny control to survive UDP loss"
    );
    assert!(
        notices
            .iter()
            .all(|frame| { frame.kind == Kind::PathDown && frame.path == 1 && frame.id == 0 })
    );
    assert!(s.path_failure_notices(true, 234).is_empty());
    assert_eq!(s.counters.path_down_notices_sent, 3);
}

#[test]
fn remote_path_failure_releases_pending_tcp_without_an_echo_loop() {
    let mut s = ready(&[6, 40]);
    s.policy = Policy::Smart;
    s.enqueue(tcp(0, 5000));
    let original = data(&mut s, 230).remove(0);
    assert_eq!(original.path, 0);

    assert!(s.fail_path_remote(0));
    assert!(!s.fail_path_remote(0), "duplicate controls are idempotent");
    assert!(
        s.path_failure_notices(true, 231).is_empty(),
        "a remote notice must never be echoed"
    );
    let repaired = data(&mut s, 232);
    assert_eq!(repaired.len(), 1);
    assert_eq!((repaired[0].id, repaired[0].path), (original.id, 1));
    assert_eq!(s.counters.path_down_notices_received, 1);
}

#[test]
fn compatibility_and_rejoin_cannot_emit_a_stale_path_failure() {
    let mut legacy = ready(&[6, 40]);
    legacy.fail_path(0);
    assert!(legacy.path_failure_notices(false, 232).is_empty());
    assert!(legacy.path_failure_notices(true, 234).is_empty());

    let mut rejoined = ready(&[6, 40]);
    rejoined.fail_path(0);
    rejoined.add_path("path0".into(), false).unwrap();
    assert!(rejoined.path_failure_notices(true, 232).is_empty());
}

#[test]
fn delayed_ack_from_old_path_incarnation_cannot_train_the_rejoined_path() {
    let mut s = ready(&[6, 40]);
    s.policy = Policy::Smart;
    s.enqueue(tcp(0, 5000));
    let original = data(&mut s, 230).remove(0);
    let old_generation = s.paths[0].generation;
    s.remove_path(0);
    s.add_path("path0".into(), false).unwrap();
    assert_ne!(s.paths[0].generation, old_generation);
    assert_eq!(s.paths[0].acknowledged_bytes, 0);

    s.receive(
        &Frame::control(Kind::Ack, 0, original.id, original.stamp),
        240,
    );

    assert_eq!(s.pending_packets(), 1);
    assert_eq!(s.paths[0].acknowledged_bytes, 0);
    assert_eq!(s.paths[0].in_flight, 0);
}

#[test]
fn rejoined_path_charges_and_releases_only_its_current_incarnation() {
    let mut s = ready(&[6, 40]);
    s.policy = Policy::Smart;
    s.enqueue(tcp(0, 5000));
    let original = data(&mut s, 230).remove(0);
    let mut pending = s.pending.remove(&original.id).unwrap();
    assert_eq!(s.paths[0].in_flight, pending.body.len());

    s.remove_path(0);
    s.add_path("path0".into(), false).unwrap();
    assert_eq!(s.paths[0].in_flight, 0);
    s.send_copy(&mut pending, original.id, 0, 240);
    assert_eq!(s.paths[0].in_flight, pending.body.len());
    s.release_flight(&pending);
    assert_eq!(s.paths[0].in_flight, 0);
}

#[test]
fn two_higher_same_path_acks_repair_tcp_before_the_deadline() {
    let mut s = ready(&[12]);
    s.policy = Policy::Smart;
    let step = (BOND_MTU - 40) as u32;
    for sequence in [0, step, 2 * step] {
        s.enqueue(tcp(sequence, 5000));
    }
    let sent = data(&mut s, 230);
    assert_eq!(sent.len(), 3);
    let missing = sent[0].clone();
    for acknowledged in &sent[1..] {
        s.receive(
            &Frame::control(
                Kind::Ack,
                acknowledged.path,
                acknowledged.id,
                acknowledged.stamp,
            ),
            250,
        );
    }
    let repair = data(&mut s, 251);
    assert_eq!(repair.len(), 1);
    assert_eq!((repair[0].id, repair[0].path), (missing.id, 0));
    assert_eq!(s.counters.tcp_fast_ack_repairs, 1);
    assert_eq!(s.counters.tcp_deadline_repairs, 0);
}

#[test]
fn one_later_same_path_ack_repairs_a_paced_tcp_hole() {
    let mut s = ready(&[12]);
    s.policy = Policy::Smart;
    let step = (BOND_MTU - 40) as u32;
    s.enqueue(tcp(0, 5000));
    let missing = data(&mut s, 230).remove(0);
    s.enqueue(tcp(step, 5000));
    let acknowledged = data(&mut s, 240).remove(0);
    assert_eq!(acknowledged.path, missing.path);

    s.receive(
        &Frame::control(
            Kind::Ack,
            acknowledged.path,
            acknowledged.id,
            acknowledged.stamp,
        ),
        252,
    );
    let repair = data(&mut s, 253);
    assert_eq!(repair.len(), 1);
    assert_eq!((repair[0].id, repair[0].path), (missing.id, 0));
    assert_eq!(s.counters.tcp_fast_ack_repairs, 1);
    assert_eq!(s.counters.tcp_deadline_repairs, 0);
}

#[test]
fn later_ack_on_same_path_but_different_tcp_flow_does_not_repair() {
    let mut s = ready(&[12]);
    s.policy = Policy::Smart;
    s.enqueue(tcp(0, 5000));
    let missing = data(&mut s, 230).remove(0);
    s.enqueue(tcp(0, 5001));
    let acknowledged = data(&mut s, 240).remove(0);
    assert_eq!(acknowledged.path, missing.path);

    s.receive(
        &Frame::control(
            Kind::Ack,
            acknowledged.path,
            acknowledged.id,
            acknowledged.stamp,
        ),
        252,
    );
    assert!(data(&mut s, 253).is_empty());
    assert_eq!(s.counters.tcp_fast_ack_repairs, 0);
}

#[test]
fn continuity_protects_low_rate_tcp_on_two_paths() {
    let mut s = ready(&[6, 25]);
    s.enqueue(tcp(0, 5000));
    let sent = data(&mut s, 230);
    assert_eq!(sent.len(), 2);
    assert_eq!(sent[0].id, sent[1].id);
    assert_ne!(sent[0].path, sent[1].path);
    assert_eq!(s.counters.protection_copies, 1);
}

#[test]
fn continuity_protects_tcp_ack_control_on_two_paths_like_udp() {
    let mut s = ready(&[6, 25]);
    let mut ack = tcp(0, 5000);
    ack.truncate(40);
    assert!(bare_tcp_ack(&ack));
    assert!(tcp_flow_key(&ack).is_none());

    s.enqueue(ack);
    let sent = data(&mut s, 230);
    assert_eq!(sent.len(), 2);
    assert_eq!(sent[0].id, sent[1].id);
    assert_ne!(sent[0].path, sent[1].path);
    assert_eq!(s.counters.protection_copies, 1);
}

#[test]
fn smart_tcp_ack_control_retains_single_copy_policy() {
    let mut s = ready(&[6, 25]);
    s.policy = Policy::Smart;
    let mut ack = tcp(0, 5000);
    ack.truncate(40);
    s.enqueue(ack);
    assert_eq!(data(&mut s, 230).len(), 1);
    assert_eq!(s.counters.protection_copies, 0);
}

#[test]
fn continuity_defers_tcp_backup_when_alternate_is_temporarily_paced() {
    let mut s = ready(&[6, 25]);
    s.paths[1].next_send = 240.0;
    s.enqueue(tcp(0, 5000));

    let primary = data(&mut s, 230);
    assert_eq!(primary.len(), 1);
    assert_eq!(primary[0].path, 0);
    assert_eq!(s.counters.protection_deferred, 1);

    assert!(data(&mut s, 239).is_empty());
    let backup = data(&mut s, 240);
    assert_eq!(backup.len(), 1);
    assert_eq!(backup[0].id, primary[0].id);
    assert_eq!(backup[0].path, 1);
    assert_eq!(s.counters.protection_deferred_sent, 1);
    assert_eq!(s.counters.repairs, 0);
}

#[test]
fn continuity_tcp_backup_ignores_interactive_latency_cutoff() {
    let mut s = ready(&[6, 120]);
    s.enqueue(tcp(0, 5000));
    let sent = data(&mut s, 230);
    assert_eq!(sent.len(), 2);
    assert_ne!(sent[0].path, sent[1].path);
    assert_eq!(s.counters.protection_copies, 1);
}

#[test]
fn tcp_continuity_protection_has_a_shared_bandwidth_ceiling() {
    let mut s = ready(&[6, 25]);
    for sequence in 0..128 {
        s.enqueue(tcp(sequence * (BOND_MTU - 40) as u32, 5000));
    }
    let sent = data(&mut s, 230);
    let protected = sent.len().saturating_sub(128);
    assert!(
        protected > 0,
        "the initial bounded continuity burst is useful"
    );
    assert!(
        protected * BOND_MTU <= TCP_CONTINUITY_BURST_BYTES as usize,
        "redundancy cannot exceed its shared burst budget"
    );
    assert!(protected < 128, "high-rate TCP is not duplicated wholesale");
}

#[test]
fn smart_tcp_does_not_use_continuity_duplication() {
    let mut s = ready(&[6, 25]);
    s.policy = Policy::Smart;
    s.enqueue(tcp(0, 5000));
    assert_eq!(data(&mut s, 230).len(), 1);
    assert_eq!(s.counters.protection_copies, 0);
}

#[test]
fn cross_path_ack_reordering_does_not_trigger_a_false_tcp_repair() {
    let mut s = ready(&[6, 40]);
    s.paths[1].next_send = 1_000.0;
    s.enqueue(tcp(0, 5000));
    let missing = data(&mut s, 230).remove(0);
    assert_eq!(missing.path, 0);

    s.paths[0].next_send = 1_000.0;
    s.paths[1].next_send = 0.0;
    for port in [5001, 5002] {
        s.enqueue(tcp(0, port));
        let acknowledged = data(&mut s, 240 + u64::from(port - 5001))
            .into_iter()
            .find(|frame| frame.id != missing.id)
            .expect("independent flow uses the available alternate");
        assert_eq!(acknowledged.path, 1);
        s.receive(
            &Frame::control(
                Kind::Ack,
                acknowledged.path,
                acknowledged.id,
                acknowledged.stamp,
            ),
            250,
        );
    }
    assert!(data(&mut s, 251).is_empty());
    assert_eq!(s.counters.tcp_fast_ack_repairs, 0);
}

#[test]
fn legacy_udp_keeps_its_existing_quiet_path_recovery() {
    let mut s = ready(&[40, 6]);
    s.policy = Policy::Smart;
    s.paths[1].next_send = 1_000.0;
    let mut udp = tcp(0, 5000);
    udp[9] = 17;
    s.enqueue(udp);
    let original = data(&mut s, 275).remove(0);
    s.paths[1].next_send = 0.0;
    s.receive(&Frame::control(Kind::Pong, 1, 0, 276), 282);
    let repaired = data(&mut s, 282);
    assert!(repaired.iter().any(|f| f.id == original.id && f.path == 1));
    assert_eq!(s.counters.repairs, 1);
    assert_eq!(s.counters.tcp_early_repairs_deferred, 0);
}

#[test]
fn tcp_waits_for_briefly_full_fast_path_instead_of_creating_slow_gap() {
    let mut s = ready(&[6, 40]);
    s.policy = Policy::Smart;
    s.paths[1].congestion_window = 32 * BOND_MTU;
    s.paths[0].in_flight = s.paths[0].congestion_window - 4 * BOND_MTU;
    let step = (BOND_MTU - 40) as u32;
    s.enqueue(tcp(step, 5000));
    assert!(
        data(&mut s, 230).is_empty(),
        "do not spill the early segment onto the slow path"
    );
    s.paths[0].in_flight = 0; // Previously outstanding traffic acknowledged.
    s.enqueue(tcp(2 * step, 5000));
    let mut sent = data(&mut s, 232);
    sent.extend(data(&mut s, 233));
    assert_eq!(sent.len(), 2);
    let mut q = TcpReorder::default();
    q.push(tcp(0, 5000), 220);
    for frame in sent {
        assert_eq!(frame.path, 0);
        assert_eq!(q.push(frame.body, frame.stamp + 3).len(), 1);
    }
}

#[test]
fn tcp_retry_uses_fast_healthy_path_before_slow_untried_path() {
    let mut s = ready(&[6, 40]);
    s.policy = Policy::Smart;
    s.enqueue(tcp(0, 5000));
    let original = data(&mut s, 230);
    assert_eq!(original.len(), 1);
    assert_eq!(original[0].path, 0);
    for now in (240..=280).step_by(20) {
        refresh(&mut s, now, &[6, 40]);
    }
    let retry = data(&mut s, 300);
    assert_eq!(retry.len(), 1);
    assert_eq!(retry[0].id, original[0].id);
    assert_eq!(
        retry[0].path, 0,
        "a retry must use earliest arrival, not prefer an untried carrier"
    );
    for now in (300..=360).step_by(20) {
        refresh(&mut s, now, &[6, 40]);
    }
    let next_retry = data(&mut s, 370);
    assert_eq!(next_retry.len(), 1);
    assert_eq!(
        next_retry[0].path, 1,
        "unanswered data retries must eventually try a different carrier even if probes answer"
    );
}

#[test]
fn tcp_pacer_wait_does_not_spill_and_udp_still_progresses() {
    let mut s = ready(&[6, 40]);
    s.paths[0].next_send = 231.0;
    s.enqueue(tcp(0, 5000));
    let mut udp = vec![0; 200];
    udp[0] = 0x45;
    udp[9] = 17;
    s.enqueue(udp);
    let sent = data(&mut s, 230);
    assert!(sent.iter().any(|f| f.body[9] == 17));
    assert!(!sent.iter().any(|f| f.body[9] == 6));
    assert!(
        data(&mut s, 232)
            .iter()
            .any(|f| f.body[9] == 6 && f.path == 0)
    );
}

#[test]
fn tcp_wait_is_bounded_even_when_only_probes_work_on_fast_path() {
    let mut s = ready(&[6, 40]);
    s.paths[0].in_flight = s.paths[0].congestion_window;
    s.enqueue(tcp(0, 5000));
    for now in 230..236 {
        assert!(data(&mut s, now).is_empty());
    }
    let sent = data(&mut s, 236);
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].path, 1);
    assert_eq!(s.counters.tcp_bounded_wait_fallbacks, 1);
}

#[test]
fn tcp_failed_fast_path_bypasses_wait_and_full_window_retry_cannot_deadlock() {
    let mut s = ready(&[6, 40]);
    s.enqueue(tcp(0, 5000));
    let first = data(&mut s, 230).remove(0);
    s.paths[0].in_flight = s.paths[0].congestion_window;
    for now in (240..=280).step_by(20) {
        refresh(&mut s, now, &[6, 40]);
    }
    assert_eq!(data(&mut s, 300)[0].path, 0);
    // A real removal overrides the preferred path immediately, including repairs.
    s.remove_path(0);
    s.enqueue(tcp((BOND_MTU - 40) as u32, 5000));
    let sent = data(&mut s, 302);
    assert!(sent.iter().all(|f| f.path == 1));
    assert!(sent.iter().any(|f| f.id == first.id));
    assert!(sent.iter().any(|f| f.id != first.id));
}

#[test]
fn tcp_large_backlog_can_bond_but_other_flows_do_not_force_a_slow_spill() {
    let mut s = ready(&[6, 40]);
    s.paths[0].congestion_window = 32 * BOND_MTU;
    s.paths[0].in_flight = s.paths[0].congestion_window;
    for i in 0..400 {
        s.enqueue(tcp(i * (BOND_MTU - 40) as u32, 5000));
    }
    assert!(data(&mut s, 230).iter().any(|f| f.path == 1));
    let mut isolated = ready(&[6, 40]);
    isolated.paths[0].in_flight = isolated.paths[0].congestion_window;
    for port in 5000..5400 {
        isolated.enqueue(tcp(0, port));
    }
    assert!(data(&mut isolated, 230).is_empty());
}

#[test]
fn tcp_ordering_metrics_distinguish_gap_fill_from_deadline_release() {
    let step = (BOND_MTU - 40) as u32;
    let mut q = TcpReorder::default();
    q.push(tcp(0, 5000), 0);
    q.push(tcp(2 * step, 5000), 5);
    assert_eq!(q.snapshot().buffered_packets, 1);
    q.push(tcp(step, 5000), 20);
    assert_eq!(q.snapshot().max_hold_ms, 15);
    assert_eq!(q.snapshot().deadline_gap_releases, 0);
    q.push(tcp(4 * step, 5000), 25);
    assert_eq!(q.drain_due(105).len(), 1);
    let stats = q.snapshot();
    assert_eq!(stats.buffered_packets, 0);
    assert_eq!(stats.held_packets, 2);
    assert_eq!(stats.released_held_packets, 2);
    assert_eq!(stats.deadline_gap_releases, 1);
    assert_eq!(stats.total_hold_ms, 95);
}

#[test]
fn tcp_loaded_rate_is_used_but_quiet_rate_expires_and_rejoin_resets_it() {
    let mut s = ready(&[6]);
    let p = &mut s.paths[0];
    p.in_flight = p.congestion_window / 2;
    p.tcp_sent(230);
    p.tcp_acked(100_000, 280);
    assert_eq!(p.tcp_delivery_bps, 16_000_000.0);
    assert_eq!(p.tcp_bytes_per_ms(281), 2500.0);
    assert_eq!(p.tcp_bytes_per_ms(1281), p.estimated_bytes_per_ms());
    p.in_flight = 0;
    p.capacity_used_until = None;
    p.tcp_rate = TcpRate::default();
    p.tcp_sent(1500);
    p.tcp_acked(100, 1600);
    assert_eq!(
        p.tcp_delivery_bps, 16_000_000.0,
        "quiet traffic cannot validate lower capacity"
    );
    s.remove_path(0);
    s.add_path("path0".into(), false).unwrap();
    assert_eq!(s.paths[0].tcp_delivery_bps, 0.0);
}

#[test]
fn tcp_flow_parser_excludes_bare_ack_udp_and_fragments_and_handles_options() {
    let mut ip = tcp(0, 5000);
    let key = tcp_flow_key(&ip).unwrap();
    let hdr = ip[20..].to_vec();
    ip.splice(20..20, [0; 4]);
    ip[0] = 0x46;
    assert_eq!(&ip[24..], &hdr);
    assert_eq!(tcp_flow_key(&ip), Some(key));
    ip[6] = 0x20;
    assert!(tcp_flow_key(&ip).is_none());
    ip = tcp(0, 5000);
    ip.truncate(40);
    assert!(tcp_flow_key(&ip).is_none());
    ip[33] = 2;
    assert!(tcp_flow_key(&ip).is_some());
    ip[9] = 17;
    assert!(tcp_flow_key(&ip).is_none());
    for len in 0..40 {
        assert!(tcp_flow_key(&vec![0; len]).is_none());
    }
}
