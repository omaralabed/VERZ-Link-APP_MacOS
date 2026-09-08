use std::{
    collections::HashMap,
    net::SocketAddr,
    path::PathBuf,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use clap::{Parser, ValueEnum};
use serde::Serialize;
use tokio::time;
use verz_link_lab::{
    Channel, DEFAULT_PAYLOAD, Kind, PathState, Role, SessionId, bind_interface_socket, load_secret,
    monotonic_micros, recovery_decision, synthetic_payload,
};

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Policy {
    Recovery,
    Duplicate,
}

#[derive(Parser)]
#[command(about = "VERZ Link V2 dual-interface synthetic-traffic lab client")]
struct Args {
    #[arg(long)]
    relay: SocketAddr,
    #[arg(long, num_args = 2, required = true)]
    interface: Vec<String>,
    #[arg(long)]
    secret_file: PathBuf,
    #[arg(long, default_value_t = 15)]
    duration_seconds: u64,
    #[arg(long, default_value_t = 100)]
    packets_per_second: u64,
    #[arg(long, default_value_t = 5_000_000)]
    alternate_spare_bps: u64,
    #[arg(long, value_enum, default_value_t = Policy::Recovery)]
    policy: Policy,
}

struct Pending {
    first_sent: Instant,
    origin_micros: u64,
    primary: usize,
    sent: [bool; 2],
}

#[derive(Default, Serialize)]
struct Counters {
    sent_original: u64,
    sent_protection: u64,
    sent_repair: u64,
    acknowledged: u64,
    expired: u64,
    socket_errors: u64,
    protect_in_advance_decisions: u64,
    reactive_repair_decisions: u64,
}

#[derive(Serialize)]
struct Report {
    status: &'static str,
    policy: String,
    elapsed_seconds: f64,
    paths: Vec<PathState>,
    counters: Counters,
    maximum_ack_gap_ms: f64,
    maximum_recovery_ms: f64,
    outstanding_packets: usize,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    if args.interface[0] == args.interface[1] {
        bail!("provide two different interfaces");
    }
    if args.packets_per_second == 0 || args.packets_per_second > 1_000 {
        bail!("packets-per-second must be between 1 and 1000");
    }
    let secret = load_secret(&args.secret_file)?;
    let sockets = [
        bind_interface_socket(&args.interface[0], args.relay)?,
        bind_interface_socket(&args.interface[1], args.relay)?,
    ];
    let sources = [sockets[0].local_addr()?, sockets[1].local_addr()?];
    let session = SessionId::random();
    let mut channels = [
        Channel::new(&secret, session, 0, Role::Client)?,
        Channel::new(&secret, session, 1, Role::Client)?,
    ];
    let mut paths = [
        PathState::new(0, args.interface[0].clone(), sources[0]),
        PathState::new(1, args.interface[1].clone(), sources[1]),
    ];
    let epoch = Instant::now();
    let warm_deadline = epoch + Duration::from_secs(8);
    let mut probe_sequence = 0_u64;
    let mut probe_tick = time::interval(Duration::from_millis(10));
    probe_tick.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
    let mut buffer0 = [0_u8; 2_048];
    let mut buffer1 = [0_u8; 2_048];

    while !paths.iter().all(|path| path.samples >= 5) {
        if Instant::now() >= warm_deadline {
            bail!(
                "both paths did not reach the relay; observations: {}",
                serde_json::to_string(&paths)?
            );
        }
        tokio::select! {
            _ = probe_tick.tick() => {
                for index in 0..2 {
                    let sent_at = monotonic_micros(epoch);
                    let packet = channels[index].seal(Kind::Probe, 0, probe_sequence, sent_at, &[])?;
                    let _ = sockets[index].send(&packet).await;
                }
                probe_sequence += 1;
            }
            result = sockets[0].recv(&mut buffer0) => {
                if let Ok(length) = result { observe(0, &buffer0[..length], &mut channels, &mut paths, epoch, None)?; }
            }
            result = sockets[1].recv(&mut buffer1) => {
                if let Ok(length) = result { observe(1, &buffer1[..length], &mut channels, &mut paths, epoch, None)?; }
            }
        }
    }

    let started = Instant::now();
    let finish = started + Duration::from_secs(args.duration_seconds);
    let drain_finish = finish + Duration::from_millis(250);
    let interval = Duration::from_secs_f64(1.0 / args.packets_per_second as f64);
    let mut data_tick = time::interval(interval);
    data_tick.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
    let mut pending: HashMap<u64, Pending> = HashMap::new();
    let mut sequence = 0_u64;
    let mut counters = Counters::default();
    let mut last_ack = None;
    let mut maximum_ack_gap = Duration::ZERO;
    let mut maximum_recovery = Duration::ZERO;

    while Instant::now() < drain_finish {
        let now = Instant::now();
        // Collect repair candidates separately to avoid aliasing the map.
        let repair_sequences: Vec<_> = pending
            .iter()
            .filter_map(|(number, item)| {
                let threshold = Duration::from_secs_f64(
                    (paths[item.primary].srtt_ms.unwrap_or(30.0) * 1.5 / 1_000.0)
                        .clamp(0.020, 0.045),
                );
                let alternate = 1 - item.primary;
                (now.duration_since(item.first_sent) >= threshold
                    && !item.sent[alternate]
                    && paths[alternate].healthy(now))
                .then_some((*number, alternate))
            })
            .collect();
        for (number, alternate) in repair_sequences {
            let origin_micros = pending
                .get(&number)
                .map(|item| item.origin_micros)
                .context("repair candidate disappeared")?;
            let packet = channels[alternate].seal(
                Kind::Data,
                0,
                number,
                origin_micros,
                &synthetic_payload(number, DEFAULT_PAYLOAD),
            )?;
            match sockets[alternate].send(&packet).await {
                Ok(_) => {
                    if let Some(item) = pending.get_mut(&number) {
                        item.sent[alternate] = true;
                    }
                    counters.sent_repair += 1;
                }
                Err(_) => counters.socket_errors += 1,
            }
        }
        let expired: Vec<_> = pending
            .iter()
            .filter_map(|(number, item)| {
                (now.duration_since(item.first_sent) > Duration::from_millis(100))
                    .then_some(*number)
            })
            .collect();
        for number in expired {
            pending.remove(&number);
            counters.expired += 1;
        }

        tokio::select! {
            _ = probe_tick.tick() => {
                for index in 0..2 {
                    let sent_at = monotonic_micros(epoch);
                    let packet = channels[index].seal(Kind::Probe, 0, probe_sequence, sent_at, &[])?;
                    if sockets[index].send(&packet).await.is_err() { counters.socket_errors += 1; }
                }
                probe_sequence += 1;
            }
            _ = data_tick.tick(), if Instant::now() < finish => {
                let now = Instant::now();
                let exposed = pending.len() as u64 * (DEFAULT_PAYLOAD as u64 + 96);
                if let Some(decision) = recovery_decision(&paths, now, exposed, args.alternate_spare_bps as f64) {
                    let primary = decision.primary_path as usize;
                    if decision.protect_in_advance { counters.protect_in_advance_decisions += 1; }
                    else { counters.reactive_repair_decisions += 1; }
                    let mut targets = vec![primary];
                    if (matches!(args.policy, Policy::Duplicate) || decision.protect_in_advance)
                        && let Some(alternate) = decision.alternate_path
                    {
                        targets.push(alternate as usize);
                    }
                    let origin = monotonic_micros(epoch);
                    let payload = synthetic_payload(sequence, DEFAULT_PAYLOAD);
                    let mut sent = [false; 2];
                    for target in targets {
                        let packet = channels[target].seal(Kind::Data, 0, sequence, origin, &payload)?;
                        if sockets[target].send(&packet).await.is_ok() {
                            sent[target] = true;
                            if target == primary { counters.sent_original += 1; }
                            else { counters.sent_protection += 1; }
                        } else { counters.socket_errors += 1; }
                    }
                    if sent.iter().any(|value| *value) {
                        pending.insert(sequence, Pending { first_sent: now, origin_micros: origin, primary, sent });
                    }
                    sequence += 1;
                }
            }
            result = sockets[0].recv(&mut buffer0) => {
                if let Ok(length) = result {
                    handle_received(0, &buffer0[..length], &mut channels, &mut paths, epoch,
                        &mut pending, &mut counters, &mut last_ack, &mut maximum_ack_gap, &mut maximum_recovery)?;
                }
            }
            result = sockets[1].recv(&mut buffer1) => {
                if let Ok(length) = result {
                    handle_received(1, &buffer1[..length], &mut channels, &mut paths, epoch,
                        &mut pending, &mut counters, &mut last_ack, &mut maximum_ack_gap, &mut maximum_recovery)?;
                }
            }
        }
    }
    let report = Report {
        status: if counters.expired == 0 && maximum_ack_gap <= Duration::from_millis(100) {
            "pass"
        } else {
            "fail"
        },
        policy: format!("{:?}", args.policy).to_lowercase(),
        elapsed_seconds: started.elapsed().as_secs_f64(),
        paths: paths.to_vec(),
        counters,
        maximum_ack_gap_ms: maximum_ack_gap.as_secs_f64() * 1_000.0,
        maximum_recovery_ms: maximum_recovery.as_secs_f64() * 1_000.0,
        outstanding_packets: pending.len(),
    };
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

fn observe(
    index: usize,
    packet: &[u8],
    channels: &mut [Channel; 2],
    paths: &mut [PathState; 2],
    epoch: Instant,
    expected: Option<Kind>,
) -> Result<()> {
    let message = channels[index].open(packet)?;
    if expected.is_some_and(|kind| message.kind != kind) {
        return Ok(());
    }
    if message.kind == Kind::Pong {
        let sent = Duration::from_micros(message.echo_micros);
        let elapsed = epoch.elapsed();
        if elapsed >= sent {
            paths[index].observe(Instant::now(), elapsed - sent);
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn handle_received(
    index: usize,
    packet: &[u8],
    channels: &mut [Channel; 2],
    paths: &mut [PathState; 2],
    epoch: Instant,
    pending: &mut HashMap<u64, Pending>,
    counters: &mut Counters,
    last_ack: &mut Option<Instant>,
    maximum_ack_gap: &mut Duration,
    maximum_recovery: &mut Duration,
) -> Result<()> {
    let message = channels[index]
        .open(packet)
        .context("authenticate relay packet")?;
    let now = Instant::now();
    match message.kind {
        Kind::Pong => {
            let sent = Duration::from_micros(message.echo_micros);
            let elapsed = epoch.elapsed();
            if elapsed >= sent {
                paths[index].observe(now, elapsed - sent);
            }
        }
        Kind::Ack => {
            if let Some(item) = pending.remove(&message.sequence) {
                let recovery = now.duration_since(item.first_sent);
                *maximum_recovery = (*maximum_recovery).max(recovery);
                counters.acknowledged += 1;
                if let Some(previous) = *last_ack {
                    *maximum_ack_gap = (*maximum_ack_gap).max(now.duration_since(previous));
                }
                *last_ack = Some(now);
            }
        }
        Kind::Data | Kind::Probe => {}
    }
    Ok(())
}
