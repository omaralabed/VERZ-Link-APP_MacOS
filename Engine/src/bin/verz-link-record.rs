//! Record how one real link treats a steady stream, for the simulator.
//!
//! Sends authenticated data packets at a fixed rate over one interface to the
//! lab relay and logs every send, every acknowledgement and every carrier
//! change. The simulator replays the file in place of a fake link. Nothing
//! on the relay changes: it only acknowledges.
//!
//! Lines:
//! ```text
//! # {"interface":..,"started_unix_us":..,..}   metadata
//! s,<seq>,<sent_us>                            a packet left
//! f,<seq>,<at_us>                              a send failed (no carrier)
//! a,<seq>,<received_us>                        its acknowledgement arrived
//! c,<at_us>,<0|1>                              carrier changed (first: initial state)
//! r,<at_us>,0                                  socket reopened (link came back, maybe with a new address)
//! ```
//! Times are microseconds since this process started; `started_unix_us`
//! places them on the wall clock so links recorded by separate processes line up.

use std::{
    io::{BufWriter, Write},
    net::SocketAddr,
    path::PathBuf,
    time::{Duration, Instant, SystemTime},
};

use anyhow::{Context, Result, bail};
use clap::Parser;
use tokio::time;
use verz_link_lab::{
    Channel, Kind, Role, SessionId, bind_interface_socket, interface_carrier, load_secret,
    monotonic_micros, synthetic_payload,
};

/// Close to the video datagrams the simulator uses, within the lab MTU.
const PAYLOAD: usize = 1_100;

#[derive(Parser)]
#[command(about = "Record how one real link treats a steady stream, for the simulator")]
struct Args {
    #[arg(long)]
    relay: SocketAddr,
    #[arg(long)]
    interface: String,
    #[arg(long)]
    secret_file: PathBuf,
    #[arg(long)]
    out: PathBuf,
    #[arg(long, default_value_t = 600)]
    seconds: u64,
    #[arg(long, default_value_t = 3.0)]
    mbps: f64,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    if !(0.1..=50.0).contains(&args.mbps) {
        bail!("mbps must be between 0.1 and 50");
    }
    let secret = load_secret(&args.secret_file)?;
    let mut socket = bind_interface_socket(&args.interface, args.relay)?;
    let mut channel = Channel::new(&secret, SessionId::random(), 0, Role::Client)?;
    // A link that comes back may have a new address; a socket bound to the
    // old one sends nothing. Reopen it when sends fail or the carrier returns.
    let mut reopen = false;
    let file = std::fs::File::create(&args.out)
        .with_context(|| format!("create {}", args.out.display()))?;
    let mut out = BufWriter::new(file);
    let started_unix_us = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)?
        .as_micros() as u64;
    let epoch = Instant::now();
    writeln!(
        out,
        "# {}",
        serde_json::json!({
            "interface": args.interface,
            "relay": args.relay.to_string(),
            "source": socket.local_addr()?.to_string(),
            "payload": PAYLOAD,
            "mbps": args.mbps,
            "started_unix_us": started_unix_us,
        })
    )?;
    let mut carrier = interface_carrier(&socket, &args.interface);
    writeln!(out, "c,0,{}", u8::from(carrier.unwrap_or(true)))?;

    let interval_us = (PAYLOAD as f64 * 8.0 / args.mbps) as u64;
    let mut send_timer = time::interval(Duration::from_micros(interval_us.max(100)));
    // A stalled process must not catch up with a burst the link never saw.
    send_timer.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
    let mut carrier_timer = time::interval(Duration::from_millis(250));
    let mut report_timer = time::interval(Duration::from_secs(5));
    let deadline = time::Instant::now() + Duration::from_secs(args.seconds);
    let mut buffer = [0_u8; 2_048];
    let mut sequence = 0_u64;
    let (mut sent, mut acked) = (0_u64, 0_u64);
    let mut all_rtts: Vec<u64> = Vec::new();
    let (mut window_sent, mut window_acked) = (0_u64, 0_u64);
    let mut window_rtts: Vec<u64> = Vec::new();
    let tag = args.interface.clone();

    loop {
        tokio::select! {
            _ = send_timer.tick() => {
                let now = monotonic_micros(epoch);
                let packet = channel.seal(Kind::Data, 0, sequence, now, &synthetic_payload(sequence, PAYLOAD))?;
                match socket.send(&packet).await {
                    Ok(_) => {
                        writeln!(out, "s,{sequence},{now}")?;
                        sent += 1;
                        window_sent += 1;
                    }
                    Err(_) => {
                        writeln!(out, "f,{sequence},{now}")?;
                        reopen = true;
                    }
                }
                sequence += 1;
            }
            received = socket.recv(&mut buffer) => {
                let Ok(length) = received else {
                    // The interface is down; let the carrier poll say so.
                    time::sleep(Duration::from_millis(50)).await;
                    continue;
                };
                let now = monotonic_micros(epoch);
                if let Ok(message) = channel.open(&buffer[..length])
                    && message.kind == Kind::Ack
                {
                    writeln!(out, "a,{},{now}", message.sequence)?;
                    acked += 1;
                    window_acked += 1;
                    let rtt = now.saturating_sub(message.echo_micros);
                    all_rtts.push(rtt);
                    window_rtts.push(rtt);
                }
            }
            _ = carrier_timer.tick() => {
                let state = interface_carrier(&socket, &args.interface);
                if state != carrier {
                    carrier = state;
                    writeln!(out, "c,{},{}", monotonic_micros(epoch), u8::from(carrier.unwrap_or(true)))?;
                    reopen |= state == Some(true);
                }
                if reopen
                    && state != Some(false)
                    && let Ok(fresh) = bind_interface_socket(&args.interface, args.relay)
                {
                    socket = fresh;
                    channel = Channel::new(&secret, SessionId::random(), 0, Role::Client)?;
                    writeln!(out, "r,{},0", monotonic_micros(epoch))?;
                    reopen = false;
                }
            }
            _ = report_timer.tick() => {
                let elapsed = epoch.elapsed().as_secs();
                if elapsed == 0 {
                    continue;
                }
                let loss = if window_sent == 0 { 0.0 } else { 100.0 * window_sent.saturating_sub(window_acked) as f64 / window_sent as f64 };
                window_rtts.sort_unstable();
                let median = window_rtts.get(window_rtts.len() / 2).map_or("-".to_owned(), |r| format!("{:.1}", *r as f64 / 1_000.0));
                let state = match carrier { Some(true) => "up", Some(false) => "DOWN", None => "?" };
                // One write per line, so two recorders sharing a log do not interleave.
                let line = format!("{tag} {elapsed:>5}s  sent {sent:>7}  acked {acked:>7}  last 5 s: loss {loss:>5.1}%  rtt {median:>6} ms  carrier {state}\n");
                let _ = std::io::stderr().write_all(line.as_bytes());
                window_sent = 0;
                window_acked = 0;
                window_rtts.clear();
                out.flush()?;
            }
            _ = time::sleep_until(deadline) => break,
            _ = tokio::signal::ctrl_c() => break,
        }
    }
    // Let the last acknowledgements land.
    let grace = time::Instant::now() + Duration::from_secs(1);
    while let Ok(Ok(length)) = time::timeout_at(grace, socket.recv(&mut buffer)).await {
        let now = monotonic_micros(epoch);
        if let Ok(message) = channel.open(&buffer[..length])
            && message.kind == Kind::Ack
        {
            writeln!(out, "a,{},{now}", message.sequence)?;
            acked += 1;
            all_rtts.push(now.saturating_sub(message.echo_micros));
        }
    }
    out.flush()?;
    all_rtts.sort_unstable();
    let rtt_ms = |i: usize| all_rtts.get(i).map(|r| *r as f64 / 1_000.0);
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "interface": args.interface,
            "file": args.out.display().to_string(),
            "seconds": epoch.elapsed().as_secs(),
            "sent": sent,
            "acknowledged": acked,
            "loss_percent": if sent == 0 { 0.0 } else { 100.0 * sent.saturating_sub(acked) as f64 / sent as f64 },
            "rtt_min_ms": rtt_ms(0),
            "rtt_median_ms": rtt_ms(all_rtts.len() / 2),
            "rtt_p99_ms": rtt_ms(all_rtts.len().saturating_sub(1) * 99 / 100),
            "rtt_max_ms": rtt_ms(all_rtts.len().saturating_sub(1)),
        }))?
    );
    Ok(())
}
