use std::{
    collections::HashMap,
    net::SocketAddr,
    path::PathBuf,
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use clap::Parser;
use serde::Serialize;
use tokio::{net::UdpSocket, time};
use verz_link_lab::{
    Channel, DEFAULT_PORT, Kind, Outer, REPLAY_WIDTH, ReplayWindow, Role, SessionId, load_secret,
    synthetic_payload,
};

#[derive(Parser)]
#[command(about = "VERZ Link V2 synthetic-traffic lab relay")]
struct Args {
    #[arg(long, default_value_t = SocketAddr::from(([0, 0, 0, 0], DEFAULT_PORT)))]
    listen: SocketAddr,
    #[arg(long)]
    secret_file: PathBuf,
}

struct Peer {
    channel: Channel,
    address: SocketAddr,
    last_seen: Instant,
}

#[derive(Default, Serialize)]
struct Stats {
    authenticated_datagrams: u64,
    unique_data_packets: u64,
    repaired_or_duplicate_data: u64,
    invalid_datagrams: u64,
    sessions: usize,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let secret = load_secret(&args.secret_file)?;
    let socket = UdpSocket::bind(args.listen)
        .await
        .with_context(|| format!("bind {}", args.listen))?;
    println!("VERZ Link lab relay listening on {}", socket.local_addr()?);

    let mut peers: HashMap<(SessionId, u8), Peer> = HashMap::new();
    let mut delivered: HashMap<(SessionId, u8), ReplayWindow> = HashMap::new();
    let mut stats = Stats::default();
    let mut buffer = [0_u8; 2_048];
    let mut report = time::interval(Duration::from_secs(10));
    report.set_missed_tick_behavior(time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            received = socket.recv_from(&mut buffer) => {
                let (length, source) = received?;
                let packet = &buffer[..length];
                let outer = match Outer::parse(packet) {
                    Ok(value) => value,
                    Err(_) => {
                        stats.invalid_datagrams += 1;
                        continue;
                    }
                };
                let key = (outer.session, outer.path);
                if !peers.contains_key(&key) {
                    if peers.len() >= 256 {
                        stats.invalid_datagrams += 1;
                        continue;
                    }
                    let mut channel = Channel::new(&secret, outer.session, outer.path, Role::Relay)?;
                    let message = match channel.open(packet) {
                        Ok(value) => value,
                        Err(_) => {
                            stats.invalid_datagrams += 1;
                            continue;
                        }
                    };
                    peers.insert(key, Peer { channel, address: source, last_seen: Instant::now() });
                    process(&socket, peers.get_mut(&key).expect("inserted peer"), key, message, &mut delivered, &mut stats).await?;
                } else {
                    let peer = peers.get_mut(&key).expect("existing peer");
                    let message = match peer.channel.open(packet) {
                        Ok(value) => value,
                        Err(_) => {
                            stats.invalid_datagrams += 1;
                            continue;
                        }
                    };
                    peer.address = source;
                    peer.last_seen = Instant::now();
                    process(&socket, peer, key, message, &mut delivered, &mut stats).await?;
                }
            }
            _ = report.tick() => {
                let cutoff = Instant::now() - Duration::from_secs(120);
                peers.retain(|_, peer| peer.last_seen >= cutoff);
                delivered.retain(|(session, _), _| peers.keys().any(|(peer_session, _)| peer_session == session));
                stats.sessions = peers.keys().map(|(session, _)| *session).collect::<std::collections::HashSet<_>>().len();
                println!("{}", serde_json::to_string(&stats)?);
            }
            result = tokio::signal::ctrl_c() => {
                result?;
                stats.sessions = peers.keys().map(|(session, _)| *session).collect::<std::collections::HashSet<_>>().len();
                println!("{}", serde_json::to_string(&stats)?);
                break;
            }
        }
    }
    Ok(())
}

async fn process(
    socket: &UdpSocket,
    peer: &mut Peer,
    key: (SessionId, u8),
    message: verz_link_lab::Message,
    delivered: &mut HashMap<(SessionId, u8), ReplayWindow>,
    stats: &mut Stats,
) -> Result<()> {
    stats.authenticated_datagrams += 1;
    let response = match message.kind {
        Kind::Probe => {
            Some(
                peer.channel
                    .seal(Kind::Pong, 0, message.sequence, message.echo_micros, &[])?,
            )
        }
        Kind::Data => {
            if message.payload != synthetic_payload(message.sequence, message.payload.len()) {
                stats.invalid_datagrams += 1;
                return Ok(());
            }
            // Data sequence numbers are deduplicated across both physical paths.
            let sequence_key = (key.0, message.flow);
            let window = delivered
                .entry(sequence_key)
                .or_insert_with(|| ReplayWindow::new(REPLAY_WIDTH * 4));
            if window.mark(message.sequence) {
                stats.unique_data_packets += 1;
            } else {
                stats.repaired_or_duplicate_data += 1;
            }
            Some(peer.channel.seal(
                Kind::Ack,
                message.flow,
                message.sequence,
                message.echo_micros,
                &[],
            )?)
        }
        Kind::Ack | Kind::Pong => None,
    };
    if let Some(packet) = response {
        socket.send_to(&packet, peer.address).await?;
    }
    Ok(())
}
