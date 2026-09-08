//! Real multipath Layer-3 runtime. One Noise session and one IP assignment
//! survive individual UDP subflow loss, adapter removal and NAT rebinding.
use anyhow::{Context, Result, ensure};
use clap::{Args, Parser, Subcommand};
use serde::Deserialize;
use serde_json::json;
use snow::HandshakeState;
use std::{
    collections::HashMap,
    io::BufRead,
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{net::UdpSocket, sync::mpsc, task::JoinHandle, time};
use tun_rs::DeviceBuilder;
use verz_link_lab::{
    bind_interface_socket,
    bond::{BOND_MTU, Frame, Kind, MAX_PATHS, Policy, Scheduler},
    load_secret,
    tunnel::{
        HEADER, HELLO, Header, IP, MAX_WIRE, Transport, WELCOME, internet_destination_allowed,
        validate_ipv4,
    },
};

const SERVER_IP: [u8; 4] = [10, 78, 0, 1];
const DEFAULT_RELAY: &str = "69.164.213.57:39002";

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Mode,
}
#[derive(Subcommand)]
enum Mode {
    Server(Server),
    Client(Client),
}
#[derive(Args)]
struct Server {
    #[arg(long, default_value_t = 16, value_parser = clap::value_parser!(u16).range(1..=253))]
    max_clients: u16,
    #[arg(long, default_value = "0.0.0.0:39002")]
    listen: SocketAddr,
    #[arg(long)]
    secret_file: PathBuf,
    #[arg(long, default_value = "verzb0")]
    tun_name: String,
}
#[derive(Args)]
struct Client {
    #[arg(long, default_value = DEFAULT_RELAY)]
    relay: SocketAddr,
    #[arg(long, num_args = 1.., required = true)]
    interface: Vec<String>,
    #[arg(long)]
    secret_file: PathBuf,
    #[arg(long, value_enum, default_value_t = Policy::Smart)]
    policy: Policy,
    #[arg(long)]
    control_stdin: bool,
}
#[derive(Deserialize)]
struct InterfaceConfig {
    name: String,
    #[serde(default)]
    metered: bool,
}
#[derive(Deserialize)]
struct Control {
    interfaces: Vec<InterfaceConfig>,
    policy: Option<String>,
}

fn handshake(secret: &[u8; 32], session: &[u8; 16], initiator: bool) -> Result<HandshakeState> {
    let mut prologue = b"VERZ Link multipath v1 / authenticated IPv4 lease / MTU1200 / ".to_vec();
    prologue.extend_from_slice(session);
    let builder = snow::Builder::new("Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s".parse()?)
        .psk(0, secret)?
        .prologue(&prologue)?;
    Ok(if initiator {
        builder.build_initiator()?
    } else {
        builder.build_responder()?
    })
}
fn now(epoch: Instant) -> u64 {
    epoch.elapsed().as_millis().min(u128::from(u64::MAX)) as u64
}
async fn stop_signal() {
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("SIGTERM handler");
    tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = term.recv() => {} }
}
fn valid_interface(name: &str) -> bool {
    !name.is_empty() && name.len() < 16 && name.chars().all(|c| c.is_ascii_alphanumeric())
}
fn policy_number(policy: Policy) -> u64 {
    match policy {
        Policy::Smart => 0,
        Policy::Performance => 1,
        Policy::Continuity => 2,
        Policy::DataSaver => 3,
    }
}
fn number_policy(value: u64) -> Policy {
    match value & 3 {
        1 => Policy::Performance,
        2 => Policy::Continuity,
        3 => Policy::DataSaver,
        _ => Policy::Smart,
    }
}
fn destination_allowed(ip: &[u8]) -> bool {
    ip.len() >= 20
        && (ip[16..20] == SERVER_IP
            || (ip[16..20] != [10, 77, 0, 1] && internet_destination_allowed(ip)))
}

enum Incoming {
    Wire(usize, u64, Vec<u8>),
    Failed(usize, u64),
}
struct Subflow {
    generation: u64,
    socket: Arc<UdpSocket>,
    reader: JoinHandle<()>,
}
impl Drop for Subflow {
    fn drop(&mut self) {
        self.reader.abort();
    }
}
fn open_subflow(
    name: &str,
    relay: SocketAddr,
    index: usize,
    sender: mpsc::Sender<Incoming>,
) -> Result<Subflow> {
    ensure!(valid_interface(name), "invalid physical interface name");
    let socket = Arc::new(bind_interface_socket(name, relay)?);
    let generation = rand::random();
    let receiver = socket.clone();
    let reader = tokio::spawn(async move {
        let mut wire = [0; MAX_WIRE + 1];
        loop {
            match receiver.recv(&mut wire).await {
                Ok(length) => {
                    if sender
                        .send(Incoming::Wire(index, generation, wire[..length].to_vec()))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                Err(_) => {
                    let _ = sender.send(Incoming::Failed(index, generation)).await;
                    break;
                }
            }
        }
    });
    Ok(Subflow {
        generation,
        socket,
        reader,
    })
}

async fn establish(
    args: &Client,
    sockets: &[Option<Subflow>],
    input: &mut mpsc::Receiver<Incoming>,
) -> Result<(Transport, [u8; 4])> {
    let session = rand::random();
    let mut noise = handshake(&load_secret(&args.secret_file)?, &session, true)?;
    let mut body = [0; MAX_WIRE];
    let length = noise.write_message(&[], &mut body)?;
    let hello = Header {
        kind: HELLO,
        session,
        counter: 0,
    }
    .wrap(&body[..length]);
    let deadline = time::sleep(Duration::from_secs(10));
    tokio::pin!(deadline);
    let mut repeat = time::interval(Duration::from_millis(250));
    loop {
        tokio::select! {
            _ = &mut deadline => anyhow::bail!("none of the selected networks authenticated the VERZ Server"),
            _ = repeat.tick() => { for path in sockets.iter().flatten() { let _ = path.socket.try_send(&hello); } }
            message = input.recv() => {
                let Some(Incoming::Wire(_, _, packet)) = message else { continue; };
                let Ok(header) = Header::parse(&packet) else { continue; };
                if header.kind != WELCOME || header.session != session { continue; }
                let size = noise.read_message(&packet[HEADER..], &mut body)?;
                ensure!(size == 4 && body[..3] == [10,78,0] && (2..=254).contains(&body[3]), "invalid server IP assignment");
                return Ok((Transport::new(session, noise)?, body[..4].try_into()?));
            }
        }
    }
}

fn send_client(
    frames: Vec<Frame>,
    transport: &mut Transport,
    paths: &mut [Option<Subflow>],
    scheduler: &mut Scheduler,
) -> Result<()> {
    for frame in frames {
        let index = usize::from(frame.path);
        let Some(path) = paths.get(index).and_then(Option::as_ref) else {
            continue;
        };
        let packet = transport.seal(IP, &frame.encode())?;
        if let Err(error) = path.socket.try_send(&packet)
            && error.kind() != std::io::ErrorKind::WouldBlock
        {
            scheduler.fail_path(index);
            paths[index] = None;
        }
    }
    Ok(())
}

async fn client(args: Client) -> Result<()> {
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "administrator authorization is required"
    );
    ensure!(
        args.interface.len() <= MAX_PATHS
            && args.interface.iter().all(|name| valid_interface(name)),
        "invalid interface list"
    );
    let mut names = args.interface.clone();
    names.sort();
    names.dedup();
    let mut scheduler = Scheduler::new(
        names.iter().map(|name| (name.clone(), false)).collect(),
        args.policy,
    )?;
    let (sender, mut input) = mpsc::channel(1024);
    let mut sockets: Vec<Option<Subflow>> = names
        .iter()
        .enumerate()
        .map(|(index, name)| open_subflow(name, args.relay, index, sender.clone()).ok())
        .collect();
    ensure!(
        sockets.iter().any(Option::is_some),
        "no selected network has a usable route to the VERZ Server"
    );
    let (mut transport, assigned) = establish(&args, &sockets, &mut input).await?;
    let tun = DeviceBuilder::new()
        .ipv4(
            Ipv4Addr::from(assigned),
            32,
            Some(Ipv4Addr::from(SERVER_IP)),
        )
        .mtu(BOND_MTU as u16)
        .build_async()
        .context("create multipath system tunnel")?;
    let epoch = Instant::now();
    let mut last_reset = vec![0_u64; sockets.len()];
    let joins: Vec<_> = scheduler
        .paths
        .iter()
        .map(|path| Frame::control(Kind::Join, path.id, policy_number(scheduler.policy), 0))
        .collect();
    send_client(joins, &mut transport, &mut sockets, &mut scheduler)?;
    println!(
        "TUNNEL CONNECTED: {} {} -> 10.78.0.1 over {} -> {}",
        tun.name()?,
        Ipv4Addr::from(assigned),
        names.join(","),
        args.relay
    );
    let (control_tx, mut control_rx) = mpsc::channel(8);
    if args.control_stdin {
        std::thread::spawn(move || {
            for line in std::io::stdin().lock().lines().map_while(Result::ok) {
                if line.len() <= 65536
                    && let Ok(control) = serde_json::from_str::<Control>(&line)
                    && control_tx.blocking_send(control).is_err()
                {
                    break;
                }
            }
        });
    }
    let mut ip = [0; 65536];
    let mut tick = time::interval(Duration::from_millis(2));
    tick.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
    let mut report = time::interval(Duration::from_millis(500));
    let stop = stop_signal();
    tokio::pin!(stop);
    loop {
        tokio::select! {
            _ = &mut stop => break,
            _ = report.tick() => {
                println!("BOND_STATE {}", json!({"paths":scheduler.paths, "policy":scheduler.policy,
                    "counters":scheduler.counters, "pending_packets":scheduler.pending_packets(),
                    "healthy_paths":scheduler.paths.iter().filter(|path| path.ready(now(epoch))).count(),
                    "assigned_ip":Ipv4Addr::from(assigned).to_string(), "server_ip":"10.78.0.1"}));
            }
            Some(control) = control_rx.recv(), if args.control_stdin => {
                if control.interfaces.len() > MAX_PATHS || !control.interfaces.iter().all(|item| valid_interface(&item.name)) { continue; }
                if let Some(policy) = control.policy { scheduler.policy = match policy.as_str() { "performance" => Policy::Performance, "continuity" => Policy::Continuity, "data-saver" => Policy::DataSaver, _ => Policy::Smart }; }
                for (index, socket) in sockets.iter_mut().enumerate() {
                    if !control.interfaces.iter().any(|item| item.name == scheduler.paths[index].name) {
                        scheduler.remove_path(index); *socket = None;
                    }
                }
                for item in control.interfaces { let index = scheduler.add_path(item.name, item.metered)?; if index >= sockets.len() { sockets.push(None); last_reset.push(0); } }
                let joins = scheduler.paths.iter().filter(|path| path.enabled).map(|path| Frame::control(Kind::Join, path.id,
                    policy_number(scheduler.policy) | if path.metered { 256 } else { 0 }, now(epoch))).collect();
                send_client(joins, &mut transport, &mut sockets, &mut scheduler)?;
            }
            _ = tick.tick() => {
                let moment = now(epoch);
                for index in 0..sockets.len() {
                    if !scheduler.paths[index].enabled || moment.saturating_sub(last_reset[index]) < 500 { continue; }
                    if sockets[index].is_none() || !scheduler.paths[index].ready(moment) {
                        last_reset[index] = moment;
                        if sockets[index].is_none() || scheduler.paths[index].state == "failed" {
                            sockets[index] = open_subflow(&scheduler.paths[index].name, args.relay, index, sender.clone()).ok();
                        }
                        let id = policy_number(scheduler.policy) | if scheduler.paths[index].metered { 256 } else { 0 };
                        send_client(vec![Frame::control(Kind::Join, index as u8, id, moment)], &mut transport, &mut sockets, &mut scheduler)?;
                    }
                }
                let frames = scheduler.tick(moment);
                send_client(frames, &mut transport, &mut sockets, &mut scheduler)?;
            }
            Some(message) = input.recv() => {
                match message {
                    Incoming::Failed(index, generation) => {
                        if sockets.get(index).and_then(Option::as_ref).is_some_and(|socket| socket.generation == generation) {
                            scheduler.fail_path(index); sockets[index] = None;
                        }
                    }
                    Incoming::Wire(index, generation, packet) => {
                        if !sockets.get(index).and_then(Option::as_ref).is_some_and(|socket| socket.generation == generation) { continue; }
                        let Ok((kind, body)) = transport.open(&packet) else { continue; };
                        if kind != IP { continue; }
                        let Ok(frame) = Frame::decode(&body) else { continue; };
                        if usize::from(frame.path) != index { continue; }
                        if frame.kind == Kind::Data && validate_ipv4(&frame.body, None, Some(assigned)).is_err() { continue; }
                        let (delivery, responses) = scheduler.receive(&frame, now(epoch));
                        if let Some(delivery) = delivery { tun.send(&delivery).await?; }
                        send_client(responses, &mut transport, &mut sockets, &mut scheduler)?;
                    }
                }
            }
            length = tun.recv(&mut ip) => {
                let length = length?;
                if validate_ipv4(&ip[..length], Some(assigned), None).is_ok() { scheduler.enqueue(ip[..length].to_vec()); }
            }
        }
    }
    let closes = scheduler
        .paths
        .iter()
        .map(|path| Frame::control(Kind::Close, path.id, 0, now(epoch)))
        .collect();
    let _ = send_client(closes, &mut transport, &mut sockets, &mut scheduler);
    println!("TUNNEL CLOSED; {}", json!({"counters":scheduler.counters}));
    Ok(())
}

struct Peer {
    transport: Transport,
    assigned: [u8; 4],
    addresses: Vec<Option<SocketAddr>>,
    scheduler: Scheduler,
    hello: Vec<u8>,
    welcome: Vec<u8>,
    last_seen: Instant,
}
fn send_server(socket: &UdpSocket, peer: &mut Peer, frames: Vec<Frame>) -> Result<()> {
    for frame in frames {
        if let Some(address) = peer
            .addresses
            .get(usize::from(frame.path))
            .copied()
            .flatten()
        {
            let packet = peer.transport.seal(IP, &frame.encode())?;
            if let Err(error) = socket.try_send_to(&packet, address)
                && error.kind() != std::io::ErrorKind::WouldBlock
            {
                peer.scheduler.fail_path(usize::from(frame.path));
            }
        }
    }
    Ok(())
}
async fn server(args: Server) -> Result<()> {
    ensure!(cfg!(target_os = "linux"), "Linux relay required");
    let secret = load_secret(&args.secret_file)?;
    let socket = UdpSocket::bind(args.listen).await?;
    let tun = DeviceBuilder::new()
        .name(&args.tun_name)
        .ipv4(Ipv4Addr::from(SERVER_IP), 24, None)
        .mtu(BOND_MTU as u16)
        .build_async()?;
    let mut peers: HashMap<[u8; 16], Peer> = HashMap::new();
    let mut wire = [0; MAX_WIRE + 1];
    let mut ip = [0; 65536];
    let epoch = Instant::now();
    let mut tick = time::interval(Duration::from_millis(2));
    tick.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
    let mut report = time::interval(Duration::from_secs(5));
    let stop = stop_signal();
    tokio::pin!(stop);
    println!(
        "MULTIPATH SERVER ready: {} / 10.78.0.1 / {}",
        tun.name()?,
        args.listen
    );
    loop {
        tokio::select! {
            _ = &mut stop => break,
            _ = report.tick() => {
                peers.retain(|_, peer| peer.last_seen.elapsed() < Duration::from_secs(120));
                println!("{}", json!({"devices":peers.len(), "healthy_paths":peers.values().map(|peer| peer.scheduler.paths.iter().filter(|path| path.ready(now(epoch))).count()).sum::<usize>()}));
            }
            _ = tick.tick() => {
                for peer in peers.values_mut() { let frames = peer.scheduler.tick(now(epoch)); send_server(&socket, peer, frames)?; }
            }
            received = socket.recv_from(&mut wire) => {
                let (length, address) = received?;
                let packet = &wire[..length];
                let Ok(header) = Header::parse(packet) else { continue; };
                if header.kind == HELLO {
                    if let Some(peer) = peers.get(&header.session) {
                        if peer.hello == packet { let _ = socket.try_send_to(&peer.welcome, address); }
                        continue;
                    }
                    if peers.len() >= usize::from(args.max_clients) { continue; }
                    let Some(last) = (2..=254).find(|last| !peers.values().any(|peer| peer.assigned[3] == *last)) else { continue; };
                    let assigned = [10,78,0,last];
                    let mut noise = handshake(&secret, &header.session, false)?;
                    let mut plain = [0; MAX_WIRE];
                    if noise.read_message(&packet[HEADER..], &mut plain).is_err() { continue; }
                    let length = noise.write_message(&assigned, &mut plain)?;
                    let welcome = Header { kind: WELCOME, session: header.session, counter: 0 }.wrap(&plain[..length]);
                    let _ = socket.try_send_to(&welcome, address);
                    let mut scheduler = Scheduler::new(vec![("path0".into(), false)], Policy::Smart)?;
                    scheduler.remove_path(0);
                    peers.insert(header.session, Peer { transport: Transport::new(header.session, noise)?, assigned,
                        addresses: vec![None], scheduler, hello: packet.to_vec(), welcome, last_seen: Instant::now() });
                    continue;
                }
                let Some(peer) = peers.get_mut(&header.session) else { continue; };
                let Ok((kind, body)) = peer.transport.open(packet) else { continue; };
                if kind != IP { continue; }
                let Ok(frame) = Frame::decode(&body) else { continue; };
                let index = usize::from(frame.path);
                if frame.kind == Kind::Join {
                    while peer.addresses.len() <= index {
                        let name = format!("path{}", peer.addresses.len());
                        let added = peer.scheduler.add_path(name, false)?;
                        peer.scheduler.remove_path(added); peer.addresses.push(None);
                    }
                    peer.scheduler.add_path(format!("path{index}"), frame.id & 256 != 0)?;
                    peer.scheduler.policy = number_policy(frame.id);
                    peer.addresses[index] = Some(address);
                } else if peer.addresses.get(index) != Some(&Some(address)) { continue; }
                peer.last_seen = Instant::now();
                if frame.kind == Kind::Close { peers.remove(&header.session); continue; }
                if frame.kind == Kind::Data && (validate_ipv4(&frame.body, Some(peer.assigned), None).is_err() || !destination_allowed(&frame.body)) { continue; }
                let (delivery, responses) = peer.scheduler.receive(&frame, now(epoch));
                if let Some(delivery) = delivery { tun.send(&delivery).await?; }
                send_server(&socket, peer, responses)?;
            }
            length = tun.recv(&mut ip) => {
                let length = length?;
                if validate_ipv4(&ip[..length], None, None).is_err() { continue; }
                if let Some(peer) = peers.values_mut().find(|peer| ip[16..20] == peer.assigned) { peer.scheduler.enqueue(ip[..length].to_vec()); }
            }
        }
    }
    Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    match Cli::parse().command {
        Mode::Server(args) => server(args).await,
        Mode::Client(args) => client(args).await,
    }
}
