//! Real multipath Layer-3 runtime. One Noise session and one IP assignment
//! survive individual UDP subflow loss, adapter removal and NAT rebinding.
use anyhow::{Context, Result, ensure};
use clap::{Args, Parser, Subcommand};
use serde::Deserialize;
use serde_json::json;
use std::{
    collections::HashMap,
    io::BufRead,
    net::{Ipv4Addr, SocketAddr, UdpSocket as StdUdpSocket},
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::{net::UdpSocket, sync::mpsc, task::JoinHandle, time};
use tun_rs::{AsyncDevice, DeviceBuilder};
use verz_link_core::{ACK as UDP_ACK, NACK as UDP_NACK, Packet as UdpPacket, transport::WanWriter};
use verz_link_lab::{
    bind_interface_socket, bind_interface_std_socket,
    bond::{
        AckBatcher, BOND_MTU, FEATURE_ACK_BATCH, FEATURE_PATH_FAILURE, FEATURE_UDP_LANE, Frame,
        Kind, MAX_PATHS, Policy, Scheduler, handshake, transport as bond_transport,
    },
    egress::{Datagram, Egress},
    intake::{INTAKE_BATCH, KernelTxMonitor, TunIntake},
    interface_carrier, load_secret,
    payload_meter::{Direction, PayloadMeter, udp_payload_len},
    reorder::{ReorderStats, TcpReorder},
    tunnel::{
        HEADER, HELLO, Header, IP, MAX_WIRE, Transport, WELCOME, internet_destination_allowed,
        validate_ipv4,
    },
    udp_lane::{self, UdpLane},
};

const SERVER_IP: [u8; 4] = [10, 78, 0, 1];
const DEFAULT_RELAY: &str = "69.164.213.57:443";
const PACKET_WRITER_QUEUE: usize = 8192;

struct PacketWriter {
    sender: mpsc::Sender<Vec<u8>>,
    task: JoinHandle<std::io::Result<()>>,
    reorder: Arc<Mutex<ReorderStats>>,
    udp_payload: Arc<AtomicU64>,
    udp_unmeasured: Arc<AtomicU64>,
}
impl PacketWriter {
    fn reorder_snapshot(&self) -> ReorderStats {
        *self.reorder.lock().unwrap_or_else(|e| e.into_inner())
    }
    fn udp(tun: Arc<AsyncDevice>) -> Self {
        let (sender, mut receiver) = mpsc::channel::<Vec<u8>>(1024);
        let udp_payload = Arc::new(AtomicU64::new(0));
        let udp_unmeasured = Arc::new(AtomicU64::new(0));
        let received = udp_payload.clone();
        let unmeasured = udp_unmeasured.clone();
        let task = tokio::spawn(async move {
            while let Some(packet) = receiver.recv().await {
                if tun.send(&packet).await? != packet.len() {
                    return Err(std::io::Error::other("short UDP TUN write"));
                }
                if let Some(bytes) = udp_payload_len(&packet) {
                    received.fetch_add(bytes, Ordering::Relaxed);
                } else {
                    unmeasured.fetch_add(1, Ordering::Relaxed);
                }
            }
            Ok(())
        });
        Self {
            sender,
            task,
            reorder: Default::default(),
            udp_payload,
            udp_unmeasured,
        }
    }
    fn new(tun: Arc<AsyncDevice>) -> Self {
        // A recovered high-capacity path can legitimately deliver several
        // megabytes while the TUN writer drains. Keep this bounded, but large
        // enough that recovery does not turn a short path event into packet
        // drops and thousands of repairs.
        let (sender, receiver) = mpsc::channel::<Vec<u8>>(PACKET_WRITER_QUEUE);
        let reorder = Arc::new(Mutex::new(ReorderStats::default()));
        let task = tokio::spawn(run_packet_writer_observed(
            receiver,
            reorder.clone(),
            move |packet| {
                let tun = tun.clone();
                async move {
                    let written = tun.send(&packet).await?;
                    if written != packet.len() {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::WriteZero,
                            "short TUN packet write",
                        ));
                    }
                    Ok(())
                }
            },
        ));
        Self {
            sender,
            task,
            reorder,
            udp_payload: Default::default(),
            udp_unmeasured: Default::default(),
        }
    }
}

// One bounded admission queue owns packets before they are acknowledged.
// Reordering lives in the writer: released bursts go straight to the TUN,
// never through a smaller, lossy intermediate channel. Memory remains bounded
// by 8,192 admitted packets plus TcpReorder's 8,192-packet global bound.
#[cfg(test)]
async fn run_packet_writer<F, Fut>(
    receiver: mpsc::Receiver<Vec<u8>>,
    write: F,
) -> std::io::Result<()>
where
    F: FnMut(Vec<u8>) -> Fut,
    Fut: std::future::Future<Output = std::io::Result<()>>,
{
    run_packet_writer_observed(receiver, Default::default(), write).await
}

async fn run_packet_writer_observed<F, Fut>(
    mut receiver: mpsc::Receiver<Vec<u8>>,
    observed: Arc<Mutex<ReorderStats>>,
    mut write: F,
) -> std::io::Result<()>
where
    F: FnMut(Vec<u8>) -> Fut,
    Fut: std::future::Future<Output = std::io::Result<()>>,
{
    let mut reorder = TcpReorder::default();
    let epoch = Instant::now();
    let mut tick = time::interval(Duration::from_millis(2));
    tick.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
    let mut report = time::interval(Duration::from_secs(1));
    report.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
    loop {
        let packets = tokio::select! {
            _ = report.tick() => {
                // One bounded snapshot per second, never a lock per packet.
                *observed.lock().unwrap_or_else(|e| e.into_inner()) = reorder.snapshot();
                continue;
            },
            packet = receiver.recv() => match packet {
                Some(packet) => reorder.push(packet, now(epoch)),
                None => return Ok(()),
            },
            _ = tick.tick() => reorder.drain_due(now(epoch)),
        };
        write_batch(packets, &mut write).await?;
    }
}

async fn write_batch<F, Fut>(packets: Vec<Vec<u8>>, write: &mut F) -> std::io::Result<()>
where
    F: FnMut(Vec<u8>) -> Fut,
    Fut: std::future::Future<Output = std::io::Result<()>>,
{
    for (index, packet) in packets.into_iter().enumerate() {
        write(packet).await?;
        // Ready writes must not monopolize the single-thread reactor during
        // a large gap release. Probe, control, and ACK tasks get regular turns.
        if index % 32 == 31 {
            tokio::task::yield_now().await;
        }
    }
    Ok(())
}

fn receive_to_writer(
    scheduler: &mut Scheduler,
    writer: &PacketWriter,
    frame: &Frame,
    moment: u64,
) -> Result<Vec<Frame>> {
    let permit = if frame.kind == Kind::Data && !scheduler.has_received(frame.id) {
        match writer.sender.try_reserve() {
            Ok(permit) => Some(permit),
            Err(mpsc::error::TrySendError::Full(_)) => {
                scheduler.counters.receive_backpressure += 1;
                // No ACK and no receive/replay marking: an outer retry remains
                // eligible once space is available. Never await a blocked TUN
                // from the network/control reactor.
                return Ok(Vec::new());
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                anyhow::bail!("tunnel admission queue closed")
            }
        }
    } else {
        None
    };
    let (delivery, responses) = scheduler.receive(frame, moment);
    if let Some(packet) = delivery {
        permit
            .context("new packet has no reserved delivery capacity")?
            .send(packet);
    }
    Ok(responses)
}
impl Drop for PacketWriter {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Mode,
}
#[derive(Subcommand)]
enum Mode {
    Server(Server),
    BrainServer(verz_link_lab::brain::BrainServerArgs),
    Client(Client),
    Direct(verz_link_lab::direct::DirectArgs),
    Hybrid(Hybrid),
}
#[derive(Args)]
struct Server {
    #[arg(long, default_value_t = 16, value_parser = clap::value_parser!(u16).range(1..=253))]
    max_clients: u16,
    #[arg(long, default_value = "0.0.0.0:443")]
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
#[derive(Args)]
struct Hybrid {
    #[arg(long, default_value = DEFAULT_RELAY)]
    relay: SocketAddr,
    #[arg(long, num_args = 1.., required = true)]
    interface: Vec<String>,
    #[arg(long)]
    secret_file: PathBuf,
    #[arg(long, value_enum, default_value_t = Policy::Smart)]
    policy: Policy,
    #[arg(long, default_value = "127.0.0.1:0")]
    listen: SocketAddr,
    /// name=IPv4,metered; repeated once per physical adapter.
    #[arg(long, num_args = 1.., required = true)]
    path: Vec<String>,
    #[arg(long)]
    secure_domain: Vec<String>,
    #[arg(long)]
    brain: SocketAddr,
}

#[derive(Clone, Deserialize)]
struct InterfaceConfig {
    name: String,
    address: Option<String>,
    #[serde(default)]
    metered: bool,
}
#[derive(Clone, Deserialize)]
struct Control {
    interfaces: Vec<InterfaceConfig>,
    policy: Option<String>,
    #[serde(default, alias = "secureDomains")]
    secure_domains: Option<Vec<String>>,
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

fn observed_carrier(socket: &impl std::os::fd::AsRawFd, interface: &str) -> Option<bool> {
    let started = Instant::now();
    let result = interface_carrier(socket, interface);
    let elapsed_ms = started.elapsed().as_millis();
    // Diagnosis only: a USB driver ioctl can stall the network reactor even
    // though the socket itself is nonblocking. Record actual slow calls rather
    // than assuming an SRT buffer or path timeout caused the observed pause.
    if elapsed_ms >= 50 {
        println!(
            "CARRIER_QUERY_DELAY {}",
            json!({"interface":interface,"elapsed_ms":elapsed_ms})
        );
    }
    result
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
    Opened(usize, u64, std::result::Result<StdUdpSocket, String>),
}
struct Subflow {
    generation: u64,
    socket: Arc<UdpSocket>,
    reader: JoinHandle<()>,
    pending_join: Option<Vec<u8>>,
    ack_batching: bool,
    acks: AckBatcher,
    udp_ready: bool,
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
    ensure!(
        observed_carrier(socket.as_ref(), name) != Some(false),
        "adapter has no carrier"
    );
    Ok(activate_subflow(socket, index, sender))
}

fn activate_subflow(
    socket: Arc<UdpSocket>,
    index: usize,
    sender: mpsc::Sender<Incoming>,
) -> Subflow {
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
    Subflow {
        generation,
        socket,
        reader,
        pending_join: None,
        ack_batching: false,
        acks: AckBatcher::default(),
        udp_ready: false,
    }
}

/// Adapter creation can wait in macOS while an unplugged interface loses its
/// route. Never perform it in the 2 ms traffic scheduler: one background open
/// may be pending per path, and its generation makes stale results harmless.
fn begin_subflow_open(
    name: String,
    relay: SocketAddr,
    index: usize,
    attempt: u64,
    sender: mpsc::Sender<Incoming>,
) {
    tokio::spawn(async move {
        let opened = tokio::task::spawn_blocking(move || {
            ensure!(valid_interface(&name), "invalid physical interface name");
            let socket = bind_interface_std_socket(&name, relay)?;
            ensure!(
                interface_carrier(&socket, &name) != Some(false),
                "adapter has no carrier"
            );
            Ok::<_, anyhow::Error>(socket)
        })
        .await
        .map_err(|error| error.to_string())
        .and_then(|result| result.map_err(|error| error.to_string()));
        let _ = sender.send(Incoming::Opened(index, attempt, opened)).await;
    });
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
                return Ok((bond_transport(session, noise)?, body[..4].try_into()?));
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
        let Some(path) = paths.get_mut(index).and_then(Option::as_mut) else {
            continue;
        };
        let frame = if path.ack_batching {
            let Some(frame) = path.acks.push(frame) else {
                continue;
            };
            frame
        } else {
            frame
        };
        // A fresh Tokio UDP socket may not yet be writable. Losing Join here
        // strands all following probes at the relay's old NAT address.
        if let Some(join) = path.pending_join.as_ref() {
            match path.socket.try_send(join) {
                Ok(_) => path.pending_join = None,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(_) => {
                    scheduler.fail_path(index);
                    paths[index] = None;
                    continue;
                }
            }
        }
        let packet = transport.seal(IP, &frame.encode())?;
        if let Err(error) = path.socket.try_send(&packet) {
            if error.kind() == std::io::ErrorKind::WouldBlock {
                scheduler.counters.socket_backpressure += 1;
                if frame.kind == Kind::Join {
                    path.pending_join = Some(packet);
                }
            } else {
                scheduler.fail_path(index);
                paths[index] = None;
            }
        }
    }
    Ok(())
}

async fn client(args: Client) -> Result<()> {
    client_with_controls(args, None, None, None).await
}

/// The reference Sender calls this synchronously. A failed primary write is
/// therefore visible immediately and triggers its same-call alternate send.
/// It must NOT call send_client, which defers recovery to the TCP scheduler.
struct UdpSocketWriter<'a> {
    transport: &'a mut Transport,
    scheduler: &'a mut Scheduler,
    sockets: Vec<Option<(&'a UdpSocket, Option<SocketAddr>)>>,
    physical: bool,
}
impl WanWriter for UdpSocketWriter<'_> {
    fn carrier(&self, id: u8) -> bool {
        let index = usize::from(id);
        self.sockets
            .get(index)
            .and_then(Option::as_ref)
            .is_some_and(|(socket, _)| {
                self.scheduler.paths[index].enabled
                    && (!self.physical
                        || observed_carrier(*socket, &self.scheduler.paths[index].name)
                            != Some(false))
            })
    }
    fn send(&mut self, id: u8, wire: &[u8]) -> std::io::Result<()> {
        let index = usize::from(id);
        let Some((socket, address)) = self.sockets.get(index).and_then(Option::as_ref) else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "UDP path unavailable",
            ));
        };
        let frame = Frame {
            kind: Kind::Udp,
            path: id,
            id: 0,
            stamp: 0,
            body: wire.to_vec(),
        };
        let sealed = self
            .transport
            .seal(IP, &frame.encode())
            .map_err(std::io::Error::other)?;
        let result = if let Some(address) = address {
            socket.try_send_to(&sealed, *address)
        } else {
            socket.try_send(&sealed)
        };
        match result {
            Ok(n) if n == sealed.len() => {
                self.scheduler.paths[index].sent_bytes += wire
                    .len()
                    .saturating_sub(verz_link_core::HEADER + verz_link_core::TAG)
                    as u64;
                Ok(())
            }
            Ok(_) => Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "short UDP send",
            )),
            Err(error) => {
                if error.kind() == std::io::ErrorKind::WouldBlock {
                    self.scheduler.counters.socket_backpressure += 1;
                } else {
                    self.scheduler.fail_path(index);
                }
                Err(error)
            }
        }
    }
}
enum UdpAction {
    Send(Vec<u8>),
    Receive(UdpPacket, Vec<u8>),
    Tick,
}
fn udp_action(
    lane: &mut UdpLane,
    action: UdpAction,
    policy: Policy,
    moment: u64,
    paths: &[verz_link_core::scheduler::Link],
    writer: &mut impl WanWriter,
) -> std::io::Result<()> {
    let controls = match action {
        UdpAction::Send(ip) => return lane.send(&ip, paths, policy, moment, writer),
        UdpAction::Receive(packet, wire) => {
            if packet.flags == UDP_ACK || packet.flags == UDP_NACK {
                return lane.control(&wire, paths, writer);
            }
            lane.receive(packet, moment)?
        }
        UdpAction::Tick => lane.tick(moment),
    };
    // Like the repo gateway, return control over every surviving path. ACK
    // loss can leave cache entries until eviction, but never stalls sending.
    for mut packet in controls {
        for path in paths
            .iter()
            .filter(|p| !p.disabled && matches!(p.status, 1 | 2))
        {
            packet.link = path.id;
            if writer.carrier(path.id) {
                let _ = writer.send(path.id, &lane.encode(&packet)?);
            }
        }
    }
    Ok(())
}
fn udp_client_action(
    lane: &mut UdpLane,
    action: UdpAction,
    transport: &mut Transport,
    sockets: &[Option<Subflow>],
    scheduler: &mut Scheduler,
    moment: u64,
) {
    let paths = udp_lane::links(scheduler, moment);
    let policy = scheduler.policy;
    let sockets = sockets
        .iter()
        .map(|p| {
            p.as_ref()
                .filter(|p| p.udp_ready && p.pending_join.is_none())
                .map(|p| (p.socket.as_ref(), None))
        })
        .collect();
    let mut writer = UdpSocketWriter {
        transport,
        scheduler,
        sockets,
        physical: true,
    };
    let _ = udp_action(lane, action, policy, moment, &paths, &mut writer);
}
fn udp_server_action(peer: &mut Peer, action: UdpAction, socket: &UdpSocket, moment: u64) {
    let paths = udp_lane::links(&peer.scheduler, moment);
    let policy = peer.scheduler.policy;
    let sockets = peer
        .addresses
        .iter()
        .map(|address| address.map(|address| (socket, Some(address))))
        .collect();
    let mut writer = UdpSocketWriter {
        transport: &mut peer.transport,
        scheduler: &mut peer.scheduler,
        sockets,
        physical: false,
    };
    let _ = udp_action(&mut peer.udp, action, policy, moment, &paths, &mut writer);
}
fn drain_udp(lane: &mut UdpLane, writer: &PacketWriter) -> Result<()> {
    while lane.front().is_some() {
        match writer.sender.try_reserve() {
            Ok(permit) => {
                permit.send(lane.pop().expect("front checked"));
            }
            Err(mpsc::error::TrySendError::Full(_)) => break,
            Err(mpsc::error::TrySendError::Closed(_)) => anyhow::bail!("UDP tunnel writer stopped"),
        }
    }
    Ok(())
}

async fn client_with_controls(
    args: Client,
    external_controls: Option<mpsc::Receiver<Control>>,
    mut guidance: Option<tokio::sync::watch::Receiver<verz_link_lab::brain::Guidance>>,
    relay_route: Option<tokio::sync::watch::Sender<Option<verz_link_lab::direct::RelayRoute>>>,
) -> Result<()> {
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
    let mut udp = UdpLane::new(
        &load_secret(&args.secret_file)?,
        &transport.session,
        args.policy,
    )?;
    let mut udp_negotiated = false;
    let mut path_failure_negotiated = false;
    let mut startup_udp = std::collections::VecDeque::new();
    let tun = Arc::new(
        DeviceBuilder::new()
            .ipv4(
                Ipv4Addr::from(assigned),
                32,
                Some(Ipv4Addr::from(SERVER_IP)),
            )
            .mtu(BOND_MTU as u16)
            .build_async()
            .context("create multipath system tunnel")?,
    );
    let mut writer = PacketWriter::new(tun.clone());
    let mut udp_writer = PacketWriter::udp(tun.clone());
    let epoch = Instant::now();
    let mut payload = PayloadMeter::default();
    let payload_source = format!("tcp-{:016x}", rand::random::<u64>());
    let mut last_reset = vec![0_u64; sockets.len()];
    // A dead adapter is reopened off the packet loop. The attempt token rejects
    // a completion made stale by a UI disable/address change in the meantime.
    let mut opening = vec![None::<u64>; sockets.len()];
    let mut interface_addresses: HashMap<String, String> = HashMap::new();
    let joins: Vec<_> = scheduler
        .paths
        .iter()
        .map(|path| {
            Frame::control(
                Kind::Join,
                path.id,
                FEATURE_ACK_BATCH
                    | FEATURE_UDP_LANE
                    | FEATURE_PATH_FAILURE
                    | policy_number(scheduler.policy),
                0,
            )
        })
        .collect();
    send_client(joins, &mut transport, &mut sockets, &mut scheduler)?;
    if let Some(route) = &relay_route {
        route.send_replace(Some(verz_link_lab::direct::RelayRoute {
            interface: tun.name()?,
            address: Ipv4Addr::from(assigned),
        }));
    }
    println!(
        "TUNNEL CONNECTED: {} {} -> 10.78.0.1 over {} -> {}",
        tun.name()?,
        Ipv4Addr::from(assigned),
        names.join(","),
        args.relay
    );
    let controls_enabled = args.control_stdin || external_controls.is_some();
    let (control_tx, generated_control_rx) = mpsc::channel(8);
    let mut control_rx = external_controls.unwrap_or(generated_control_rx);
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
            result = &mut writer.task => { result.context("tunnel writer task")??; anyhow::bail!("tunnel writer stopped"); }
            result = &mut udp_writer.task => { result.context("UDP tunnel writer task")??; anyhow::bail!("UDP tunnel writer stopped"); }
            _ = report.tick() => {
                payload.expire(now(epoch));
                println!("BOND_STATE {}", json!({"paths":scheduler.paths, "policy":scheduler.policy,
                    "payload": {"version":1,"source_id":payload_source,"sampled_at_ms":now(epoch),
                        "upload_bytes":payload.upload_bytes + udp.counters.payload_sent_bytes,
                        "download_bytes":payload.download_bytes + udp_writer.udp_payload.load(Ordering::Relaxed),
                        "unmeasured_packets":payload.unmeasured_packets + udp.counters.payload_unmeasured_packets + udp_writer.udp_unmeasured.load(Ordering::Relaxed),
                        "basis":"tcp_acknowledged_udp_datagrams"},
                    "counters":scheduler.counters, "tcp_reorder":writer.reorder_snapshot(), "udp_lane":udp.counters, "udp_negotiated":udp_negotiated, "path_failure_negotiated":path_failure_negotiated, "pending_packets":scheduler.pending_packets(), "queued_packets":scheduler.queued_packets(),
                    "healthy_paths":scheduler.paths.iter().filter(|path| path.ready(now(epoch))).count(),
                    "assigned_ip":Ipv4Addr::from(assigned).to_string(), "server_ip":"10.78.0.1"}));
            }
            Some(control) = control_rx.recv(), if controls_enabled => {
                if control.interfaces.len() > MAX_PATHS || !control.interfaces.iter().all(|item| valid_interface(&item.name)) { continue; }
                if let Some(policy) = control.policy { scheduler.policy = match policy.as_str() { "performance" => Policy::Performance, "continuity" => Policy::Continuity, "data-saver" => Policy::DataSaver, _ => Policy::Smart }; }
                for (index, socket) in sockets.iter_mut().enumerate() {
                    if !control.interfaces.iter().any(|item| item.name == scheduler.paths[index].name) {
                        scheduler.remove_path(index); *socket = None; opening[index] = None;
                    }
                }
                for item in control.interfaces {
                    let Ok(index) = scheduler.add_path(item.name.clone(), item.metered) else {
                        println!("Additional adapter {} exceeds this session's path-ID limit; existing paths remain active", item.name);
                        continue;
                    };
                    if index >= sockets.len() { sockets.push(None); last_reset.push(0); opening.push(None); }
                    if let Some(address) = item.address
                        && interface_addresses.insert(item.name, address.clone()).is_some_and(|previous| previous != address) {
                        sockets[index] = None; scheduler.fail_path(index); last_reset[index] = 0; opening[index] = None;
                    }
                }
                let joins = scheduler.paths.iter().filter(|path| path.enabled).map(|path| Frame::control(Kind::Join, path.id,
                    FEATURE_ACK_BATCH | FEATURE_UDP_LANE | FEATURE_PATH_FAILURE | policy_number(scheduler.policy) | if path.metered { 256 } else { 0 }, now(epoch))).collect();
                send_client(joins, &mut transport, &mut sockets, &mut scheduler)?;
            }
            _ = tick.tick() => {
                let moment = now(epoch);
                ensure!(udp_negotiated || moment < 3000, "VERZ Server does not support the repository UDP lane; update the relay before connecting this build");
                // Never query macOS interface/media state on this 2 ms packet
                // loop. USB hot-plug can block those ioctls repeatedly while
                // the driver reconfigures, stalling every surviving path too.
                // InterfaceMonitor performs discovery off the data plane and
                // sends a changed adapter set through `control_rx`; socket
                // errors and authenticated probes remain the in-engine backup.
                let notices = scheduler.path_failure_notices(path_failure_negotiated, moment);
                send_client(notices, &mut transport, &mut sockets, &mut scheduler)?;
                let acknowledgements = sockets.iter_mut().flatten().flat_map(|path| path.acks.drain()).collect();
                send_client(acknowledgements, &mut transport, &mut sockets, &mut scheduler)?;
                for index in 0..sockets.len() {
                    if !scheduler.paths[index].enabled || moment.saturating_sub(last_reset[index]) < 500 { continue; }
                    if sockets[index].is_none() || !scheduler.paths[index].ready(moment) {
                        last_reset[index] = moment;
                        // Keep the NAT mapping while probing a temporarily
                        // silent path. Rebind only after a socket/address error.
                        if sockets[index].is_none() && opening[index].is_none() {
                            let name = scheduler.paths[index].name.clone();
                            let attempt = rand::random();
                            opening[index] = Some(attempt);
                            begin_subflow_open(name, args.relay, index, attempt, sender.clone());
                        }
                        if sockets[index].is_some() {
                            let id = FEATURE_ACK_BATCH | FEATURE_UDP_LANE | FEATURE_PATH_FAILURE | policy_number(scheduler.policy) | if scheduler.paths[index].metered { 256 } else { 0 };
                            send_client(vec![Frame::control(Kind::Join, index as u8, id, moment)], &mut transport, &mut sockets, &mut scheduler)?;
                        }
                    }
                }
                if let Some(receiver) = &mut guidance
                    && receiver.has_changed().unwrap_or(false) {
                        let advice = receiver.borrow_and_update().clone();
                        if let Some((at, advice)) = advice {
                            let remaining = advice.valid_for_ms.min(5_000).saturating_sub(at.elapsed().as_millis() as u64);
                            scheduler.set_realtime_advice(advice.realtime_weights, moment.saturating_add(remaining));
                        } else {
                            scheduler.set_realtime_advice(Default::default(), 0);
                        }
                }
                let frames = scheduler.tick(moment);
                send_client(frames, &mut transport, &mut sockets, &mut scheduler)?;
                udp_client_action(&mut udp, UdpAction::Tick, &mut transport, &sockets, &mut scheduler, moment);
                if udp_negotiated && scheduler.paths.iter().any(|p| p.ready(moment)) {
                    for _ in 0..64 {
                        let Some(packet) = startup_udp.pop_front() else { break; };
                        udp_client_action(&mut udp, UdpAction::Send(packet), &mut transport, &sockets, &mut scheduler, moment);
                    }
                }
                drain_udp(&mut udp, &udp_writer)?;
            }
            Some(message) = input.recv() => {
                match message {
                    Incoming::Failed(index, generation) => {
                        if sockets.get(index).and_then(Option::as_ref).is_some_and(|socket| socket.generation == generation) {
                            scheduler.fail_path(index); sockets[index] = None;
                        }
                    }
                    Incoming::Opened(index, attempt, opened) => {
                        if opening.get(index).copied().flatten() != Some(attempt) { continue; }
                        opening[index] = None;
                        if !scheduler.paths.get(index).is_some_and(|path| path.enabled)
                            || sockets.get(index).is_some_and(Option::is_some) { continue; }
                        let Ok(socket) = opened else { continue; };
                        // A recovery attempt is optional while another path is
                        // carrying traffic. If reactor registration itself
                        // fails, retry later instead of terminating the tunnel.
                        let Ok(socket) = UdpSocket::from_std(socket) else { continue; };
                        let socket = Arc::new(socket);
                        let name = scheduler.paths[index].name.clone();
                        let metered = scheduler.paths[index].metered;
                        scheduler.add_path(name, metered)?;
                        sockets[index] = Some(activate_subflow(socket, index, sender.clone()));
                        let moment = now(epoch);
                        let id = FEATURE_ACK_BATCH | FEATURE_UDP_LANE | FEATURE_PATH_FAILURE | policy_number(scheduler.policy) | if metered { 256 } else { 0 };
                        send_client(vec![Frame::control(Kind::Join, index as u8, id, moment)], &mut transport, &mut sockets, &mut scheduler)?;
                    }
                    Incoming::Wire(index, generation, packet) => {
                        if !sockets.get(index).and_then(Option::as_ref).is_some_and(|socket| socket.generation == generation) { continue; }
                        let Ok((kind, body)) = transport.open(&packet) else { continue; };
                        if kind != IP { continue; }
                        let Ok(frame) = Frame::decode(&body) else { continue; };
                        if usize::from(frame.path) != index { continue; }
                        if frame.kind == Kind::PathFailureReady {
                            if frame.id == FEATURE_PATH_FAILURE {
                                path_failure_negotiated = true;
                            }
                            continue;
                        }
                        if frame.kind == Kind::PathDown {
                            if !path_failure_negotiated { continue; }
                            let Ok(failed) = usize::try_from(frame.id) else { continue; };
                            if failed >= sockets.len() || failed == index { continue; }
                            if scheduler.fail_path_remote(failed) {
                                sockets[failed] = None;
                                last_reset[failed] = 0;
                            }
                            continue;
                        }
                        if frame.kind == Kind::UdpReady {
                            udp_negotiated = true;
                            if let Some(path) = sockets[index].as_mut() { path.udp_ready = true; }
                            continue;
                        }
                        if frame.kind == Kind::Udp {
                            if !udp_negotiated { continue; }
                            let Ok(packet) = udp.decode(&frame.body) else { continue; };
                            if packet.link != frame.path { continue; }
                            if packet.is_data() && validate_ipv4(&packet.payload, None, Some(assigned)).is_err() { continue; }
                            scheduler.paths[index].received_bytes += packet.payload.len() as u64;
                            udp_client_action(&mut udp, UdpAction::Receive(packet, frame.body), &mut transport, &sockets, &mut scheduler, now(epoch));
                            drain_udp(&mut udp, &udp_writer)?;
                            continue;
                        }
                        if frame.kind == Kind::JoinAck && frame.id & FEATURE_ACK_BATCH != 0
                            && let Some(path) = sockets[index].as_mut() { path.ack_batching = true; }
                        if frame.kind == Kind::Data && validate_ipv4(&frame.body, None, Some(assigned)).is_err() { continue; }
                        if frame.kind == Kind::Data { payload.observe(&frame.body, Direction::Download, now(epoch)); }
                        let responses = receive_to_writer(&mut scheduler, &writer, &frame, now(epoch))?;
                        send_client(responses, &mut transport, &mut sockets, &mut scheduler)?;
                    }
                }
            }
            length = tun.recv(&mut ip) => {
                let length = length?;
                if validate_ipv4(&ip[..length], Some(assigned), None).is_ok() {
                    payload.observe(&ip[..length], Direction::Upload, now(epoch));
                    if udp_lane::is_udp(&ip[..length]) {
                        let moment = now(epoch);
                        if moment < 3000 && (!udp_negotiated || !scheduler.paths.iter().any(|p| p.ready(moment))) {
                            // Hold initial DNS/media only while the authenticated
                            // capability/probes complete. Never enter TCP queues.
                            if startup_udp.len() < 256 { startup_udp.push_back(ip[..length].to_vec()); }
                            else { udp.counters.send_failures += 1; }
                        } else {
                            udp_client_action(&mut udp, UdpAction::Send(ip[..length].to_vec()), &mut transport, &sockets, &mut scheduler, moment);
                        }
                    } else { scheduler.enqueue(ip[..length].to_vec()); }
                }
            }
        }
    }
    let closes = scheduler
        .paths
        .iter()
        .map(|path| Frame::control(Kind::Close, path.id, 0, now(epoch)))
        .collect();
    let _ = send_client(closes, &mut transport, &mut sockets, &mut scheduler);
    println!(
        "TUNNEL CLOSED; {}",
        json!({"counters":scheduler.counters, "udp_lane":udp.counters})
    );
    Ok(())
}

async fn hybrid(args: Hybrid) -> Result<()> {
    let (client_tx, client_rx) = mpsc::channel(8);
    let (direct_tx, direct_rx) = mpsc::channel(8);
    let (advice_tx, advice_rx) = tokio::sync::watch::channel(None);
    let (route_tx, route_rx) = tokio::sync::watch::channel(None);
    std::thread::spawn(move || {
        for line in std::io::stdin().lock().lines().map_while(Result::ok) {
            if line.len() > 65_536 {
                break;
            }
            let Ok(control) = serde_json::from_str::<Control>(&line) else {
                break;
            };
            let direct = verz_link_lab::direct::Control {
                interfaces: control
                    .interfaces
                    .iter()
                    .map(|item| verz_link_lab::direct::InterfaceConfig {
                        name: item.name.clone(),
                        address: item.address.clone(),
                        metered: item.metered,
                    })
                    .collect(),
                policy: control.policy.clone(),
                secure_domains: control.secure_domains.clone(),
            };
            if client_tx.blocking_send(control).is_err() || direct_tx.blocking_send(direct).is_err()
            {
                break;
            }
        }
    });
    let client_args = Client {
        relay: args.relay,
        interface: args.interface,
        secret_file: args.secret_file.clone(),
        policy: args.policy,
        control_stdin: false,
    };
    let direct_args = verz_link_lab::direct::DirectArgs {
        listen: args.listen,
        path: args.path,
        policy: args.policy,
        control_stdin: false,
        relay_fallback: true,
        secure_domain: args.secure_domain,
        brain: Some(args.brain),
        brain_secret_file: Some(args.secret_file),
    };
    tokio::try_join!(
        client_with_controls(
            client_args,
            Some(client_rx),
            Some(advice_rx),
            Some(route_tx)
        ),
        verz_link_lab::direct::run_with_guidance(
            direct_args,
            Some(direct_rx),
            Some(advice_tx),
            Some(route_rx)
        )
    )?;
    Ok(())
}

struct Peer {
    transport: Transport,
    assigned: [u8; 4],
    addresses: Vec<Option<SocketAddr>>,
    // Client-monotonic Join stamps make path control generation-safe without
    // changing the authenticated wire format. A delayed PathDown from an old
    // interface incarnation must not clear a newer, already-authenticated Join.
    join_stamps: Vec<u64>,
    scheduler: Scheduler,
    hello: Vec<u8>,
    welcome: Vec<u8>,
    last_seen: Instant,
    ack_batching: bool,
    acks: AckBatcher,
    udp: UdpLane,
    udp_enabled: bool,
    path_failure_enabled: bool,
}

fn stale_path_down(failure_stamp: u64, latest_join_stamp: u64) -> bool {
    latest_join_stamp != 0 && failure_stamp <= latest_join_stamp
}
fn send_server(
    socket: &UdpSocket,
    peer: &mut Peer,
    frames: Vec<Frame>,
    egress: &mut Egress,
) -> Result<()> {
    let mut packets = Vec::with_capacity(frames.len());
    for frame in frames {
        let frame = if peer.ack_batching {
            let Some(frame) = peer.acks.push(frame) else {
                continue;
            };
            frame
        } else {
            frame
        };
        if let Some(address) = peer
            .addresses
            .get(usize::from(frame.path))
            .copied()
            .flatten()
        {
            let packet = peer.transport.seal(IP, &frame.encode())?;
            packets.push(Datagram {
                address,
                path: usize::from(frame.path),
                bytes: packet,
                tcp_data: frame.kind == Kind::Data && frame.body.get(9) == Some(&6),
            });
        }
    }
    for failure in egress.send(socket, &packets) {
        if failure.error.kind() == std::io::ErrorKind::WouldBlock {
            peer.scheduler.counters.socket_backpressure += failure.packets as u64;
        } else {
            peer.scheduler.fail_path(failure.path);
        }
    }
    Ok(())
}
async fn server(args: Server) -> Result<()> {
    ensure!(cfg!(target_os = "linux"), "Linux relay required");
    let secret = load_secret(&args.secret_file)?;
    let socket = UdpSocket::bind(args.listen).await?;
    verz_link_lab::configure_udp_buffers(&socket)?;
    let tun = Arc::new(
        DeviceBuilder::new()
            .name(&args.tun_name)
            .ipv4(Ipv4Addr::from(SERVER_IP), 24, None)
            .mtu(BOND_MTU as u16)
            .build_async()?,
    );
    // The Linux TUN's internal ring can drop before either the qdisc or Rust
    // scheduler sees a packet. Size only this interface's bounded burst ring.
    #[cfg(target_os = "linux")]
    {
        use verz_link_lab::intake::KERNEL_RING_PACKETS;
        tun.set_tx_queue_len(KERNEL_RING_PACKETS)
            .context("set TUN intake ring")?;
        ensure!(
            tun.tx_queue_len()? == KERNEL_RING_PACKETS,
            "TUN ring size was not applied"
        );
    }
    let mut kernel_tx = KernelTxMonitor::new(&tun.name()?)?;
    let mut egress = Egress::default();
    let mut intake = TunIntake::new(tun.clone(), BOND_MTU);
    let mut intake_batch = Vec::with_capacity(INTAKE_BATCH);
    let mut writer = PacketWriter::new(tun.clone());
    let mut peers: HashMap<[u8; 16], Peer> = HashMap::new();
    let mut udp_writer = PacketWriter::udp(tun.clone());
    let mut wire = [0; MAX_WIRE + 1];
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
            result = &mut writer.task => { result.context("tunnel writer task")??; anyhow::bail!("tunnel writer stopped"); }
            _ = report.tick() => {
                peers.retain(|_, peer| peer.last_seen.elapsed() < Duration::from_secs(120));
                println!("{}", json!({"devices":peers.len(), "tcp_reorder":writer.reorder_snapshot(), "tun_intake":intake.snapshot(), "kernel_tx":kernel_tx.snapshot(), "tcp_socket_tx":egress, "healthy_paths":peers.values().map(|peer| peer.scheduler.paths.iter().filter(|path| path.ready(now(epoch))).count()).sum::<usize>(),
                    "clients":peers.values().map(|peer| json!({"ip":Ipv4Addr::from(peer.assigned).to_string(), "ack_batching":peer.ack_batching, "paths":peer.scheduler.paths, "counters":peer.scheduler.counters, "udp_enabled":peer.udp_enabled, "path_failure_enabled":peer.path_failure_enabled, "udp_lane":peer.udp.counters})).collect::<Vec<_>>()}));
            }
            _ = tick.tick(), if !peers.is_empty() => {
                for peer in peers.values_mut() {
                    let moment = now(epoch);
                    let mut frames = peer.acks.drain();
                    let scheduled = peer.scheduler.tick(moment);
                    frames.extend(peer.scheduler.path_failure_notices(peer.path_failure_enabled, moment));
                    frames.extend(scheduled);
                    send_server(&socket, peer, frames, &mut egress)?;
                    if peer.udp_enabled {
                        udp_server_action(peer, UdpAction::Tick, &socket, now(epoch));
                        drain_udp(&mut peer.udp, &udp_writer)?;
                    }
                }
            }
            result = &mut udp_writer.task => { result.context("UDP tunnel writer task")??; anyhow::bail!("UDP tunnel writer stopped"); }
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
                    peers.insert(header.session, Peer { transport: bond_transport(header.session, noise)?, assigned,
                        addresses: vec![None], join_stamps: vec![0], scheduler, hello: packet.to_vec(), welcome, last_seen: Instant::now(),
                        ack_batching: false, acks: AckBatcher::default(),
                        udp: UdpLane::new(&secret, &header.session, Policy::Smart)?, udp_enabled: false,
                        path_failure_enabled: false });
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
                        peer.scheduler.remove_path(added); peer.addresses.push(None); peer.join_stamps.push(0);
                    }
                    if frame.stamp < peer.join_stamps[index] { continue; }
                    peer.scheduler.add_path(format!("path{index}"), frame.id & 256 != 0)?;
                    peer.scheduler.policy = number_policy(frame.id);
                    peer.ack_batching = frame.id & FEATURE_ACK_BATCH != 0;
                    peer.udp_enabled |= frame.id & FEATURE_UDP_LANE != 0;
                    peer.path_failure_enabled |= frame.id & FEATURE_PATH_FAILURE != 0;
                    peer.addresses[index] = Some(address);
                    peer.join_stamps[index] = frame.stamp;
                } else if peer.addresses.get(index).copied().flatten().is_none() {
                    // Path was announced but never bound (shouldn't happen in practice); ignore.
                    continue;
                } else if peer.addresses.get(index) != Some(&Some(address)) {
                    // NAT rebind (common on cellular hotspots): packet already passed AEAD auth,
                    // so it's provably from the session owner. Rebind the return address.
                    peer.addresses[index] = Some(address);
                }
                peer.last_seen = Instant::now();
                if frame.kind == Kind::Close { peers.remove(&header.session); continue; }
                if frame.kind == Kind::Udp {
                    if !peer.udp_enabled { continue; }
                    let Ok(packet) = peer.udp.decode(&frame.body) else { continue; };
                    if packet.link != frame.path { continue; }
                    if packet.is_data() && (validate_ipv4(&packet.payload, Some(peer.assigned), None).is_err() || !destination_allowed(&packet.payload)) { continue; }
                    peer.scheduler.paths[index].received_bytes += packet.payload.len() as u64;
                    udp_server_action(peer, UdpAction::Receive(packet, frame.body), &socket, now(epoch));
                    drain_udp(&mut peer.udp, &udp_writer)?;
                    continue;
                }
                if frame.kind == Kind::PathDown {
                    if !peer.path_failure_enabled { continue; }
                    let Ok(failed) = usize::try_from(frame.id) else { continue; };
                    if failed >= peer.addresses.len() || failed == index { continue; }
                    if stale_path_down(frame.stamp, peer.join_stamps[failed]) { continue; }
                    if peer.scheduler.fail_path_remote(failed) {
                        peer.addresses[failed] = None;
                    }
                    continue;
                }
                if frame.kind == Kind::Data && (validate_ipv4(&frame.body, Some(peer.assigned), None).is_err() || !destination_allowed(&frame.body)) { continue; }
                let mut responses = receive_to_writer(&mut peer.scheduler, &writer, &frame, now(epoch))?;
                if frame.kind == Kind::Join && peer.ack_batching {
                    for response in &mut responses { response.kind = Kind::JoinAck; }
                }
                if frame.kind == Kind::Join && peer.udp_enabled {
                    responses.push(Frame::control(Kind::UdpReady, frame.path, FEATURE_UDP_LANE, frame.stamp));
                }
                if frame.kind == Kind::Join && peer.path_failure_enabled {
                    responses.push(Frame::control(Kind::PathFailureReady, frame.path, FEATURE_PATH_FAILURE, frame.stamp));
                }
                send_server(&socket, peer, responses, &mut egress)?;
            }
            count = intake.recv_batch(&mut intake_batch) => {
                if count == 0 {
                    (&mut intake.task).await.context("TUN intake task")??;
                    anyhow::bail!("TUN intake stopped");
                }
                for packet in intake_batch.drain(..) {
                    let ip = packet.bytes;
                    if validate_ipv4(&ip, None, None).is_err() { continue; }
                    if let Some(peer) = peers.values_mut().find(|peer| ip[16..20] == peer.assigned) {
                        if peer.udp_enabled && udp_lane::is_udp(&ip) {
                            udp_server_action(peer, UdpAction::Send(ip), &socket, now(epoch));
                        } else { peer.scheduler.enqueue(ip); }
                    }
                }
            }
        }
    }
    Ok(())
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    match Cli::parse().command {
        Mode::Server(args) => server(args).await,
        Mode::BrainServer(args) => verz_link_lab::brain::run_server(args).await,
        Mode::Client(args) => client(args).await,
        Mode::Direct(args) => verz_link_lab::direct::run(args).await,
        Mode::Hybrid(args) => hybrid(args).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn newer_authenticated_join_supersedes_delayed_path_down() {
        assert!(stale_path_down(4_000, 5_000));
        assert!(stale_path_down(5_000, 5_000));
        assert!(!stale_path_down(5_001, 5_000));
        assert!(!stale_path_down(1, 0));
    }

    #[tokio::test]
    async fn repo_udp_socket_writer_encrypts_full_fragments_and_survives_socket_removal()
    -> Result<()> {
        let secret = [42; 32];
        let session = [9; 16];
        let mut initiator = handshake(&secret, &session, true)?;
        let mut responder = handshake(&secret, &session, false)?;
        let mut wire = [0; MAX_WIRE];
        let mut plain = [0; MAX_WIRE];
        let len = initiator.write_message(&[], &mut wire)?;
        responder.read_message(&wire[..len], &mut plain)?;
        let len = responder.write_message(&[], &mut wire)?;
        initiator.read_message(&wire[..len], &mut plain)?;
        let mut transport = bond_transport(session, initiator)?;
        let mut remote = bond_transport(session, responder)?;
        let receiver = UdpSocket::bind("127.0.0.1:0").await?;
        let wifi = UdpSocket::bind("127.0.0.1:0").await?;
        wifi.connect(receiver.local_addr()?).await?;
        wifi.writable().await?;
        let mut lan = Some(UdpSocket::bind("127.0.0.1:0").await?);
        lan.as_ref()
            .unwrap()
            .connect(receiver.local_addr()?)
            .await?;
        lan.as_ref().unwrap().writable().await?;
        let mut scheduler = Scheduler::new(
            vec![("wifi".into(), false), ("lan".into(), false)],
            Policy::Smart,
        )?;
        for at in [10, 20, 30] {
            for id in 0..2 {
                scheduler.receive(&Frame::control(Kind::Pong, id, 0, at - 5), at);
            }
        }
        for p in &mut scheduler.paths {
            p.in_flight = p.congestion_window;
        }
        let paths = udp_lane::links(&scheduler, 30);
        let mut udp = UdpLane::new(&secret, &session, Policy::Smart)?;
        let mut received = UdpLane::new(&secret, &session, Policy::Smart)?;
        let mut ip = vec![0x5a; BOND_MTU];
        ip[0] = 0x45;
        ip[9] = 17;
        ip[6] = 0;
        ip[7] = 0;
        ip[2..4].copy_from_slice(&(BOND_MTU as u16).to_be_bytes());
        for n in 0..8u64 {
            if n == 2 {
                lan = None;
            }
            if n == 5 {
                let socket = UdpSocket::bind("127.0.0.1:0").await?;
                socket.connect(receiver.local_addr()?).await?;
                socket.writable().await?;
                lan = Some(socket);
            }
            let mut writer = UdpSocketWriter {
                transport: &mut transport,
                scheduler: &mut scheduler,
                sockets: vec![Some((&wifi, None)), lan.as_ref().map(|s| (s, None))],
                physical: false,
            };
            udp.send(&ip, &paths, Policy::Smart, 40 + n, &mut writer)?;
            for _ in 0..if lan.is_some() { 2 } else { 1 } {
                let size =
                    time::timeout(Duration::from_millis(100), receiver.recv(&mut wire)).await??;
                ensure!(
                    size + 28 <= 1500,
                    "encrypted UDP lane exceeds normal WAN MTU"
                );
                let mut tampered = wire[..size].to_vec();
                tampered[size - 1] ^= 1;
                ensure!(remote.open(&tampered).is_err(), "tampered packet accepted");
                let (_, body) = remote.open(&wire[..size])?;
                let frame = Frame::decode(&body)?;
                assert_eq!(frame.kind, Kind::Udp);
                let packet = received.decode(&frame.body)?;
                assert_eq!(packet.sequence, n as u32);
                received.receive(packet, 40 + n)?;
                ensure!(
                    remote.open(&wire[..size]).is_err(),
                    "encrypted replay accepted"
                );
            }
            assert_eq!(received.pop(), Some(ip.clone()));
            assert!(received.pop().is_none());
        }
        assert_eq!(scheduler.pending_packets(), 0);
        assert_eq!(udp.counters.send_failures, 0);
        Ok(())
    }

    #[tokio::test]
    async fn pending_rejoin_is_sent_before_subsequent_probe() -> Result<()> {
        let secret = [42; 32];
        let session = [9; 16];
        let mut initiator = handshake(&secret, &session, true)?;
        let mut responder = handshake(&secret, &session, false)?;
        let mut wire = [0; MAX_WIRE];
        let mut plain = [0; MAX_WIRE];
        let len = initiator.write_message(&[], &mut wire)?;
        responder.read_message(&wire[..len], &mut plain)?;
        let len = responder.write_message(&[], &mut wire)?;
        initiator.read_message(&wire[..len], &mut plain)?;
        let mut tx = bond_transport(session, initiator)?;
        let mut rx = bond_transport(session, responder)?;
        let server = UdpSocket::bind("127.0.0.1:0").await?;
        let (sender, _input) = mpsc::channel(8);
        let name = if cfg!(target_os = "macos") {
            "lo0"
        } else {
            "lo"
        };
        let mut path = open_subflow(name, server.local_addr()?, 0, sender)?;
        // Model Join retained after WouldBlock on a newly opened socket.
        path.pending_join = Some(tx.seal(IP, &Frame::control(Kind::Join, 0, 0, 1).encode())?);
        path.socket.writable().await?;
        let mut paths = vec![Some(path)];
        let mut scheduler = Scheduler::new(vec![(name.into(), false)], Policy::Smart)?;
        send_client(
            vec![Frame::control(Kind::Probe, 0, 2, 2)],
            &mut tx,
            &mut paths,
            &mut scheduler,
        )?;
        for expected in [Kind::Join, Kind::Probe] {
            let (len, _) =
                time::timeout(Duration::from_secs(1), server.recv_from(&mut wire)).await??;
            let (_, bytes) = rx.open(&wire[..len])?;
            assert_eq!(Frame::decode(&bytes)?.kind, expected);
        }
        assert!(paths[0].as_ref().unwrap().pending_join.is_none());
        Ok(())
    }

    #[tokio::test]
    async fn blocked_tun_writer_refuses_before_ack_and_accepts_retry() -> Result<()> {
        let (sender, mut receiver) = mpsc::channel(1);
        let writer = PacketWriter {
            sender,
            task: tokio::spawn(std::future::pending()),
            reorder: Default::default(),
            udp_payload: Default::default(),
            udp_unmeasured: Default::default(),
        };
        let mut scheduler = Scheduler::new(vec![("one-source".into(), false)], Policy::Smart)?;
        let first = data(0);
        let next = data(1);
        assert_eq!(
            receive_to_writer(&mut scheduler, &writer, &first, 0)?.len(),
            1
        );
        assert!(receive_to_writer(&mut scheduler, &writer, &next, 1)?.is_empty());
        assert!(!scheduler.has_received(1));
        assert_eq!(scheduler.counters.receive_backpressure, 1);
        assert_eq!(scheduler.counters.delivered_packets, 1);
        // Existing ACKs and health probes do not require a free data slot.
        assert_eq!(
            receive_to_writer(&mut scheduler, &writer, &first, 2)?.len(),
            1
        );
        let probe = Frame::control(Kind::Probe, 0, 7, 2);
        assert_eq!(
            receive_to_writer(&mut scheduler, &writer, &probe, 2)?[0].kind,
            Kind::Pong
        );
        assert_eq!(receiver.try_recv()?, first.body);
        assert_eq!(
            receive_to_writer(&mut scheduler, &writer, &next, 70)?.len(),
            1
        );
        assert_eq!(receiver.try_recv()?, next.body);
        assert_eq!(scheduler.counters.delivered_packets, 2);
        assert_eq!(scheduler.counters.queue_drops, 0);
        Ok(())
    }

    fn data(id: u64) -> Frame {
        let mut ip = vec![0; 140];
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&140_u16.to_be_bytes());
        ip[9] = 6;
        ip[32] = 0x50;
        ip[24..28].copy_from_slice(&(id as u32 * 100).to_be_bytes());
        Frame {
            kind: Kind::Data,
            path: 0,
            id,
            stamp: 0,
            body: ip,
        }
    }

    #[tokio::test]
    async fn reordered_burst_larger_than_admission_queue_is_written_without_loss() -> Result<()> {
        let mut reorder = TcpReorder::default();
        assert_eq!(reorder.push(data(0).body, 0).len(), 1);
        for id in 2..1500 {
            assert!(reorder.push(data(id).body, 1).is_empty());
        }
        let burst = reorder.push(data(1).body, 41);
        assert_eq!(burst.len(), 1499);
        let mut written = Vec::new();
        write_batch(burst, &mut |packet| {
            written.push(packet);
            std::future::ready(Ok(()))
        })
        .await?;
        assert_eq!(
            written,
            (1..1500).map(|id| data(id).body).collect::<Vec<_>>()
        );
        Ok(())
    }

    #[tokio::test]
    async fn admission_budget_is_shared_between_clients_without_false_acks() -> Result<()> {
        let (sender, mut receiver) = mpsc::channel(1);
        let writer = PacketWriter {
            sender,
            task: tokio::spawn(std::future::pending()),
            reorder: Default::default(),
            udp_payload: Default::default(),
            udp_unmeasured: Default::default(),
        };
        let mut a = Scheduler::new(vec![("a".into(), false)], Policy::Smart)?;
        let mut b = Scheduler::new(vec![("b".into(), false)], Policy::Smart)?;
        assert_eq!(receive_to_writer(&mut a, &writer, &data(0), 0)?.len(), 1);
        assert!(receive_to_writer(&mut b, &writer, &data(0), 1)?.is_empty());
        assert!(!b.has_received(0));
        receiver.try_recv()?;
        assert_eq!(receive_to_writer(&mut b, &writer, &data(0), 2)?.len(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn writer_failure_is_reported_not_silently_discarded() {
        let (sender, receiver) = mpsc::channel(1);
        sender.send(data(0).body).await.unwrap();
        let error = run_packet_writer(receiver, |_| {
            std::future::ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "test TUN failure",
            )))
        })
        .await
        .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
    }

    #[tokio::test]
    async fn closed_writer_does_not_acknowledge_or_mark_new_data() -> Result<()> {
        let (sender, receiver) = mpsc::channel(1);
        drop(receiver);
        let writer = PacketWriter {
            sender,
            task: tokio::spawn(std::future::pending()),
            reorder: Default::default(),
            udp_payload: Default::default(),
            udp_unmeasured: Default::default(),
        };
        let mut scheduler = Scheduler::new(vec![("one-source".into(), false)], Policy::Smart)?;
        assert!(receive_to_writer(&mut scheduler, &writer, &data(0), 0).is_err());
        assert!(!scheduler.has_received(0));
        Ok(())
    }
}
