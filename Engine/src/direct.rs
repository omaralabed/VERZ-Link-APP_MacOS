//! Direct Smart mode: a local SOCKS5 TCP flow engine. Application payloads go
//! straight to their destinations and retain only the application's own
//! encryption. Each TCP connection is pinned to one selected physical uplink.
use crate::{
    bind_ipv4_interface_fd,
    bond::Policy,
    brain::{BrainClient, ClientReport, PathReport},
    load_secret,
};
use anyhow::{Context, Result, bail, ensure};
use clap::Args;
use serde::Deserialize;
use serde_json::json;
use std::{
    collections::BTreeMap,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    os::fd::AsRawFd,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpSocket, TcpStream, lookup_host},
    sync::{RwLock, mpsc},
    time,
};

const DEFAULT_LATENCY_CUTOFF_US: u64 = 75_000;
const PROBE_DESTINATION: &str = "1.1.1.1:443";

#[derive(Args, Debug)]
pub struct DirectArgs {
    #[arg(long, default_value = "127.0.0.1:0")]
    pub listen: SocketAddr,
    /// name=IPv4,metered; repeated once per physical adapter.
    #[arg(long, num_args = 1.., required = true)]
    pub path: Vec<String>,
    #[arg(long, value_enum, default_value_t = Policy::Smart)]
    pub policy: Policy,
    #[arg(long)]
    pub control_stdin: bool,
    /// Use the system-routed secure tunnel if every direct path fails.
    #[arg(long)]
    pub relay_fallback: bool,
    /// Domain suffix that must use Secure Continuity; repeatable.
    #[arg(long)]
    pub secure_domain: Vec<String>,
    /// Encrypted scheduling-control service. No application payload is sent.
    #[arg(long)]
    pub brain: Option<SocketAddr>,
    #[arg(long)]
    pub brain_secret_file: Option<PathBuf>,
}

#[derive(Clone, Deserialize)]
pub struct InterfaceConfig {
    pub name: String,
    pub address: Option<String>,
    #[serde(default)]
    pub metered: bool,
}

#[derive(Clone, Deserialize)]
pub struct Control {
    pub interfaces: Vec<InterfaceConfig>,
    pub policy: Option<String>,
    #[serde(default, alias = "secureDomains")]
    pub secure_domains: Option<Vec<String>>,
}

#[derive(Debug)]
struct Path {
    name: String,
    address: Ipv4Addr,
    metered: bool,
    healthy: AtomicBool,
    rtt_us: AtomicU64,
    sent: AtomicU64,
    received: AtomicU64,
    failures: AtomicU64,
}

impl Path {
    fn new(name: String, address: Ipv4Addr, metered: bool) -> Result<Self> {
        ensure!(valid_interface(&name), "invalid physical interface name");
        ensure!(
            !address.is_loopback() && !address.is_unspecified(),
            "invalid path IPv4 address"
        );
        Ok(Self {
            name,
            address,
            metered,
            healthy: AtomicBool::new(true),
            rtt_us: AtomicU64::new(0),
            sent: AtomicU64::new(0),
            received: AtomicU64::new(0),
            failures: AtomicU64::new(0),
        })
    }
}

#[derive(Clone)]
struct Runtime {
    paths: Arc<RwLock<Vec<Arc<Path>>>>,
    policy: Arc<AtomicUsize>,
    cursor: Arc<AtomicUsize>,
    active: Arc<AtomicU64>,
    accepted: Arc<AtomicU64>,
    direct_connections: Arc<AtomicU64>,
    relay_connections: Arc<AtomicU64>,
    relay_fallback: Arc<AtomicBool>,
    cutoff_us: Arc<AtomicU64>,
    brain_weights: Arc<RwLock<BTreeMap<String, u32>>>,
    secure_domains: Arc<RwLock<Vec<String>>>,
}

impl Runtime {
    async fn candidates(&self) -> Vec<Arc<Path>> {
        let all = self.paths.read().await.clone();
        if all.is_empty() {
            return all;
        }
        let mut eligible: Vec<_> = all
            .iter()
            .filter(|p| p.healthy.load(Ordering::Relaxed))
            .cloned()
            .collect();
        if eligible.is_empty() {
            eligible = all;
        }
        let has_low_latency = eligible.iter().any(|p| {
            let rtt = p.rtt_us.load(Ordering::Relaxed);
            rtt > 0 && rtt < self.cutoff_us.load(Ordering::Relaxed)
        });
        if has_low_latency {
            eligible.retain(|p| {
                let rtt = p.rtt_us.load(Ordering::Relaxed);
                rtt == 0 || rtt < self.cutoff_us.load(Ordering::Relaxed)
            });
        } else if eligible.len() > 1
            && eligible
                .iter()
                .all(|p| p.rtt_us.load(Ordering::Relaxed) > 0)
        {
            // If every reachable path is slow, keep the best one as a last
            // resort instead of blackholing traffic or rotating onto worse RTT.
            eligible.sort_by_key(|p| p.rtt_us.load(Ordering::Relaxed));
            eligible.truncate(1);
        }
        let policy = number_policy(self.policy.load(Ordering::Relaxed));
        if policy == Policy::DataSaver && eligible.iter().any(|p| !p.metered) {
            eligible.retain(|p| !p.metered);
        }
        let weights = self.brain_weights.read().await;
        if !weights.is_empty()
            && eligible
                .iter()
                .any(|path| weights.get(&path.name).copied().unwrap_or(0) > 0)
        {
            eligible.retain(|path| weights.get(&path.name).copied().unwrap_or(0) > 0);
        }
        if policy == Policy::Continuity {
            eligible.sort_by_key(|p| {
                let rtt = p.rtt_us.load(Ordering::Relaxed);
                if rtt == 0 { u64::MAX - 1 } else { rtt }
            });
        } else {
            let total: usize = eligible
                .iter()
                .map(|path| weights.get(&path.name).copied().unwrap_or(1).max(1) as usize)
                .sum();
            let mut ticket = self.cursor.fetch_add(1, Ordering::Relaxed) % total;
            let mut offset = 0;
            for (index, path) in eligible.iter().enumerate() {
                let weight = weights.get(&path.name).copied().unwrap_or(1).max(1) as usize;
                if ticket < weight {
                    offset = index;
                    break;
                }
                ticket -= weight;
            }
            eligible.rotate_left(offset);
        }
        eligible
    }

    async fn must_relay(&self, host: &str) -> bool {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        self.secure_domains.read().await.iter().any(|suffix| {
            host == *suffix
                || host
                    .strip_suffix(suffix)
                    .is_some_and(|prefix| prefix.ends_with('.'))
        })
    }
}

fn valid_interface(name: &str) -> bool {
    !name.is_empty() && name.len() < 16 && name.chars().all(|c| c.is_ascii_alphanumeric())
}

fn parse_path(value: &str) -> Result<Arc<Path>> {
    let (name, rest) = value
        .split_once('=')
        .context("path must be name=IPv4,metered")?;
    let (address, metered) = rest.split_once(',').unwrap_or((rest, "false"));
    let metered = match metered {
        "true" | "1" => true,
        "false" | "0" => false,
        _ => bail!("path metered flag must be true or false"),
    };
    Ok(Arc::new(Path::new(
        name.to_owned(),
        address.parse()?,
        metered,
    )?))
}

fn policy_number(policy: Policy) -> usize {
    match policy {
        Policy::Smart => 0,
        Policy::Performance => 1,
        Policy::Continuity => 2,
        Policy::DataSaver => 3,
    }
}

fn number_policy(value: usize) -> Policy {
    match value {
        1 => Policy::Performance,
        2 => Policy::Continuity,
        3 => Policy::DataSaver,
        _ => Policy::Smart,
    }
}

fn parse_policy(value: &str) -> Option<Policy> {
    match value {
        "smart" => Some(Policy::Smart),
        "performance" => Some(Policy::Performance),
        "continuity" => Some(Policy::Continuity),
        "data-saver" => Some(Policy::DataSaver),
        _ => None,
    }
}

async fn connect_on(path: &Path, destination: SocketAddr) -> Result<TcpStream> {
    ensure!(
        destination.is_ipv4(),
        "Direct Smart currently supports IPv4 destinations"
    );
    let socket = TcpSocket::new_v4()?;
    bind_ipv4_interface_fd(socket.as_raw_fd(), &path.name)?;
    socket.bind(SocketAddrV4::new(path.address, 0).into())?;
    let stream = time::timeout(Duration::from_secs(6), socket.connect(destination))
        .await
        .context("outbound TCP connection timed out")??;
    stream.set_nodelay(true)?;
    Ok(stream)
}

async fn connect_via_system_route(destination: SocketAddr) -> Result<TcpStream> {
    let stream = time::timeout(Duration::from_secs(6), TcpStream::connect(destination))
        .await
        .context("secure relay fallback timed out")??;
    stream.set_nodelay(true)?;
    Ok(stream)
}

fn normalize_domains(domains: Vec<String>) -> Result<Vec<String>> {
    let mut normalized = Vec::new();
    for domain in domains {
        let domain = domain
            .trim()
            .trim_start_matches('.')
            .trim_end_matches('.')
            .to_ascii_lowercase();
        ensure!(
            !domain.is_empty()
                && domain.len() <= 253
                && domain.split('.').all(|label| !label.is_empty()
                    && label.len() <= 63
                    && !label.starts_with('-')
                    && !label.ends_with('-')
                    && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')),
            "invalid secure domain suffix"
        );
        if !normalized.contains(&domain) {
            normalized.push(domain);
        }
    }
    Ok(normalized)
}

async fn resolve(host: &str, port: u16) -> Result<Vec<SocketAddr>> {
    if let Ok(address) = host.parse::<Ipv4Addr>() {
        return Ok(vec![SocketAddrV4::new(address, port).into()]);
    }
    let addresses: Vec<_> = lookup_host((host, port))
        .await?
        .filter(SocketAddr::is_ipv4)
        .collect();
    ensure!(!addresses.is_empty(), "destination has no IPv4 address");
    Ok(addresses)
}

async fn socks_target(stream: &mut TcpStream) -> Result<(String, u16)> {
    let mut greeting = [0_u8; 2];
    stream.read_exact(&mut greeting).await?;
    ensure!(
        greeting[0] == 5 && greeting[1] > 0,
        "invalid SOCKS5 greeting"
    );
    let mut methods = vec![0_u8; usize::from(greeting[1])];
    stream.read_exact(&mut methods).await?;
    if !methods.contains(&0) {
        stream.write_all(&[5, 0xff]).await?;
        bail!("SOCKS client does not support no-auth mode");
    }
    stream.write_all(&[5, 0]).await?;
    let mut request = [0_u8; 4];
    stream.read_exact(&mut request).await?;
    ensure!(
        request[0] == 5 && request[1] == 1 && request[2] == 0,
        "only SOCKS5 CONNECT is supported"
    );
    let host = match request[3] {
        1 => {
            let mut address = [0_u8; 4];
            stream.read_exact(&mut address).await?;
            Ipv4Addr::from(address).to_string()
        }
        3 => {
            let length = stream.read_u8().await?;
            ensure!(length > 0, "empty SOCKS destination");
            let mut bytes = vec![0_u8; usize::from(length)];
            stream.read_exact(&mut bytes).await?;
            String::from_utf8(bytes).context("SOCKS destination is not UTF-8")?
        }
        4 => {
            stream.write_all(&[5, 8, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
            bail!("Direct Smart IPv6 support is not enabled yet");
        }
        _ => bail!("invalid SOCKS address type"),
    };
    let port = stream.read_u16().await?;
    Ok((host, port))
}

async fn handle_connection(mut client: TcpStream, runtime: Runtime) -> Result<()> {
    let (host, port) = socks_target(&mut client).await?;
    let destinations = resolve(&host, port).await?;
    let forced_relay = runtime.must_relay(&host).await;
    let mut selected: Option<(Option<Arc<Path>>, TcpStream)> = None;
    if !forced_relay {
        for path in runtime.candidates().await {
            for destination in &destinations {
                let started = Instant::now();
                match connect_on(&path, *destination).await {
                    Ok(stream) => {
                        let observed =
                            started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64;
                        let prior = path.rtt_us.load(Ordering::Relaxed);
                        path.rtt_us.store(
                            if prior == 0 {
                                observed
                            } else {
                                (prior * 7 + observed) / 8
                            },
                            Ordering::Relaxed,
                        );
                        path.healthy.store(true, Ordering::Relaxed);
                        selected = Some((Some(path), stream));
                        break;
                    }
                    Err(_) => {
                        path.failures.fetch_add(1, Ordering::Relaxed);
                        path.healthy.store(false, Ordering::Relaxed);
                    }
                }
            }
            if selected.is_some() {
                break;
            }
        }
    }
    if selected.is_none() && (forced_relay || runtime.relay_fallback.load(Ordering::Relaxed)) {
        for destination in &destinations {
            if let Ok(stream) = connect_via_system_route(*destination).await {
                selected = Some((None, stream));
                break;
            }
        }
    }
    let Some((path, mut outbound)) = selected else {
        client.write_all(&[5, 4, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
        bail!("no route succeeded for {host}:{port}");
    };
    let local = match outbound.local_addr()? {
        SocketAddr::V4(address) => address,
        SocketAddr::V6(_) => SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0),
    };
    let mut reply = vec![5, 0, 0, 1];
    reply.extend_from_slice(&local.ip().octets());
    reply.extend_from_slice(&local.port().to_be_bytes());
    client.write_all(&reply).await?;
    runtime.active.fetch_add(1, Ordering::Relaxed);
    runtime.accepted.fetch_add(1, Ordering::Relaxed);
    if path.is_some() {
        runtime.direct_connections.fetch_add(1, Ordering::Relaxed);
    } else {
        runtime.relay_connections.fetch_add(1, Ordering::Relaxed);
    }
    let result = tokio::io::copy_bidirectional(&mut client, &mut outbound).await;
    runtime.active.fetch_sub(1, Ordering::Relaxed);
    let (uploaded, downloaded) = result?;
    if let Some(path) = path {
        path.sent.fetch_add(uploaded, Ordering::Relaxed);
        path.received.fetch_add(downloaded, Ordering::Relaxed);
    }
    Ok(())
}

async fn probe(runtime: Runtime) {
    let destination: SocketAddr = PROBE_DESTINATION.parse().expect("fixed probe destination");
    let mut interval = time::interval(Duration::from_secs(1));
    interval.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
    loop {
        interval.tick().await;
        let paths = runtime.paths.read().await.clone();
        for path in paths {
            tokio::spawn(async move {
                let started = Instant::now();
                match connect_on(&path, destination).await {
                    Ok(_) => {
                        let observed =
                            started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64;
                        let prior = path.rtt_us.load(Ordering::Relaxed);
                        path.rtt_us.store(
                            if prior == 0 {
                                observed
                            } else {
                                (prior * 7 + observed) / 8
                            },
                            Ordering::Relaxed,
                        );
                        path.healthy.store(true, Ordering::Relaxed);
                    }
                    Err(_) => {
                        path.failures.fetch_add(1, Ordering::Relaxed);
                        path.healthy.store(false, Ordering::Relaxed);
                    }
                }
            });
        }
    }
}

async fn telemetry(runtime: Runtime) {
    let mut interval = time::interval(Duration::from_secs(1));
    loop {
        interval.tick().await;
        let paths = runtime.paths.read().await.clone();
        let cutoff = runtime.cutoff_us.load(Ordering::Relaxed);
        let has_fast = paths.iter().any(|p| {
            let rtt = p.rtt_us.load(Ordering::Relaxed);
            p.healthy.load(Ordering::Relaxed) && rtt > 0 && rtt < cutoff
        });
        let best_slow = (!has_fast).then(|| {
            paths
                .iter()
                .filter(|p| p.healthy.load(Ordering::Relaxed))
                .map(|p| p.rtt_us.load(Ordering::Relaxed))
                .filter(|rtt| *rtt > 0)
                .min()
                .unwrap_or(0)
        });
        let reports: Vec<_> = paths.iter().enumerate().map(|(id, path)| {
            let healthy = path.healthy.load(Ordering::Relaxed);
            let rtt = path.rtt_us.load(Ordering::Relaxed);
            let excluded = if has_fast {
                rtt >= cutoff
            } else {
                best_slow.is_some_and(|best| best > 0 && rtt > best)
            };
            json!({
                "id": id, "name": path.name, "state": if healthy { "healthy" } else { "offline" },
                "enabled": true, "rtt_ms": if rtt == 0 { None } else { Some(rtt as f64 / 1000.0) },
                "jitter_ms": 0.0, "sent_bytes": path.sent.load(Ordering::Relaxed),
                "received_bytes": path.received.load(Ordering::Relaxed), "acknowledged_bytes": 0,
                "delivery_bps": 0.0, "latency_excluded": excluded,
                "connect_failures": path.failures.load(Ordering::Relaxed)
            })
        }).collect();
        let healthy = paths
            .iter()
            .filter(|p| p.healthy.load(Ordering::Relaxed))
            .count();
        println!(
            "DIRECT_STATE {}",
            json!({
                "paths": reports, "healthy_paths": healthy, "assigned_ip": "", "server_ip": "",
                "active_connections": runtime.active.load(Ordering::Relaxed),
                "accepted_connections": runtime.accepted.load(Ordering::Relaxed),
                "direct_connections": runtime.direct_connections.load(Ordering::Relaxed),
                "relay_connections": runtime.relay_connections.load(Ordering::Relaxed),
                "cutoff_ms": cutoff as f64 / 1000.0
            })
        );
    }
}

async fn brain(runtime: Runtime, address: SocketAddr, secret_file: PathBuf) {
    let Ok(secret) = load_secret(&secret_file) else {
        println!(
            "BRAIN_STATE {}",
            json!({"connected":false,"generation":0,"strategy":"local-fallback"})
        );
        return;
    };
    loop {
        let mut connected = None;
        for path in runtime.candidates().await {
            let stream = time::timeout(Duration::from_secs(4), connect_on(&path, address)).await;
            if let Ok(Ok(stream)) = stream
                && let Ok(Ok(client)) = time::timeout(
                    Duration::from_secs(4),
                    BrainClient::from_stream(stream, &secret),
                )
                .await
            {
                connected = Some(client);
                break;
            }
        }
        let Some(mut client) = connected else {
            println!(
                "BRAIN_STATE {}",
                json!({"connected":false,"generation":0,"strategy":"local-fallback"})
            );
            time::sleep(Duration::from_secs(2)).await;
            continue;
        };
        loop {
            let paths = runtime.paths.read().await.clone();
            let report = ClientReport {
                policy: number_policy(runtime.policy.load(Ordering::Relaxed)),
                paths: paths
                    .iter()
                    .map(|path| {
                        let rtt = path.rtt_us.load(Ordering::Relaxed);
                        PathReport {
                            name: path.name.clone(),
                            rtt_ms: (rtt > 0).then_some(rtt as f64 / 1000.0),
                            healthy: path.healthy.load(Ordering::Relaxed),
                            metered: path.metered,
                            failures: path.failures.load(Ordering::Relaxed),
                        }
                    })
                    .collect(),
            };
            let response = time::timeout(Duration::from_secs(3), client.exchange(&report)).await;
            let Ok(Ok(advice)) = response else {
                break;
            };
            if (10.0..=1000.0).contains(&advice.cutoff_ms) {
                runtime
                    .cutoff_us
                    .store((advice.cutoff_ms * 1000.0) as u64, Ordering::Relaxed);
            }
            *runtime.brain_weights.write().await = advice.weights.clone();
            runtime
                .relay_fallback
                .store(advice.relay_fallback, Ordering::Relaxed);
            println!(
                "BRAIN_STATE {}",
                json!({"connected":true,"generation":advice.generation,"strategy":advice.strategy})
            );
            time::sleep(Duration::from_secs(1)).await;
        }
        println!(
            "BRAIN_STATE {}",
            json!({"connected":false,"generation":0,"strategy":"local-fallback"})
        );
        time::sleep(Duration::from_secs(2)).await;
    }
}

async fn controls(runtime: Runtime) -> Result<()> {
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    while let Some(line) = lines.next_line().await? {
        apply_control(&runtime, serde_json::from_str(&line)?).await;
    }
    Ok(())
}

async fn external_controls(runtime: Runtime, mut receiver: mpsc::Receiver<Control>) {
    while let Some(value) = receiver.recv().await {
        apply_control(&runtime, value).await;
    }
}

async fn apply_control(runtime: &Runtime, value: Control) {
    let existing = runtime.paths.read().await.clone();
    let paths: Vec<_> = value
        .interfaces
        .into_iter()
        .filter_map(|item| {
            let address: Ipv4Addr = item.address?.parse().ok()?;
            existing
                .iter()
                .find(|path| {
                    path.name == item.name
                        && path.address == address
                        && path.metered == item.metered
                })
                .cloned()
                .or_else(|| {
                    Path::new(item.name, address, item.metered)
                        .ok()
                        .map(Arc::new)
                })
        })
        .collect();
    if !paths.is_empty() {
        *runtime.paths.write().await = paths;
    }
    if let Some(policy) = value.policy.as_deref().and_then(parse_policy) {
        runtime
            .policy
            .store(policy_number(policy), Ordering::Relaxed);
    }
    if let Some(domains) = value.secure_domains
        && let Ok(domains) = normalize_domains(domains)
    {
        *runtime.secure_domains.write().await = domains;
    }
}

async fn stop_signal() {
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("SIGTERM handler");
        tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = term.recv() => {} }
    }
    #[cfg(not(unix))]
    let _ = tokio::signal::ctrl_c().await;
}

pub async fn run(args: DirectArgs) -> Result<()> {
    run_with_controls(args, None).await
}

pub async fn run_with_controls(
    args: DirectArgs,
    external: Option<mpsc::Receiver<Control>>,
) -> Result<()> {
    ensure!(
        args.listen.ip().is_loopback(),
        "Direct Smart must listen only on loopback"
    );
    let paths: Vec<_> = args
        .path
        .iter()
        .map(|value| parse_path(value))
        .collect::<Result<_>>()?;
    ensure!(
        !paths.is_empty(),
        "Direct Smart needs at least one usable path"
    );
    ensure!(
        args.brain.is_some() == args.brain_secret_file.is_some(),
        "brain address and secret file must be configured together"
    );
    let secure_domains = normalize_domains(args.secure_domain)?;
    let runtime = Runtime {
        paths: Arc::new(RwLock::new(paths)),
        policy: Arc::new(AtomicUsize::new(policy_number(args.policy))),
        cursor: Arc::new(AtomicUsize::new(0)),
        active: Arc::new(AtomicU64::new(0)),
        accepted: Arc::new(AtomicU64::new(0)),
        direct_connections: Arc::new(AtomicU64::new(0)),
        relay_connections: Arc::new(AtomicU64::new(0)),
        relay_fallback: Arc::new(AtomicBool::new(args.relay_fallback)),
        cutoff_us: Arc::new(AtomicU64::new(DEFAULT_LATENCY_CUTOFF_US)),
        brain_weights: Arc::new(RwLock::new(BTreeMap::new())),
        secure_domains: Arc::new(RwLock::new(secure_domains)),
    };
    let listener = TcpListener::bind(args.listen).await?;
    println!("DIRECT CONNECTED: {}", listener.local_addr()?);
    tokio::spawn(probe(runtime.clone()));
    tokio::spawn(telemetry(runtime.clone()));
    if let (Some(address), Some(secret_file)) = (args.brain, args.brain_secret_file) {
        tokio::spawn(brain(runtime.clone(), address, secret_file));
    }
    if let Some(receiver) = external {
        tokio::spawn(external_controls(runtime.clone(), receiver));
    } else if args.control_stdin {
        let control_runtime = runtime.clone();
        tokio::spawn(async move {
            if let Err(error) = controls(control_runtime).await {
                eprintln!("Direct control: {error}");
            }
        });
    }
    loop {
        tokio::select! {
            incoming = listener.accept() => {
                let (stream, address) = incoming?;
                if !address.ip().is_loopback() { continue; }
                let runtime = runtime.clone();
                tokio::spawn(async move {
                    // Individual applications commonly reset speculative or
                    // cancelled connections. That is flow-local, not a VERZ
                    // engine failure and must not alarm or stop other traffic.
                    let _ = handle_connection(stream, runtime).await;
                });
            }
            _ = stop_signal() => break,
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn runtime(paths: Vec<Arc<Path>>, policy: Policy) -> Runtime {
        Runtime {
            paths: Arc::new(RwLock::new(paths)),
            policy: Arc::new(AtomicUsize::new(policy_number(policy))),
            cursor: Arc::new(AtomicUsize::new(0)),
            active: Arc::new(AtomicU64::new(0)),
            accepted: Arc::new(AtomicU64::new(0)),
            direct_connections: Arc::new(AtomicU64::new(0)),
            relay_connections: Arc::new(AtomicU64::new(0)),
            relay_fallback: Arc::new(AtomicBool::new(false)),
            cutoff_us: Arc::new(AtomicU64::new(DEFAULT_LATENCY_CUTOFF_US)),
            brain_weights: Arc::new(RwLock::new(BTreeMap::new())),
            secure_domains: Arc::new(RwLock::new(Vec::new())),
        }
    }

    #[test]
    fn path_parser_rejects_unsafe_input() {
        assert!(parse_path("en0=192.168.1.2,false").is_ok());
        assert!(parse_path("../bad=192.168.1.2,false").is_err());
        assert!(parse_path("en0=127.0.0.1,false").is_err());
        assert!(parse_path("en0=192.168.1.2,maybe").is_err());
    }

    #[tokio::test]
    async fn scheduler_rotates_complete_flows_and_excludes_slow_path() -> Result<()> {
        let a = parse_path("en0=192.168.1.2,false")?;
        let b = parse_path("en7=192.168.1.3,false")?;
        a.rtt_us.store(20_000, Ordering::Relaxed);
        b.rtt_us.store(40_000, Ordering::Relaxed);
        let runtime = runtime(vec![a.clone(), b.clone()], Policy::Smart);
        assert_eq!(runtime.candidates().await[0].name, "en0");
        assert_eq!(runtime.candidates().await[0].name, "en7");
        b.rtt_us.store(75_000, Ordering::Relaxed);
        assert_eq!(runtime.candidates().await.len(), 1);
        assert_eq!(runtime.candidates().await[0].name, "en0");
        Ok(())
    }

    #[tokio::test]
    async fn data_saver_avoids_metered_path() -> Result<()> {
        let a = parse_path("en0=192.168.1.2,true")?;
        let b = parse_path("en7=192.168.1.3,false")?;
        let runtime = runtime(vec![a, b], Policy::DataSaver);
        assert_eq!(runtime.candidates().await.len(), 1);
        assert_eq!(runtime.candidates().await[0].name, "en7");
        Ok(())
    }

    #[tokio::test]
    async fn all_slow_paths_keep_only_the_lowest_rtt_last_resort() -> Result<()> {
        let a = parse_path("en0=192.168.1.2,false")?;
        let b = parse_path("en7=192.168.1.3,false")?;
        a.rtt_us.store(120_000, Ordering::Relaxed);
        b.rtt_us.store(90_000, Ordering::Relaxed);
        let runtime = runtime(vec![a, b], Policy::Smart);
        let selected = runtime.candidates().await;
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].name, "en7");
        Ok(())
    }

    #[test]
    fn secure_domain_rules_are_normalized_and_validated() {
        assert_eq!(
            normalize_domains(vec![".Example.COM.".into()]).unwrap(),
            vec!["example.com"]
        );
        assert!(normalize_domains(vec!["bad domain".into()]).is_err());
    }
}
