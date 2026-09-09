//! Direct Smart mode: a local SOCKS5 TCP flow engine. Application payloads go
//! straight to their destinations and retain only the application's own
//! encryption. Each TCP connection is pinned to one selected physical uplink.
use crate::{
    bind_ipv4_interface_fd,
    bond::Policy,
    brain::{BrainAdvice, BrainClient, ClientReport, Controller, Guidance, PathReport},
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
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    task::{Context as TaskContext, Poll},
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, ReadBuf},
    net::{TcpListener, TcpSocket, TcpStream, lookup_host},
    sync::{RwLock, mpsc, watch},
    time,
};

const DEFAULT_LATENCY_CUTOFF_US: u64 = 75_000;
const PROBE_DESTINATION: &str = "1.1.1.1:443";
static INCARNATION: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum Intent {
    #[default]
    Balanced,
    Download,
    Upload,
    Realtime,
}
type FlowHistory = Arc<Mutex<BTreeMap<(String, u16), Intent>>>;

fn known_realtime_port(port: u16) -> bool {
    // Explicit RTSP/RTMP/SIP/TURN endpoints. Port 443 is deliberately unknown:
    // it could carry a call, a download, or a web page. No TLS interception.
    matches!(port, 554 | 1935 | 3478 | 5349 | 5060 | 5061)
}

fn direction(uploaded: u64, downloaded: u64) -> Intent {
    if downloaded >= 65_536 && downloaded / 4 > uploaded {
        Intent::Download
    } else if uploaded >= 65_536 && uploaded / 4 > downloaded {
        Intent::Upload
    } else {
        Intent::Balanced
    }
}

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
    active: AtomicU64,
    jitter_us: AtomicU64,
    probe_failure_ppm: AtomicU64,
    probing: AtomicBool,
    incarnation: u64,
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
            active: AtomicU64::new(0),
            jitter_us: AtomicU64::new(0),
            probe_failure_ppm: AtomicU64::new(0),
            probing: AtomicBool::new(false),
            incarnation: INCARNATION.fetch_add(1, Ordering::Relaxed),
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
    brain_advice: Arc<RwLock<Option<(Instant, BrainAdvice)>>>,
    local_advice: Arc<RwLock<Option<BrainAdvice>>>,
    history: FlowHistory,
    epoch: Instant,
    guidance: Option<watch::Sender<Guidance>>,
    secure_domains: Arc<RwLock<Vec<String>>>,
}

impl Runtime {
    async fn candidates(&self, intent: Intent) -> Vec<Arc<Path>> {
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
        let policy = number_policy(self.policy.load(Ordering::Relaxed));
        if policy == Policy::DataSaver && eligible.iter().any(|p| !p.metered) {
            eligible.retain(|p| !p.metered);
        }
        let remote = self.brain_advice.read().await;
        let local = self.local_advice.read().await;
        let advice = remote
            .as_ref()
            .filter(|(at, advice)| {
                advice.valid_for_ms > 0
                    && at.elapsed().as_millis() < u128::from(advice.valid_for_ms.min(5_000))
            })
            .map(|(_, advice)| advice)
            .or(local.as_ref());
        let empty = BTreeMap::new();
        let weights = advice
            .map(|a| match intent {
                Intent::Download => &a.download_weights,
                Intent::Upload => &a.upload_weights,
                Intent::Realtime => &a.realtime_weights,
                Intent::Balanced => &a.weights,
            })
            .unwrap_or(&empty);
        if intent == Intent::Realtime || policy == Policy::Continuity {
            let has_fast = eligible.iter().any(|p| {
                let rtt = p.rtt_us.load(Ordering::Relaxed);
                rtt > 0 && rtt < self.cutoff_us.load(Ordering::Relaxed)
            });
            eligible.sort_by(|a, b| {
                let score = |p: &Path| {
                    let rtt = p.rtt_us.load(Ordering::Relaxed);
                    let local = if rtt == 0 {
                        u64::MAX - 1
                    } else {
                        rtt.saturating_add(p.jitter_us.load(Ordering::Relaxed) * 4)
                            .saturating_add(p.probe_failure_ppm.load(Ordering::Relaxed) / 2)
                    };
                    local as f64
                        / (weights.get(&p.name).copied().unwrap_or(16).clamp(1, 64) as f64).sqrt()
                };
                let delayed = |p: &Path| {
                    has_fast
                        && p.rtt_us.load(Ordering::Relaxed)
                            >= self.cutoff_us.load(Ordering::Relaxed)
                };
                delayed(a)
                    .cmp(&delayed(b))
                    .then_with(|| score(a).total_cmp(&score(b)))
            });
        } else {
            let offset = self.cursor.fetch_add(1, Ordering::Relaxed) % eligible.len();
            eligible.rotate_left(offset);
            // Least assigned work weighted by directional observed goodput.
            // Give every idle link a chance, including links absent from the
            // last brain report. Never let stale/zero advice exclude a healthy
            // bulk path. Established connections are never moved mid-stream.
            eligible.sort_by(|a, b| {
                let score = |p: &Path| {
                    p.active.load(Ordering::Relaxed) as f64
                        / weights.get(&p.name).copied().unwrap_or(16).clamp(1, 64) as f64
                };
                score(a).total_cmp(&score(b))
            });
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

    async fn report(&self) -> ClientReport {
        ClientReport {
            policy: number_policy(self.policy.load(Ordering::Relaxed)),
            sample_ms: self.epoch.elapsed().as_millis() as u64,
            paths: self
                .paths
                .read()
                .await
                .iter()
                .map(|p| {
                    let rtt = p.rtt_us.load(Ordering::Relaxed);
                    PathReport {
                        name: p.name.clone(),
                        rtt_ms: (rtt > 0).then_some(rtt as f64 / 1000.0),
                        healthy: p.healthy.load(Ordering::Relaxed),
                        metered: p.metered,
                        failures: p.failures.load(Ordering::Relaxed),
                        sent_bytes: p.sent.load(Ordering::Relaxed),
                        received_bytes: p.received.load(Ordering::Relaxed),
                        active_flows: p.active.load(Ordering::Relaxed),
                        jitter_ms: p.jitter_us.load(Ordering::Relaxed) as f64 / 1000.0,
                        probe_failure_ratio: p.probe_failure_ppm.load(Ordering::Relaxed) as f64
                            / 1_000_000.0,
                        incarnation: p.incarnation,
                    }
                })
                .collect(),
        }
    }
}

struct PathLease(Arc<Path>);
impl PathLease {
    fn new(path: Arc<Path>) -> Self {
        path.active.fetch_add(1, Ordering::Relaxed);
        Self(path)
    }
}
impl Drop for PathLease {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Count successful socket IO as it happens, including partial transfers and
/// resets. Counting only when copy_bidirectional finishes hid long downloads
/// and live uploads from the brain entirely.
struct MeteredStream {
    inner: TcpStream,
    path: Option<Arc<Path>>,
    uploaded: u64,
    downloaded: u64,
    next_observation: u64,
    key: (String, u16),
    history: FlowHistory,
}
impl MeteredStream {
    fn observe(&mut self) {
        if self.uploaded + self.downloaded < self.next_observation {
            return;
        }
        self.next_observation = self.uploaded + self.downloaded + 1_048_576;
        if let Ok(mut history) = self.history.lock() {
            if history.len() >= 1024 && !history.contains_key(&self.key) {
                history.pop_first();
            }
            history.insert(self.key.clone(), direction(self.uploaded, self.downloaded));
        }
    }
}
impl AsyncRead for MeteredStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, buf);
        let bytes = (buf.filled().len() - before) as u64;
        if let Some(path) = &self.path {
            path.received.fetch_add(bytes, Ordering::Relaxed);
        }
        self.downloaded += bytes;
        self.observe();
        result
    }
}
impl AsyncWrite for MeteredStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(bytes)) = result {
            if let Some(path) = &self.path {
                path.sent.fetch_add(bytes as u64, Ordering::Relaxed);
            }
            self.uploaded += bytes as u64;
            self.observe();
        }
        result
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
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
    let intent = if known_realtime_port(port) {
        Intent::Realtime
    } else {
        runtime
            .history
            .lock()
            .ok()
            .and_then(|h| h.get(&(host.clone(), port)).copied())
            .unwrap_or_default()
    };
    let forced_relay = runtime.must_relay(&host).await
        || (runtime.relay_fallback.load(Ordering::Relaxed)
            && (intent == Intent::Realtime
                || number_policy(runtime.policy.load(Ordering::Relaxed)) == Policy::Continuity));
    let mut lease = None;
    let mut selected: Option<(Option<Arc<Path>>, TcpStream)> = None;
    if !forced_relay {
        for path in runtime.candidates(intent).await {
            let reservation = PathLease::new(path.clone());
            for destination in &destinations {
                match connect_on(&path, *destination).await {
                    Ok(stream) => {
                        // Destination latency is not uplink latency. Mixing
                        // them made a distant site mark a good ISP "slow".
                        path.healthy.store(true, Ordering::Relaxed);
                        selected = Some((Some(path), stream));
                        break;
                    }
                    Err(_) => {
                        path.failures.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
            if selected.is_some() {
                lease = Some(reservation);
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
    let Some((path, outbound)) = selected else {
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
    let mut outbound = MeteredStream {
        inner: outbound,
        path,
        uploaded: 0,
        downloaded: 0,
        next_observation: 65_536,
        key: (host, port),
        history: runtime.history.clone(),
    };
    let result =
        tokio::io::copy_bidirectional_with_sizes(&mut client, &mut outbound, 65_536, 65_536).await;
    runtime.active.fetch_sub(1, Ordering::Relaxed);
    drop(lease);
    result?;
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
            if path.probing.swap(true, Ordering::Relaxed) {
                continue;
            }
            tokio::spawn(async move {
                let started = Instant::now();
                match connect_on(&path, destination).await {
                    Ok(_) => {
                        let observed =
                            started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64;
                        let prior = path.rtt_us.load(Ordering::Relaxed);
                        let jitter = path.jitter_us.load(Ordering::Relaxed);
                        path.jitter_us.store(
                            (jitter * 3 + prior.abs_diff(observed)) / 4,
                            Ordering::Relaxed,
                        );
                        path.rtt_us.store(
                            if prior == 0 {
                                observed
                            } else {
                                (prior * 7 + observed) / 8
                            },
                            Ordering::Relaxed,
                        );
                        path.healthy.store(true, Ordering::Relaxed);
                        path.probe_failure_ppm
                            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| Some(v * 7 / 8))
                            .ok();
                    }
                    Err(_) => {
                        path.failures.fetch_add(1, Ordering::Relaxed);
                        path.healthy.store(false, Ordering::Relaxed);
                        path.probe_failure_ppm
                            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                                Some(v * 7 / 8 + 125_000)
                            })
                            .ok();
                    }
                }
                path.probing.store(false, Ordering::Relaxed);
            });
        }
    }
}

async fn telemetry(runtime: Runtime) {
    let mut interval = time::interval(Duration::from_secs(1));
    interval.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
    let mut controller = Controller::default();
    let mut previous: BTreeMap<u64, (Instant, u64, u64)> = BTreeMap::new();
    loop {
        interval.tick().await;
        let advice = controller.advise(&runtime.report().await, 0);
        *runtime.local_advice.write().await = Some(advice.clone());
        let paths = runtime.paths.read().await.clone();
        let cutoff = runtime.cutoff_us.load(Ordering::Relaxed);
        previous.retain(|id, _| paths.iter().any(|p| p.incarnation == *id));
        let reports: Vec<_> = paths.iter().enumerate().map(|(id, path)| {
            let healthy = path.healthy.load(Ordering::Relaxed);
            let rtt = path.rtt_us.load(Ordering::Relaxed);
            let sent = path.sent.load(Ordering::Relaxed);
            let received = path.received.load(Ordering::Relaxed);
            let now = Instant::now();
            let (up, down) = previous.insert(path.incarnation, (now, sent, received)).map(|(at, tx, rx)| {
                let secs = now.duration_since(at).as_secs_f64().max(0.001);
                (sent.saturating_sub(tx) as f64 * 8.0 / secs, received.saturating_sub(rx) as f64 * 8.0 / secs)
            }).unwrap_or((0.0, 0.0));
            json!({
                "id": id, "name": path.name, "state": if healthy { "healthy" } else { "offline" },
                "enabled": true, "rtt_ms": if rtt == 0 { None } else { Some(rtt as f64 / 1000.0) },
                "jitter_ms": path.jitter_us.load(Ordering::Relaxed) as f64 / 1000.0,
                "sent_bytes": sent, "received_bytes": received, "acknowledged_bytes": 0,
                "delivery_bps": up + down, "latency_excluded": false,
                "realtime_preferred": advice.realtime_weights.get(&path.name).is_some_and(|w| *w > 0),
                "upload_bps": up, "download_bps": down, "active_flows": path.active.load(Ordering::Relaxed),
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
        for path in runtime.candidates(Intent::Realtime).await {
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
            *runtime.brain_advice.write().await = None;
            if let Some(sender) = &runtime.guidance {
                sender.send_replace(None);
            }
            println!(
                "BRAIN_STATE {}",
                json!({"connected":false,"generation":0,"strategy":"local-fallback"})
            );
            time::sleep(Duration::from_secs(2)).await;
            continue;
        };
        loop {
            let report = runtime.report().await;
            let response = time::timeout(Duration::from_secs(3), client.exchange(&report)).await;
            let Ok(Ok(advice)) = response else {
                break;
            };
            let current = runtime.report().await;
            if current.policy != report.policy
                || current.paths.len() != report.paths.len()
                || current
                    .paths
                    .iter()
                    .zip(&report.paths)
                    .any(|(a, b)| a.incarnation != b.incarnation)
            {
                continue;
            }
            // Advice cannot change security mode, local health or cost rules.
            // A v1 server has no TTL/directional weights: use local v2 policy.
            let compatible = advice.strategy == "adaptive-goodput-v2" && advice.valid_for_ms > 0;
            *runtime.brain_advice.write().await =
                compatible.then(|| (Instant::now(), advice.clone()));
            if let Some(sender) = &runtime.guidance {
                sender.send_replace(compatible.then(|| (Instant::now(), advice.clone())));
            }
            println!(
                "BRAIN_STATE {}",
                json!({"connected":compatible,"generation":advice.generation,"strategy":advice.strategy,
                    "learnedPaths": advice.learned_paths})
            );
            time::sleep(Duration::from_secs(1)).await;
        }
        *runtime.brain_advice.write().await = None;
        if let Some(sender) = &runtime.guidance {
            sender.send_replace(None);
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
    let changed = existing.len() != paths.len()
        || existing
            .iter()
            .zip(&paths)
            .any(|(a, b)| a.incarnation != b.incarnation)
        || value
            .policy
            .as_deref()
            .and_then(parse_policy)
            .is_some_and(|p| policy_number(p) != runtime.policy.load(Ordering::Relaxed));
    *runtime.paths.write().await = paths;
    if changed {
        *runtime.brain_advice.write().await = None;
        *runtime.local_advice.write().await = None;
        if let Some(sender) = &runtime.guidance {
            sender.send_replace(None);
        }
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
    run_with_guidance(args, external, None).await
}

pub async fn run_with_guidance(
    args: DirectArgs,
    external: Option<mpsc::Receiver<Control>>,
    guidance: Option<watch::Sender<Guidance>>,
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
        brain_advice: Arc::new(RwLock::new(None)),
        local_advice: Arc::new(RwLock::new(None)),
        history: Arc::new(Mutex::new(BTreeMap::new())),
        epoch: Instant::now(),
        guidance,
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
            brain_advice: Arc::new(RwLock::new(None)),
            local_advice: Arc::new(RwLock::new(None)),
            history: Arc::new(Mutex::new(BTreeMap::new())),
            epoch: Instant::now(),
            guidance: None,
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
    async fn scheduler_keeps_slow_bulk_path_but_prefers_fast_for_realtime() -> Result<()> {
        let a = parse_path("en0=192.168.1.2,false")?;
        let b = parse_path("en7=192.168.1.3,false")?;
        a.rtt_us.store(20_000, Ordering::Relaxed);
        b.rtt_us.store(40_000, Ordering::Relaxed);
        let runtime = runtime(vec![a.clone(), b.clone()], Policy::Smart);
        assert_eq!(runtime.candidates(Intent::Balanced).await[0].name, "en0");
        assert_eq!(runtime.candidates(Intent::Balanced).await[0].name, "en7");
        b.rtt_us.store(75_000, Ordering::Relaxed);
        assert_eq!(runtime.candidates(Intent::Download).await.len(), 2);
        assert_eq!(runtime.candidates(Intent::Realtime).await[0].name, "en0");
        Ok(())
    }

    #[tokio::test]
    async fn data_saver_avoids_metered_path() -> Result<()> {
        let a = parse_path("en0=192.168.1.2,true")?;
        let b = parse_path("en7=192.168.1.3,false")?;
        let runtime = runtime(vec![a, b], Policy::DataSaver);
        assert_eq!(runtime.candidates(Intent::Balanced).await.len(), 1);
        assert_eq!(runtime.candidates(Intent::Balanced).await[0].name, "en7");
        Ok(())
    }

    #[tokio::test]
    async fn all_slow_paths_remain_available_for_bulk() -> Result<()> {
        let a = parse_path("en0=192.168.1.2,false")?;
        let b = parse_path("en7=192.168.1.3,false")?;
        a.rtt_us.store(120_000, Ordering::Relaxed);
        b.rtt_us.store(90_000, Ordering::Relaxed);
        let runtime = runtime(vec![a, b], Policy::Smart);
        assert_eq!(runtime.candidates(Intent::Download).await.len(), 2);
        assert_eq!(runtime.candidates(Intent::Realtime).await[0].name, "en7");
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

    #[tokio::test]
    async fn assignments_use_directional_weights_and_reserve_in_progress_flows() -> Result<()> {
        let a = parse_path("en0=192.168.1.2,false")?;
        let b = parse_path("en7=192.168.1.3,false")?;
        a.active.store(4, Ordering::Relaxed);
        b.active.store(4, Ordering::Relaxed);
        let runtime = runtime(vec![a.clone(), b], Policy::Smart);
        let mut advice = crate::brain::advise(&runtime.report().await, 1);
        advice.download_weights = BTreeMap::from([("en0".into(), 64), ("en7".into(), 4)]);
        advice.upload_weights = BTreeMap::from([("en0".into(), 4), ("en7".into(), 64)]);
        *runtime.brain_advice.write().await = Some((Instant::now(), advice));
        assert_eq!(runtime.candidates(Intent::Download).await[0].name, "en0");
        assert_eq!(runtime.candidates(Intent::Upload).await[0].name, "en7");
        let lease = PathLease::new(a.clone());
        assert_eq!(a.active.load(Ordering::Relaxed), 5);
        drop(lease);
        assert_eq!(a.active.load(Ordering::Relaxed), 4);
        Ok(())
    }

    #[tokio::test]
    async fn expired_advice_uses_local_learning_and_new_paths_are_not_starved() -> Result<()> {
        let a = parse_path("en0=192.168.1.2,false")?;
        let b = parse_path("en7=192.168.1.3,false")?;
        a.active.store(2, Ordering::Relaxed);
        b.active.store(2, Ordering::Relaxed);
        let runtime = runtime(vec![a, b], Policy::Smart);
        let mut remote = crate::brain::advise(&runtime.report().await, 1);
        remote.download_weights = BTreeMap::from([("en0".into(), 1), ("en7".into(), 64)]);
        let mut local = remote.clone();
        local.download_weights = BTreeMap::from([("en0".into(), 64), ("en7".into(), 1)]);
        *runtime.local_advice.write().await = Some(local);
        *runtime.brain_advice.write().await =
            Some((Instant::now() - Duration::from_secs(6), remote));
        assert_eq!(runtime.candidates(Intent::Download).await[0].name, "en0");
        let c = parse_path("en8=192.168.1.4,false")?;
        runtime.paths.write().await.push(c);
        assert_eq!(runtime.candidates(Intent::Download).await[0].name, "en8");
        apply_control(
            &runtime,
            Control {
                interfaces: vec![],
                policy: None,
                secure_domains: None,
            },
        )
        .await;
        assert!(runtime.candidates(Intent::Download).await.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn live_socket_bytes_are_visible_before_close_and_half_close_survives() -> Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let socket = TcpStream::connect(listener.local_addr()?).await?;
        let (mut peer, _) = listener.accept().await?;
        let path = parse_path("en0=192.168.1.2,false")?;
        let history: FlowHistory = Arc::new(Mutex::new(BTreeMap::new()));
        let mut socket = MeteredStream {
            inner: socket,
            path: Some(path.clone()),
            uploaded: 0,
            downloaded: 0,
            next_observation: 65_536,
            key: ("example.test".into(), 443),
            history: history.clone(),
        };
        let writer = tokio::spawn(async move {
            let mut bytes = vec![];
            peer.read_to_end(&mut bytes).await.unwrap();
            assert_eq!(bytes, vec![42; 131_072]);
            peer.write_all(&[7; 128]).await.unwrap();
        });
        socket.write_all(&vec![42; 131_072]).await?;
        assert_eq!(path.sent.load(Ordering::Relaxed), 131_072);
        assert_eq!(
            history.lock().unwrap()[&("example.test".into(), 443)],
            Intent::Upload
        );
        socket.shutdown().await?;
        let mut bytes = vec![];
        socket.read_to_end(&mut bytes).await?;
        assert_eq!(bytes, vec![7; 128]);
        assert_eq!(path.received.load(Ordering::Relaxed), 128);
        writer.await?;
        Ok(())
    }

    #[test]
    fn unknown_encrypted_traffic_is_not_guessed_to_be_a_call() {
        assert!(!known_realtime_port(443));
        assert!(known_realtime_port(1935));
        assert!(known_realtime_port(5061));
        assert_eq!(direction(512, 8_000), Intent::Balanced);
        assert_eq!(direction(128, 1_000_000), Intent::Download);
        assert_eq!(direction(1_000_000, 128), Intent::Upload);
    }
}
