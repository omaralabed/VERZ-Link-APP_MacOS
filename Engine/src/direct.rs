//! Direct Smart mode: a local SOCKS5 TCP flow engine. Application payloads go
//! straight to their destinations and retain only the application's own
//! encryption. Each TCP connection is pinned to one selected physical uplink.
use crate::{
    bind_ipv4_interface_fd,
    bond::Policy,
    brain::{BrainAdvice, BrainClient, ClientReport, Controller, Guidance, PathReport, TcpReport},
    load_secret, tcp_metrics,
};
use anyhow::{Context, Result, bail, ensure};
use clap::Args;
use serde::Deserialize;
use serde_json::json;
use std::{
    collections::{BTreeMap, VecDeque},
    future::Future,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    os::fd::AsRawFd,
    path::PathBuf,
    pin::Pin,
    sync::{
        Arc,
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
/// Plain HTTP so the probe times a real request/response round trip without a
/// TLS dependency. A TCP-splitting middlebox (satellite/cellular PEP, ISP
/// accelerator) answers the handshake locally in a few ms; it cannot answer
/// the request itself without forwarding it end to end.
const PROBE_DESTINATION: &str = "1.1.1.1:80";
const PROBE_HEALTH_DESTINATION: &str = "1.1.1.1:443";
const PROBE_TIMEOUT: Duration = Duration::from_secs(3);
const CONNECT_BUDGET: Duration = Duration::from_secs(3);
const CONNECT_ATTEMPT: Duration = Duration::from_millis(1_200);
const PREFERRED_MINIMUM: Duration = Duration::from_millis(300);
const CONNECT_STAGGER: Duration = Duration::from_millis(150);
/// Extra end-to-end delay a path may carry before new-flow placement starts
/// penalising it; below this, capacity weights alone decide.
const LATENCY_DEAD_ZONE_US: u64 = 50_000;
const LATENCY_PENALTY_STEP_US: u64 = 100_000;
static INCARNATION: AtomicU64 = AtomicU64::new(1);
static PROBE_NONCE: AtomicU64 = AtomicU64::new(0);
/// Per-run random salt: flow records can correlate repeat destinations within
/// one session, but the log never contains a destination or a stable hash.
static FLOW_SALT: std::sync::OnceLock<[u8; 16]> = std::sync::OnceLock::new();

/// Placement decision plus the evidence it was made on. Written to the local
/// flow log so future policy changes can be replayed against real usage.
#[derive(Default)]
struct Plan {
    paths: Vec<Arc<Path>>,
    source: &'static str,
    champion: Option<String>,
    primary: Option<String>,
    trial: Option<String>,
    features: Vec<serde_json::Value>,
}

fn destination_tag(host: &str, port: u16) -> String {
    use sha2::{Digest, Sha256};
    let salt = FLOW_SALT.get_or_init(rand::random);
    let mut hasher = Sha256::new();
    hasher.update(salt);
    hasher.update(host.to_ascii_lowercase().as_bytes());
    hasher.update(port.to_be_bytes());
    hex::encode(&hasher.finalize()[..8])
}

/// Published only after the encrypted client has created its assigned utun.
/// Binding relay sockets explicitly keeps protected flows off the physical
/// default route during Hybrid startup and rollback.
#[derive(Clone)]
pub struct RelayRoute {
    pub interface: String,
    pub address: Ipv4Addr,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum Intent {
    #[default]
    Balanced,
    // Direction-specific placement needs per-flow evidence that a new SOCKS
    // connection does not carry; kept for when such a signal exists.
    #[allow(dead_code)]
    Download,
    #[allow(dead_code)]
    Upload,
    Realtime,
}

fn known_realtime_port(port: u16) -> bool {
    // Explicit RTSP/RTMP/SIP/TURN endpoints. Port 443 is deliberately unknown:
    // it could carry a call, a download, or a web page. No TLS interception.
    matches!(port, 554 | 1935 | 3478 | 5349 | 5060 | 5061)
}

/// Placement intent for a new flow. Only the flow's own destination port is
/// evidence about it. The machine-wide traffic shape of the last second is not:
/// applying it made an unrelated page request inherit the placement rules of a
/// concurrent bulk download, and flipped every second.
fn intent_for(port: u16) -> Intent {
    if known_realtime_port(port) {
        Intent::Realtime
    } else {
        Intent::Balanced
    }
}

fn preferred_budget(connect_us: u64) -> Duration {
    if connect_us == 0 {
        return CONNECT_ATTEMPT;
    }
    Duration::from_micros(connect_us.saturating_mul(3).saturating_add(100_000))
        .clamp(PREFERRED_MINIMUM, CONNECT_ATTEMPT)
}

/// Multiplier applied to a path's new-flow score for carrying more end-to-end
/// delay than the best available path. Unknown delay is not penalised.
fn latency_factor(rtt_us: u64, best_rtt_us: u64) -> f64 {
    if rtt_us == 0 || best_rtt_us == 0 {
        return 1.0;
    }
    let excess = rtt_us
        .saturating_sub(best_rtt_us)
        .saturating_sub(LATENCY_DEAD_ZONE_US);
    (1.0 + excess as f64 / LATENCY_PENALTY_STEP_US as f64).min(16.0)
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
    /// Smoothed end-to-end request/response delay from the probe, not the
    /// TCP handshake time.
    rtt_us: AtomicU64,
    /// Smoothed TCP handshake time; only used to size the failover wait.
    connect_us: AtomicU64,
    sent: AtomicU64,
    received: AtomicU64,
    failures: AtomicU64,
    active: AtomicU64,
    jitter_us: AtomicU64,
    probe_failure_ppm: AtomicU64,
    probing: AtomicBool,
    acknowledged: AtomicU64,
    retransmitted: AtomicU64,
    queued: AtomicU64,
    busy: AtomicU64,
    connecting: AtomicU64,
    tcp_observed: AtomicBool,
    upload_hold_until_ms: AtomicU64,
    recovery_acknowledged: AtomicU64,
    last_trial_ms: AtomicU64,
    created: Instant,
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
            connect_us: AtomicU64::new(0),
            sent: AtomicU64::new(0),
            received: AtomicU64::new(0),
            failures: AtomicU64::new(0),
            active: AtomicU64::new(0),
            jitter_us: AtomicU64::new(0),
            probe_failure_ppm: AtomicU64::new(0),
            probing: AtomicBool::new(false),
            acknowledged: AtomicU64::new(0),
            retransmitted: AtomicU64::new(0),
            queued: AtomicU64::new(0),
            busy: AtomicU64::new(0),
            connecting: AtomicU64::new(0),
            tcp_observed: AtomicBool::new(false),
            upload_hold_until_ms: AtomicU64::new(0),
            recovery_acknowledged: AtomicU64::new(0),
            last_trial_ms: AtomicU64::new(0),
            created: Instant::now(),
            incarnation: INCARNATION.fetch_add(1, Ordering::Relaxed),
        })
    }

    fn upload_held(&self) -> bool {
        self.created.elapsed().as_millis()
            < u128::from(self.upload_hold_until_ms.load(Ordering::Relaxed))
    }

    /// How long a new flow waits on this path before other adapters are tried.
    /// Scaled from the measured handshake so a 70 ms path fails over in about
    /// 300 ms instead of a fixed 1.2 s, while a genuinely slow path is not
    /// declared dead by a shorter wait than its own handshake.
    fn preferred_budget(&self) -> Duration {
        preferred_budget(self.connect_us.load(Ordering::Relaxed))
    }

    fn hold_uploads(&self) {
        self.upload_hold_until_ms.fetch_max(
            self.created.elapsed().as_millis() as u64 + 3_000,
            Ordering::Relaxed,
        );
        self.recovery_acknowledged.store(
            self.acknowledged
                .load(Ordering::Relaxed)
                .saturating_add(65_536),
            Ordering::Relaxed,
        );
    }
}

#[derive(Clone)]
struct Runtime {
    payload: Arc<PayloadTotals>,
    paths: Arc<RwLock<Vec<Arc<Path>>>>,
    policy: Arc<AtomicUsize>,
    cursor: Arc<AtomicUsize>,
    active: Arc<AtomicU64>,
    accepted: Arc<AtomicU64>,
    direct_connections: Arc<AtomicU64>,
    relay_connections: Arc<AtomicU64>,
    relay_fallback: Arc<AtomicBool>,
    relay_route: Option<watch::Receiver<Option<RelayRoute>>>,
    cutoff_us: Arc<AtomicU64>,
    brain_advice: Arc<RwLock<Option<(Instant, BrainAdvice)>>>,
    local_advice: Arc<RwLock<Option<BrainAdvice>>>,
    /// 0=mixed/unknown, 1=download-dominant, 2=upload-dominant. Updated from
    /// delivered TCP bytes once per second; new flows use it immediately while
    /// established flows remain pinned to their original ISP.
    traffic_shape: Arc<AtomicUsize>,
    epoch: Instant,
    guidance: Option<watch::Sender<Guidance>>,
    secure_domains: Arc<RwLock<Vec<String>>>,
}

impl Runtime {
    async fn candidates(&self, intent: Intent) -> Vec<Arc<Path>> {
        self.plan(intent).await.paths
    }

    /// Ordered connect candidates plus the evidence the decision was made on.
    /// The recorder writes the latter; nothing here changes placement.
    async fn plan(&self, intent: Intent) -> Plan {
        let all = self.paths.read().await.clone();
        if all.is_empty() {
            return Plan::default();
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
        // Cloud advice without any delivery evidence is only its cold-start
        // tie-break, which the deployed server still takes from adapter order.
        // The Mac has measured end-to-end delay; its own controller uses it.
        let remote = remote.as_ref().filter(|(at, advice)| {
            advice.valid_for_ms > 0
                && advice.learned_paths > 0
                && at.elapsed().as_millis() < u128::from(advice.valid_for_ms.min(5_000))
        });
        let source = match (remote.is_some(), local.is_some()) {
            (true, _) => "cloud",
            (false, true) => "local",
            _ => "none",
        };
        let advice = remote.map(|(_, advice)| advice).or(local.as_ref());
        let empty = BTreeMap::new();
        let weights = advice
            .map(|a| match intent {
                Intent::Realtime => &a.realtime_weights,
                Intent::Download => &a.download_weights,
                Intent::Upload => &a.upload_weights,
                Intent::Balanced => &a.weights,
            })
            .unwrap_or(&empty);
        let advised_champion = advice.and_then(|a| match intent {
            Intent::Realtime => None,
            Intent::Download => a.download_champion.as_deref(),
            Intent::Upload => a.upload_champion.as_deref(),
            Intent::Balanced => a.balanced_champion.as_deref(),
        });
        let mut features: Vec<_> = eligible
            .iter()
            .map(|p| {
                let ms = |v: u64| (v > 0).then_some(v as f64 / 1000.0);
                json!({
                    "name": p.name, "rtt_ms": ms(p.rtt_us.load(Ordering::Relaxed)),
                    "connect_ms": ms(p.connect_us.load(Ordering::Relaxed)),
                    "jitter_ms": p.jitter_us.load(Ordering::Relaxed) as f64 / 1000.0,
                    "probe_failure_ppm": p.probe_failure_ppm.load(Ordering::Relaxed),
                    "busy": p.busy.load(Ordering::Relaxed), "connecting": p.connecting.load(Ordering::Relaxed),
                    "active": p.active.load(Ordering::Relaxed), "weight": weights.get(&p.name),
                    "held": p.upload_held(), "metered": p.metered,
                    "acknowledged": p.acknowledged.load(Ordering::Relaxed), "received": p.received.load(Ordering::Relaxed)
                })
            })
            .collect();
        let mut plan = Plan {
            paths: Vec::new(),
            source,
            champion: advised_champion.map(str::to_owned),
            primary: None,
            trial: None,
            features: Vec::new(),
        };
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
            // Unknown TLS may switch from download to upload on this same
            // connection. Use the conservative two-direction weight, never
            // the direction of an earlier connection to this destination.
            let busy =
                |p: &Path| p.busy.load(Ordering::Relaxed) + p.connecting.load(Ordering::Relaxed);
            let unproven = |p: &Path| {
                let guided_challenger = advised_champion.is_some_and(|champion| {
                    champion != p.name && weights.get(&p.name).copied().unwrap_or(1) <= 1
                });
                (p.acknowledged.load(Ordering::Relaxed) < 65_536
                    && p.received.load(Ordering::Relaxed) < 65_536)
                    || p.upload_hold_until_ms.load(Ordering::Relaxed) > 0
                    || guided_challenger
            };
            let primary = advised_champion
                .and_then(|name| eligible.iter().find(|p| p.name == name && !p.upload_held()))
                .or_else(|| {
                    eligible
                        .iter()
                        .filter(|p| !p.upload_held())
                        .min_by_key(|p| {
                            (
                                unproven(p),
                                match p.rtt_us.load(Ordering::Relaxed) {
                                    0 => u64::MAX,
                                    v => v,
                                },
                                p.name.clone(),
                            )
                        })
                })
                .or_else(|| eligible.first())
                .map(|p| p.name.clone())
                .unwrap();
            let trial_allowed = |p: &Path| {
                !p.upload_held()
                    && busy(p) == 0
                    && p.created.elapsed().as_millis() as u64
                        >= p.last_trial_ms.load(Ordering::Relaxed) + 5_000
            };
            let group = |p: &Path| {
                if p.upload_held() {
                    2
                } else if p.name != primary && unproven(p) {
                    1
                } else {
                    0
                }
            };
            let rtt = |p: &Path| p.rtt_us.load(Ordering::Relaxed);
            let best_rtt = eligible
                .iter()
                .map(|p| rtt(p))
                .filter(|v| *v > 0)
                .min()
                .unwrap_or(0);
            let penalty = |p: &Path| latency_factor(rtt(p), best_rtt);
            for feature in &mut features {
                if let Some(p) = eligible
                    .iter()
                    .find(|p| Some(p.name.as_str()) == feature["name"].as_str())
                {
                    feature["penalty"] = json!(penalty(p));
                    feature["unproven"] = json!(unproven(p));
                }
            }
            let primary_load = eligible
                .iter()
                .find(|p| p.name == primary)
                .map(|p| busy(p))
                .unwrap_or(0);
            // A trial pins whatever flow arrives next to the unproven path for
            // that flow's whole life; it cannot be migrated. A path with far
            // more end-to-end delay only gets that chance once the primary
            // carries many concurrent flows, not on the first keep-alive.
            let trial = if primary_load > 0 {
                eligible
                    .iter()
                    .find(|p| {
                        p.name != primary
                            && unproven(p)
                            && trial_allowed(p)
                            && (penalty(p) <= 2.0 || primary_load >= 8)
                    })
                    .map(|p| p.name.clone())
            } else {
                None
            };
            eligible.sort_by(|a, b| {
                let score = |p: &Path| {
                    // +1 prevents an idle, known-poor link from always beating
                    // a busy strong link. Idle keep-alives are not workload.
                    (busy(p) + 1) as f64
                        / weights.get(&p.name).copied().unwrap_or(4).clamp(1, 64) as f64
                        * penalty(p)
                };
                let rank = |p: &Path| {
                    if trial.as_ref() == Some(&p.name) {
                        0
                    } else {
                        group(p) + 1
                    }
                };
                rank(a)
                    .cmp(&rank(b))
                    .then_with(|| score(a).total_cmp(&score(b)))
            });
            // Keep held/unknown paths as last-resort connect fallbacks. Local
            // congestion wins over stale or incorrect remote positive weights.
            if let Some(path) = eligible.first().filter(|p| trial.as_ref() == Some(&p.name)) {
                path.last_trial_ms
                    .store(path.created.elapsed().as_millis() as u64, Ordering::Relaxed);
            }
            plan.primary = Some(primary);
            plan.trial = trial;
        }
        plan.paths = eligible;
        plan.features = features;
        plan
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
                        tcp: p.tcp_observed.load(Ordering::Relaxed).then(|| TcpReport {
                            acknowledged: p.acknowledged.load(Ordering::Relaxed),
                            retransmitted: p.retransmitted.load(Ordering::Relaxed),
                            queued: p.queued.load(Ordering::Relaxed),
                            busy: p.busy.load(Ordering::Relaxed),
                            held: p.upload_held(),
                        }),
                    }
                })
                .collect(),
        }
    }
}

struct PathLease {
    path: Arc<Path>,
    connecting: bool,
}
impl PathLease {
    fn new(path: Arc<Path>) -> Self {
        path.active.fetch_add(1, Ordering::Relaxed);
        path.connecting.fetch_add(1, Ordering::Relaxed);
        Self {
            path,
            connecting: true,
        }
    }
    fn connected(&mut self) {
        self.path.connecting.fetch_sub(1, Ordering::Relaxed);
        self.connecting = false;
    }
}
impl Drop for PathLease {
    fn drop(&mut self) {
        self.path.active.fetch_sub(1, Ordering::Relaxed);
        if self.connecting {
            self.path.connecting.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

/// Count successful socket IO as it happens, including partial transfers and
/// resets. Counting only when copy_bidirectional finishes hid long downloads
/// and live uploads from the brain entirely.
#[derive(Default)]
struct PayloadTotals {
    upload: AtomicU64,
    download: AtomicU64,
    unmeasured: AtomicU64,
}

struct MeteredStream {
    payload: Option<Arc<PayloadTotals>>,
    payload_acknowledged: u64,
    inner: TcpStream,
    path: Option<Arc<Path>>,
    uploaded: u64,
    downloaded: u64,
    tick: Pin<Box<time::Sleep>>,
    last_activity: Instant,
    last_progress: Instant,
    minimum_rtt_us: u64,
    acknowledged: u64,
    retransmitted: u64,
    queued: u64,
    busy: bool,
    opened: Instant,
    first_write: Option<Instant>,
    first_read: Option<Instant>,
    holds: u32,
}
impl MeteredStream {
    fn new(inner: TcpStream, path: Option<Arc<Path>>) -> Self {
        let baseline = tcp_metrics::snapshot(inner.as_raw_fd(), 0)
            .map(|s| s.rtt_us)
            .unwrap_or(0);
        if let Some(p) = &path {
            p.busy.fetch_add(1, Ordering::Relaxed);
        }
        Self {
            payload: None,
            payload_acknowledged: 0,
            inner,
            path,
            uploaded: 0,
            downloaded: 0,
            tick: Box::pin(time::sleep(Duration::from_millis(250))),
            last_activity: Instant::now(),
            last_progress: Instant::now(),
            minimum_rtt_us: baseline,
            acknowledged: 0,
            retransmitted: 0,
            queued: 0,
            busy: true,
            opened: Instant::now(),
            first_write: None,
            first_read: None,
            holds: 0,
        }
    }

    /// Application-level time to first byte: first remote byte after the first
    /// client byte was forwarded. None for flows that never got a reply.
    fn ttfb_ms(&self) -> Option<f64> {
        Some(
            self.first_read?
                .saturating_duration_since(self.first_write?)
                .as_secs_f64()
                * 1000.0,
        )
    }

    fn sample(&mut self) {
        if self.path.is_none() && self.payload.is_none() {
            return;
        }
        let snapshot = tcp_metrics::snapshot(self.inner.as_raw_fd(), self.uploaded);
        if let Some(total) = &self.payload {
            if let Some(s) = snapshot {
                let acknowledged = s
                    .acknowledged
                    .min(self.uploaded)
                    .max(self.payload_acknowledged);
                total
                    .upload
                    .fetch_add(acknowledged - self.payload_acknowledged, Ordering::Relaxed);
                self.payload_acknowledged = acknowledged;
            }
        }
        let Some(path) = &self.path else {
            return;
        };
        if let Some(s) = snapshot {
            path.tcp_observed.store(true, Ordering::Relaxed);
            let acked = s.acknowledged.saturating_sub(self.acknowledged);
            let retransmitted = s.retransmitted.saturating_sub(self.retransmitted);
            path.acknowledged.fetch_add(acked, Ordering::Relaxed);
            path.retransmitted
                .fetch_add(retransmitted, Ordering::Relaxed);
            self.acknowledged = self.acknowledged.max(s.acknowledged);
            self.retransmitted = self.retransmitted.max(s.retransmitted);
            replace_contribution(&path.queued, self.queued, s.queued);
            self.queued = s.queued;
            if s.rtt_us > 0 {
                self.minimum_rtt_us = if self.minimum_rtt_us == 0 {
                    s.rtt_us
                } else {
                    self.minimum_rtt_us.min(s.rtt_us)
                };
            }
            if acked > 0 {
                self.last_progress = Instant::now();
            }
            if upload_congested(
                self.uploaded,
                s.queued,
                s.rtt_us.saturating_sub(self.minimum_rtt_us),
                acked,
                retransmitted,
                self.last_progress.elapsed(),
            ) {
                path.hold_uploads();
                self.holds += 1;
            } else if !path.upload_held()
                && path.acknowledged.load(Ordering::Relaxed)
                    >= path.recovery_acknowledged.load(Ordering::Relaxed)
            {
                path.upload_hold_until_ms.store(0, Ordering::Relaxed);
            }
        } else if self.queued > 0 && self.last_progress.elapsed() > Duration::from_millis(500) {
            // Missing/reset socket stats cannot manufacture successful delivery.
            path.hold_uploads();
            self.holds += 1;
        }
        let busy = self.queued > 16_384 || self.last_activity.elapsed() < Duration::from_secs(1);
        if busy != self.busy {
            replace_contribution(&path.busy, u64::from(self.busy), u64::from(busy));
            self.busy = busy;
        }
    }

    fn poll_metrics(&mut self, cx: &mut TaskContext<'_>) {
        if self.tick.as_mut().poll(cx).is_ready() {
            self.sample();
            self.tick
                .as_mut()
                .reset(time::Instant::now() + Duration::from_millis(250));
            // Register even when both socket directions are waiting. Otherwise
            // a completely stalled upload could never report its congestion.
            let _ = self.tick.as_mut().poll(cx);
        }
    }
}

fn replace_contribution(total: &AtomicU64, old: u64, new: u64) {
    if new >= old {
        total.fetch_add(new - old, Ordering::Relaxed);
    } else {
        total.fetch_sub(old - new, Ordering::Relaxed);
    }
}

fn upload_congested(
    written: u64,
    queued: u64,
    excess_rtt_us: u64,
    acknowledged: u64,
    retransmitted: u64,
    stalled: Duration,
) -> bool {
    written >= 65_536
        && queued >= 16_384
        && (excess_rtt_us >= 50_000
            || stalled >= Duration::from_millis(500)
            || (retransmitted >= 4_096
                && retransmitted as f64 / (acknowledged + retransmitted).max(1) as f64 >= 0.05))
}

impl Drop for MeteredStream {
    fn drop(&mut self) {
        self.sample();
        // A transient missing snapshot may recover while the socket is alive.
        // Report a coverage gap only if it closes with unconfirmed bytes.
        if let Some(total) = &self.payload
            && self.uploaded > self.payload_acknowledged
        {
            total.unmeasured.fetch_add(1, Ordering::Relaxed);
        }
        if let Some(path) = &self.path {
            path.queued.fetch_sub(self.queued, Ordering::Relaxed);
            if self.busy {
                path.busy.fetch_sub(1, Ordering::Relaxed);
            }
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
        if let Some(total) = &self.payload {
            total.download.fetch_add(bytes, Ordering::Relaxed);
        }
        if bytes > 0 {
            self.last_activity = Instant::now();
            self.first_read.get_or_insert_with(Instant::now);
        }
        self.poll_metrics(cx);
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
            if bytes > 0
                && self.queued == 0
                && self.last_activity.elapsed() >= Duration::from_secs(1)
            {
                self.last_progress = Instant::now();
            }
            self.uploaded += bytes as u64;
            if bytes > 0 {
                self.last_activity = Instant::now();
                self.first_write.get_or_insert_with(Instant::now);
            }
        }
        self.poll_metrics(cx);
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

async fn connect_via_relay(
    destination: SocketAddr,
    route: Option<watch::Receiver<Option<RelayRoute>>>,
) -> Result<TcpStream> {
    let socket = TcpSocket::new_v4()?;
    if let Some(route) = route {
        let route = route
            .borrow()
            .clone()
            .context("encrypted route is not ready")?;
        bind_ipv4_interface_fd(socket.as_raw_fd(), &route.interface)?;
        socket.bind(SocketAddrV4::new(route.address, 0).into())?;
    }
    let stream = time::timeout(CONNECT_ATTEMPT, socket.connect(destination))
        .await
        .context("secure relay fallback timed out")??;
    stream.set_nodelay(true)?;
    Ok(stream)
}

/// Race TCP handshakes only; application bytes are sent once, to the winner.
/// At most two attempts are live. Cancellation drops losing sockets and their
/// path reservations before returning; a blackholed path cannot add repeated
/// six-second waits for every address/adapter.
async fn race_connections<T, F>(
    attempts: impl IntoIterator<Item = F>,
    budget: Duration,
) -> Result<T>
where
    T: Send + 'static,
    F: Future<Output = Result<T>> + Send + 'static,
{
    let mut waiting: VecDeque<_> = attempts.into_iter().take(16).collect();
    let mut pending = tokio::task::JoinSet::new();
    let deadline = time::Instant::now() + budget;
    let mut next_launch = time::Instant::now();
    loop {
        if time::Instant::now() >= deadline {
            break;
        }
        if pending.len() < 2
            && (pending.is_empty() || time::Instant::now() >= next_launch)
            && let Some(attempt) = waiting.pop_front()
        {
            pending.spawn(async move {
                time::timeout(CONNECT_ATTEMPT, attempt)
                    .await
                    .context("TCP attempt timed out")?
            });
            next_launch = time::Instant::now() + CONNECT_STAGGER;
        }
        if pending.is_empty() && waiting.is_empty() {
            break;
        }
        tokio::select! {
            _ = time::sleep_until(deadline) => break,
            result = pending.join_next(), if !pending.is_empty() => {
                if let Some(Ok(Ok(winner))) = result {
                    pending.shutdown().await;
                    return Ok(winner);
                }
                // An immediate refusal need not delay the next candidate.
                next_launch = time::Instant::now();
            }
            _ = time::sleep_until(next_launch), if pending.len() < 2 && !waiting.is_empty() => {}
        }
    }
    pending.shutdown().await;
    bail!("no TCP candidate connected within the setup budget")
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
    let addresses: Vec<_> = time::timeout(Duration::from_secs(2), lookup_host((host, port)))
        .await
        .context("destination DNS lookup timed out")??
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
    let accepted = Instant::now();
    let (host, port) = time::timeout(Duration::from_secs(3), socks_target(&mut client))
        .await
        .context("SOCKS negotiation timed out")??;
    let resolving = Instant::now();
    let resolved = resolve(&host, port).await;
    let dns_ms = resolving.elapsed().as_secs_f64() * 1000.0;
    let mut record = json!({
        "t": std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0),
        "dst": destination_tag(&host, port), "port": port, "literal_ip": host.parse::<Ipv4Addr>().is_ok(),
        "dns_ms": dns_ms, "policy": number_policy(runtime.policy.load(Ordering::Relaxed)),
        "active": runtime.active.load(Ordering::Relaxed)
    });
    let destinations = match resolved {
        Ok(addresses) => addresses,
        Err(error) => {
            client.write_all(&[5, 4, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
            record["result"] = json!("dns_failed");
            println!("FLOW_RECORD {record}");
            return Err(error);
        }
    };
    record["addresses"] = json!(destinations.len());
    let intent = intent_for(port);
    let forced_relay = runtime.must_relay(&host).await
        || (runtime.relay_fallback.load(Ordering::Relaxed)
            && (intent == Intent::Realtime
                || number_policy(runtime.policy.load(Ordering::Relaxed)) == Policy::Continuity));
    record["intent"] = json!(format!("{intent:?}"));
    record["forced_relay"] = json!(forced_relay);
    let mut lease = None;
    let mut selected: Option<(Option<Arc<Path>>, TcpStream)> = None;
    let mut stage = "relay";
    let connecting = Instant::now();
    if !forced_relay {
        let plan = runtime.plan(intent).await;
        record["advice"] = json!(plan.source);
        record["champion"] = json!(plan.champion);
        record["primary"] = json!(plan.primary);
        record["trial"] = json!(plan.trial);
        record["order"] = json!(
            plan.paths
                .iter()
                .map(|p| p.name.as_str())
                .collect::<Vec<_>>()
        );
        record["paths"] = json!(plan.features);
        let mut paths = plan.paths;
        if let Some(preferred) = paths.first().cloned() {
            // Selection and failover are separate decisions. Trying an
            // unproven adapter 150 ms later let it steal control connections
            // from the selected path. Use the controller's preferred path
            // first; open the remaining paths only after a real failure.
            let preferred_attempts = destinations.iter().copied().map(|destination| {
                let path = preferred.clone();
                async move {
                    let mut reservation = PathLease::new(path.clone());
                    let result = connect_on(&path, destination).await;
                    if result.is_err() {
                        path.failures.fetch_add(1, Ordering::Relaxed);
                    }
                    let stream = result?;
                    path.healthy.store(true, Ordering::Relaxed);
                    reservation.connected();
                    Ok((path, stream, reservation))
                }
            });
            record["preferred_budget_ms"] = json!(preferred.preferred_budget().as_millis() as u64);
            if let Ok((path, stream, reservation)) =
                race_connections(preferred_attempts, preferred.preferred_budget()).await
            {
                selected = Some((Some(path), stream));
                lease = Some(reservation);
                stage = "preferred";
            } else {
                preferred.healthy.store(false, Ordering::Relaxed);
            }
            paths.remove(0);
        }
        if selected.is_none() {
            let candidates: Vec<_> = destinations
                .iter()
                .flat_map(|destination| paths.iter().map(move |path| (path.clone(), *destination)))
                .collect();
            let attempts = candidates
                .into_iter()
                .map(|(path, destination)| async move {
                    let mut reservation = PathLease::new(path.clone());
                    let result = connect_on(&path, destination).await;
                    if result.is_err() {
                        path.failures.fetch_add(1, Ordering::Relaxed);
                    }
                    let stream = result?;
                    path.healthy.store(true, Ordering::Relaxed);
                    reservation.connected();
                    Ok((path, stream, reservation))
                });
            if let Ok((path, stream, reservation)) =
                race_connections(attempts, CONNECT_BUDGET).await
            {
                selected = Some((Some(path), stream));
                lease = Some(reservation);
                stage = "failover";
            }
        }
    }
    if selected.is_none() && (forced_relay || runtime.relay_fallback.load(Ordering::Relaxed)) {
        let attempts = destinations
            .into_iter()
            .map(|destination| connect_via_relay(destination, runtime.relay_route.clone()));
        if let Ok(stream) = race_connections(attempts, Duration::from_secs(2)).await {
            selected = Some((None, stream));
            stage = if forced_relay {
                "relay"
            } else {
                "relay_fallback"
            };
        }
    }
    record["connect_ms"] = json!(connecting.elapsed().as_secs_f64() * 1000.0);
    record["stage"] = json!(stage);
    let Some((path, outbound)) = selected else {
        client.write_all(&[5, 4, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
        record["result"] = json!("no_route");
        println!("FLOW_RECORD {record}");
        bail!("no route succeeded for {host}:{port}");
    };
    record["path"] = json!(path.as_ref().map(|p| p.name.as_str()).unwrap_or("relay"));
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
    let direct_payload = path.as_ref().map(|_| runtime.payload.clone());
    let mut outbound = MeteredStream::new(outbound, path);
    // Hybrid relay traffic is already counted by the TUN payload observer.
    outbound.payload = direct_payload;
    let result =
        tokio::io::copy_bidirectional_with_sizes(&mut client, &mut outbound, 65_536, 65_536).await;
    runtime.active.fetch_sub(1, Ordering::Relaxed);
    drop(lease);
    outbound.sample();
    record["result"] = json!(match &result {
        Ok(_) => "closed",
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => "reset",
        Err(_) => "error",
    });
    record["up"] = json!(outbound.uploaded);
    record["down"] = json!(outbound.downloaded);
    record["acked"] = json!(outbound.acknowledged);
    record["retransmitted"] = json!(outbound.retransmitted);
    record["holds"] = json!(outbound.holds);
    record["ttfb_ms"] = json!(outbound.ttfb_ms());
    record["open_ms"] = json!(outbound.opened.elapsed().as_secs_f64() * 1000.0);
    record["total_ms"] = json!(accepted.elapsed().as_secs_f64() * 1000.0);
    record["min_rtt_ms"] =
        json!((outbound.minimum_rtt_us > 0).then_some(outbound.minimum_rtt_us as f64 / 1000.0));
    println!("FLOW_RECORD {record}");
    result?;
    Ok(())
}

/// Returns (handshake time, request-to-first-response-byte time). The second
/// value is the path's real end-to-end delay; the first is only a lower bound.
async fn probe_once(path: &Path, destination: SocketAddr) -> Result<(Duration, Duration)> {
    let started = Instant::now();
    let mut stream = time::timeout(PROBE_TIMEOUT, connect_on(path, destination))
        .await
        .context("probe connect timed out")??;
    let connect = started.elapsed();
    // Unique path defeats any transparent cache between us and the server.
    let nonce = PROBE_NONCE.fetch_add(1, Ordering::Relaxed);
    let request = format!(
        "HEAD /verz-probe/{nonce} HTTP/1.1\r\nHost: {}\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n",
        destination.ip()
    );
    let sent = Instant::now();
    stream.write_all(request.as_bytes()).await?;
    let mut first = [0_u8; 1];
    let read = time::timeout(PROBE_TIMEOUT, stream.read(&mut first))
        .await
        .context("probe response timed out")??;
    ensure!(read == 1, "probe peer closed without responding");
    Ok((connect, sent.elapsed()))
}

fn smooth(cell: &AtomicU64, observed: Duration) -> u64 {
    let observed = observed.as_micros().min(u128::from(u64::MAX)) as u64;
    let prior = cell.load(Ordering::Relaxed);
    cell.store(
        if prior == 0 {
            observed
        } else {
            (prior * 7 + observed) / 8
        },
        Ordering::Relaxed,
    );
    prior
}

async fn probe(runtime: Runtime) {
    let destination: SocketAddr = PROBE_DESTINATION.parse().expect("fixed probe destination");
    let health: SocketAddr = PROBE_HEALTH_DESTINATION
        .parse()
        .expect("fixed health destination");
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
                match probe_once(&path, destination).await {
                    Ok((connect, response)) => {
                        smooth(&path.connect_us, connect);
                        let observed = response.as_micros().min(u128::from(u64::MAX)) as u64;
                        let prior = smooth(&path.rtt_us, response);
                        let jitter = path.jitter_us.load(Ordering::Relaxed);
                        path.jitter_us.store(
                            (jitter * 3
                                + if prior == 0 {
                                    0
                                } else {
                                    prior.abs_diff(observed)
                                })
                                / 4,
                            Ordering::Relaxed,
                        );
                        path.healthy.store(true, Ordering::Relaxed);
                        path.probe_failure_ppm
                            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| Some(v * 7 / 8))
                            .ok();
                    }
                    Err(_) => {
                        path.failures.fetch_add(1, Ordering::Relaxed);
                        path.probe_failure_ppm
                            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                                Some(v * 7 / 8 + 125_000)
                            })
                            .ok();
                        // A network that blocks plain HTTP is still usable for
                        // TLS; only a failed handshake marks the path offline.
                        // Its end-to-end delay then stays unknown, so it is
                        // never preferred for realtime work on handshake alone.
                        let reachable =
                            time::timeout(PROBE_TIMEOUT, connect_on(&path, health)).await;
                        path.healthy
                            .store(matches!(reachable, Ok(Ok(_))), Ordering::Relaxed);
                    }
                }
                path.probing.store(false, Ordering::Relaxed);
            });
        }
    }
}

async fn telemetry(runtime: Runtime) {
    let payload_source = format!("proxy-{:016x}", rand::random::<u64>());
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
        let mut total_up = 0.0;
        let mut total_down = 0.0;
        let reports: Vec<_> = paths.iter().enumerate().map(|(id, path)| {
            let healthy = path.healthy.load(Ordering::Relaxed);
            let rtt = path.rtt_us.load(Ordering::Relaxed);
            let sent = path.sent.load(Ordering::Relaxed);
            let acknowledged = path.acknowledged.load(Ordering::Relaxed);
            let received = path.received.load(Ordering::Relaxed);
            let now = Instant::now();
            let (up, down) = previous.insert(path.incarnation, (now, acknowledged, received)).map(|(at, tx, rx)| {
                let secs = now.duration_since(at).as_secs_f64().max(0.001);
                (acknowledged.saturating_sub(tx) as f64 * 8.0 / secs, received.saturating_sub(rx) as f64 * 8.0 / secs)
            }).unwrap_or((0.0, 0.0));
            total_up += up;
            total_down += down;
            json!({
                "id": id, "name": path.name, "state": if healthy { "healthy" } else { "offline" },
                "enabled": true, "rtt_ms": if rtt == 0 { None } else { Some(rtt as f64 / 1000.0) },
                "connect_ms": match path.connect_us.load(Ordering::Relaxed) { 0 => None, v => Some(v as f64 / 1000.0) },
                "jitter_ms": path.jitter_us.load(Ordering::Relaxed) as f64 / 1000.0,
                "sent_bytes": sent, "received_bytes": received, "acknowledged_bytes": acknowledged,
                "delivery_bps": up + down, "latency_excluded": false,
                "realtime_preferred": advice.realtime_weights.get(&path.name).is_some_and(|w| *w > 0),
                "upload_bps": up, "download_bps": down, "active_flows": path.active.load(Ordering::Relaxed),
                "upload_held": path.upload_held(), "tcp_observed": path.tcp_observed.load(Ordering::Relaxed),
                "connect_failures": path.failures.load(Ordering::Relaxed)
            })
        }).collect();
        let traffic_shape = if total_down >= 1_000_000.0 && total_down > total_up * 2.0 {
            1
        } else if total_up >= 1_000_000.0 && total_up > total_down * 2.0 {
            2
        } else {
            0
        };
        runtime
            .traffic_shape
            .store(traffic_shape, Ordering::Relaxed);
        let healthy = paths
            .iter()
            .filter(|p| p.healthy.load(Ordering::Relaxed))
            .count();
        println!(
            "DIRECT_STATE {}",
            json!({
                "paths": reports, "healthy_paths": healthy, "assigned_ip": "", "server_ip": "",
                "payload": {"version":1,"source_id":payload_source,"sampled_at_ms":runtime.epoch.elapsed().as_millis() as u64,
                    "upload_bytes":runtime.payload.upload.load(Ordering::Relaxed),
                    "download_bytes":runtime.payload.download.load(Ordering::Relaxed),
                    "unmeasured_packets":runtime.payload.unmeasured.load(Ordering::Relaxed),
                    "basis":"tcp_socket_payload"},
                "active_connections": runtime.active.load(Ordering::Relaxed),
                "accepted_connections": runtime.accepted.load(Ordering::Relaxed),
                "direct_connections": runtime.direct_connections.load(Ordering::Relaxed),
                "relay_connections": runtime.relay_connections.load(Ordering::Relaxed),
                "traffic_shape": match traffic_shape { 1 => "download", 2 => "upload", _ => "balanced" },
                "balanced_champion": advice.balanced_champion,
                "download_champion": advice.download_champion,
                "upload_champion": advice.upload_champion,
                "download_guarded": advice.download_guarded,
                "upload_guarded": advice.upload_guarded,
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
            // Older servers do not provide champion/confidence guidance: use
            // the local v4 controller until both ends have been upgraded.
            let compatible = advice.strategy == crate::brain::STRATEGY && advice.valid_for_ms > 0;
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
    run_with_guidance(args, external, None, None).await
}

pub async fn run_with_guidance(
    args: DirectArgs,
    external: Option<mpsc::Receiver<Control>>,
    guidance: Option<watch::Sender<Guidance>>,
    relay_route: Option<watch::Receiver<Option<RelayRoute>>>,
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
        payload: Default::default(),
        paths: Arc::new(RwLock::new(paths)),
        policy: Arc::new(AtomicUsize::new(policy_number(args.policy))),
        cursor: Arc::new(AtomicUsize::new(0)),
        active: Arc::new(AtomicU64::new(0)),
        accepted: Arc::new(AtomicU64::new(0)),
        direct_connections: Arc::new(AtomicU64::new(0)),
        relay_connections: Arc::new(AtomicU64::new(0)),
        relay_fallback: Arc::new(AtomicBool::new(args.relay_fallback)),
        relay_route,
        cutoff_us: Arc::new(AtomicU64::new(DEFAULT_LATENCY_CUTOFF_US)),
        brain_advice: Arc::new(RwLock::new(None)),
        local_advice: Arc::new(RwLock::new(None)),
        traffic_shape: Arc::new(AtomicUsize::new(0)),
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

    #[tokio::test]
    async fn preferred_connection_wins_without_opening_a_backup() {
        let launched = Arc::new(AtomicUsize::new(0));
        let attempts = (0..4).map(|index| {
            let launched = launched.clone();
            async move {
                launched.fetch_add(1, Ordering::Relaxed);
                Ok(index)
            }
        });
        assert_eq!(race_connections(attempts, CONNECT_BUDGET).await.unwrap(), 0);
        assert_eq!(launched.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn stalled_primary_does_not_hold_backup_and_losing_leases_are_dropped() {
        let primary = parse_path("en0=192.0.2.1,false").unwrap();
        let backup = parse_path("en7=192.0.2.2,false").unwrap();
        let started = Instant::now();
        let attempts = [primary.clone(), backup.clone()]
            .into_iter()
            .enumerate()
            .map(|(index, path)| async move {
                let mut lease = PathLease::new(path);
                if index == 0 {
                    std::future::pending::<()>().await;
                }
                lease.connected();
                Ok(lease)
            });
        let winner = race_connections(attempts, CONNECT_BUDGET).await.unwrap();
        assert!(started.elapsed() < Duration::from_secs(1));
        assert_eq!(primary.active.load(Ordering::Relaxed), 0);
        assert_eq!(primary.connecting.load(Ordering::Relaxed), 0);
        assert_eq!(backup.active.load(Ordering::Relaxed), 1);
        drop(winner);
        assert_eq!(backup.active.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn all_stalled_candidates_share_one_deadline_and_release_reservations() {
        let path = parse_path("en0=192.0.2.1,false").unwrap();
        let attempts = (0..16).map(|_| {
            let path = path.clone();
            async move {
                let _lease = PathLease::new(path);
                std::future::pending::<Result<()>>().await
            }
        });
        let started = Instant::now();
        assert!(
            race_connections(attempts, Duration::from_millis(220))
                .await
                .is_err()
        );
        assert!(started.elapsed() < Duration::from_secs(1));
        assert_eq!(path.active.load(Ordering::Relaxed), 0);
        assert_eq!(path.connecting.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn refused_candidates_do_not_add_a_stagger_delay_each() {
        let started = Instant::now();
        let attempts = (0..8).map(|index| async move {
            ensure!(index == 7, "refused");
            Ok(index)
        });
        assert_eq!(race_connections(attempts, CONNECT_BUDGET).await.unwrap(), 7);
        assert!(started.elapsed() < CONNECT_STAGGER);
    }

    #[tokio::test]
    async fn hybrid_relay_cannot_fall_through_to_default_when_unready_or_invalid() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = listener.local_addr().unwrap();
        let (route_tx, route_rx) = watch::channel(None);
        assert!(
            connect_via_relay(endpoint, Some(route_rx.clone()))
                .await
                .is_err()
        );
        route_tx.send_replace(Some(RelayRoute {
            interface: "utun4294967294".into(),
            address: Ipv4Addr::LOCALHOST,
        }));
        assert!(connect_via_relay(endpoint, Some(route_rx)).await.is_err());
        assert!(
            time::timeout(Duration::from_millis(30), listener.accept())
                .await
                .is_err()
        );
    }

    fn runtime(paths: Vec<Arc<Path>>, policy: Policy) -> Runtime {
        Runtime {
            payload: Default::default(),
            paths: Arc::new(RwLock::new(paths)),
            policy: Arc::new(AtomicUsize::new(policy_number(policy))),
            cursor: Arc::new(AtomicUsize::new(0)),
            active: Arc::new(AtomicU64::new(0)),
            accepted: Arc::new(AtomicU64::new(0)),
            direct_connections: Arc::new(AtomicU64::new(0)),
            relay_connections: Arc::new(AtomicU64::new(0)),
            relay_fallback: Arc::new(AtomicBool::new(false)),
            relay_route: None,
            cutoff_us: Arc::new(AtomicU64::new(DEFAULT_LATENCY_CUTOFF_US)),
            brain_advice: Arc::new(RwLock::new(None)),
            local_advice: Arc::new(RwLock::new(None)),
            traffic_shape: Arc::new(AtomicUsize::new(0)),
            epoch: Instant::now(),
            guidance: None,
            secure_domains: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Cloud advice as it looks once the server has delivery evidence.
    async fn learned_advice(runtime: &Runtime) -> BrainAdvice {
        let mut advice = crate::brain::advise(&runtime.report().await, 1);
        advice.learned_paths = 1;
        advice
    }

    #[test]
    fn path_parser_rejects_unsafe_input() {
        assert!(parse_path("en0=192.168.1.2,false").is_ok());
        assert!(parse_path("../bad=192.168.1.2,false").is_err());
        assert!(parse_path("en0=127.0.0.1,false").is_err());
        assert!(parse_path("en0=192.168.1.2,maybe").is_err());
    }

    #[tokio::test]
    async fn proven_paths_share_work_but_realtime_prefers_low_delay() -> Result<()> {
        let a = parse_path("en0=192.168.1.2,false")?;
        let b = parse_path("en7=192.168.1.3,false")?;
        a.rtt_us.store(20_000, Ordering::Relaxed);
        b.rtt_us.store(40_000, Ordering::Relaxed);
        a.acknowledged.store(100_000, Ordering::Relaxed);
        b.acknowledged.store(100_000, Ordering::Relaxed);
        let runtime = runtime(vec![a.clone(), b.clone()], Policy::Smart);
        assert_eq!(runtime.candidates(Intent::Balanced).await[0].name, "en0");
        assert_eq!(runtime.candidates(Intent::Balanced).await[0].name, "en7");
        b.rtt_us.store(75_000, Ordering::Relaxed);
        assert_eq!(runtime.candidates(Intent::Balanced).await.len(), 2);
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
        assert_eq!(runtime.candidates(Intent::Balanced).await.len(), 2);
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
    async fn mixed_use_assignments_use_conservative_weights_and_reservations() -> Result<()> {
        let a = parse_path("en0=192.168.1.2,false")?;
        let b = parse_path("en7=192.168.1.3,false")?;
        a.active.store(100, Ordering::Relaxed); // idle keep-alives do not matter
        b.active.store(4, Ordering::Relaxed);
        a.acknowledged.store(100_000, Ordering::Relaxed);
        b.acknowledged.store(100_000, Ordering::Relaxed);
        let runtime = runtime(vec![a.clone(), b], Policy::Smart);
        let mut advice = learned_advice(&runtime).await;
        advice.download_weights = BTreeMap::from([("en0".into(), 64), ("en7".into(), 4)]);
        advice.upload_weights = BTreeMap::from([("en0".into(), 4), ("en7".into(), 64)]);
        advice.weights = BTreeMap::from([("en0".into(), 4), ("en7".into(), 16)]);
        *runtime.brain_advice.write().await = Some((Instant::now(), advice));
        assert_eq!(runtime.candidates(Intent::Balanced).await[0].name, "en7");
        let mut lease = PathLease::new(a.clone());
        assert_eq!(a.connecting.load(Ordering::Relaxed), 1);
        lease.connected();
        assert_eq!(a.connecting.load(Ordering::Relaxed), 0);
        drop(lease);
        assert_eq!(a.active.load(Ordering::Relaxed), 100);
        Ok(())
    }

    #[tokio::test]
    async fn live_traffic_direction_uses_its_own_champion_and_weights() -> Result<()> {
        let wifi = parse_path("en0=192.168.1.2,false")?;
        let lan = parse_path("en7=192.168.1.3,false")?;
        for path in [&wifi, &lan] {
            path.rtt_us.store(20_000, Ordering::Relaxed);
            path.acknowledged.store(100_000, Ordering::Relaxed);
            path.received.store(100_000, Ordering::Relaxed);
        }
        let runtime = runtime(vec![wifi, lan], Policy::Smart);
        let mut advice = learned_advice(&runtime).await;
        advice.download_champion = Some("en0".into());
        advice.upload_champion = Some("en7".into());
        advice.download_weights = BTreeMap::from([("en0".into(), 64), ("en7".into(), 8)]);
        advice.upload_weights = BTreeMap::from([("en0".into(), 8), ("en7".into(), 64)]);
        *runtime.brain_advice.write().await = Some((Instant::now(), advice));

        runtime.traffic_shape.store(1, Ordering::Relaxed);
        assert_eq!(runtime.candidates(Intent::Download).await[0].name, "en0");
        runtime.traffic_shape.store(2, Ordering::Relaxed);
        assert_eq!(runtime.candidates(Intent::Upload).await[0].name, "en7");
        Ok(())
    }

    #[tokio::test]
    async fn expired_advice_uses_local_learning_and_limits_unknown_path_trials() -> Result<()> {
        let a = parse_path("en0=192.168.1.2,false")?;
        let b = parse_path("en7=192.168.1.3,false")?;
        a.busy.store(2, Ordering::Relaxed);
        b.busy.store(2, Ordering::Relaxed);
        a.acknowledged.store(100_000, Ordering::Relaxed);
        b.acknowledged.store(100_000, Ordering::Relaxed);
        let runtime = runtime(vec![a, b], Policy::Smart);
        let mut remote = learned_advice(&runtime).await;
        remote.weights = BTreeMap::from([("en0".into(), 1), ("en7".into(), 64)]);
        let mut local = remote.clone();
        local.weights = BTreeMap::from([("en0".into(), 64), ("en7".into(), 1)]);
        *runtime.local_advice.write().await = Some(local);
        *runtime.brain_advice.write().await =
            Some((Instant::now() - Duration::from_secs(6), remote));
        assert_eq!(runtime.candidates(Intent::Balanced).await[0].name, "en0");
        let mut c = parse_path("en8=192.168.1.4,false")?;
        Arc::get_mut(&mut c).unwrap().created = Instant::now() - Duration::from_secs(6);
        runtime.paths.write().await.push(c);
        assert_eq!(runtime.candidates(Intent::Balanced).await[0].name, "en8");
        assert_eq!(runtime.candidates(Intent::Balanced).await[0].name, "en0");
        apply_control(
            &runtime,
            Control {
                interfaces: vec![],
                policy: None,
                secure_domains: None,
            },
        )
        .await;
        assert!(runtime.candidates(Intent::Balanced).await.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn live_socket_bytes_are_visible_before_close_and_half_close_survives() -> Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let socket = TcpStream::connect(listener.local_addr()?).await?;
        let (mut peer, _) = listener.accept().await?;
        let path = parse_path("en0=192.168.1.2,false")?;
        let mut socket = MeteredStream::new(socket, Some(path.clone()));
        let totals = Arc::new(PayloadTotals::default());
        socket.payload = Some(totals.clone());
        let writer = tokio::spawn(async move {
            let mut bytes = vec![];
            peer.read_to_end(&mut bytes).await.unwrap();
            assert_eq!(bytes, vec![42; 131_072]);
            peer.write_all(&[7; 128]).await.unwrap();
        });
        socket.write_all(&vec![42; 131_072]).await?;
        assert_eq!(path.sent.load(Ordering::Relaxed), 131_072);
        socket.shutdown().await?;
        let mut bytes = vec![];
        socket.read_to_end(&mut bytes).await?;
        assert_eq!(bytes, vec![7; 128]);
        assert_eq!(path.received.load(Ordering::Relaxed), 128);
        writer.await?;
        socket.sample();
        assert!(path.acknowledged.load(Ordering::Relaxed) > 0);
        assert!(path.acknowledged.load(Ordering::Relaxed) <= 131_072);
        assert_eq!(totals.download.load(Ordering::Relaxed), 128);
        assert!(totals.upload.load(Ordering::Relaxed) > 0);
        assert!(totals.upload.load(Ordering::Relaxed) <= 131_072);
        let before = totals.upload.load(Ordering::Relaxed);
        socket.sample();
        assert_eq!(totals.upload.load(Ordering::Relaxed), before);
        drop(socket);
        assert_eq!(path.queued.load(Ordering::Relaxed), 0);
        assert_eq!(path.busy.load(Ordering::Relaxed), 0);
        Ok(())
    }

    #[tokio::test]
    async fn stalled_socket_is_sampled_without_reads_and_cleans_up_on_cancellation() -> Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let socket = TcpStream::connect(listener.local_addr()?).await?;
        let (peer, _) = listener.accept().await?;
        let size: libc::c_int = 8192;
        // SAFETY: valid accepted socket and correctly sized integer option.
        assert_eq!(
            unsafe {
                libc::setsockopt(
                    peer.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_RCVBUF,
                    (&size as *const libc::c_int).cast(),
                    std::mem::size_of_val(&size) as libc::socklen_t,
                )
            },
            0
        );
        let path = parse_path("en0=192.168.1.2,false")?;
        let mut stream = MeteredStream::new(socket, Some(path.clone()));
        let transfer =
            tokio::spawn(async move { stream.write_all(&vec![0; 16 * 1024 * 1024]).await });
        time::timeout(Duration::from_secs(4), async {
            while !path.upload_held() {
                time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await?;
        assert!(path.queued.load(Ordering::Relaxed) > 0);
        assert!(path.acknowledged.load(Ordering::Relaxed) < path.sent.load(Ordering::Relaxed));
        transfer.abort();
        let _ = transfer.await;
        assert_eq!(path.queued.load(Ordering::Relaxed), 0);
        assert_eq!(path.busy.load(Ordering::Relaxed), 0);
        drop(peer);
        Ok(())
    }

    #[tokio::test]
    async fn expired_hold_allows_one_recovery_trial_not_an_upload_flood() -> Result<()> {
        let mut a = parse_path("en0=192.168.1.2,false")?;
        Arc::get_mut(&mut a).unwrap().created = Instant::now() - Duration::from_secs(10);
        a.acknowledged.store(1_000_000, Ordering::Relaxed);
        a.upload_hold_until_ms.store(5_000, Ordering::Relaxed);
        a.recovery_acknowledged.store(2_000_000, Ordering::Relaxed);
        let b = parse_path("en7=192.168.1.3,false")?;
        b.acknowledged.store(1_000_000, Ordering::Relaxed);
        b.busy.store(2, Ordering::Relaxed);
        let runtime = runtime(vec![a, b], Policy::Smart);
        assert_eq!(runtime.candidates(Intent::Balanced).await[0].name, "en0");
        assert_eq!(runtime.candidates(Intent::Balanced).await[0].name, "en7");
        Ok(())
    }

    #[test]
    fn unknown_encrypted_traffic_is_not_guessed_to_be_a_call() {
        assert!(!known_realtime_port(443));
        assert!(known_realtime_port(1935));
        assert!(known_realtime_port(5061));
    }

    #[test]
    fn unknown_flows_are_not_classified_by_machine_wide_traffic_shape() {
        assert_eq!(intent_for(443), Intent::Balanced);
        assert_eq!(intent_for(80), Intent::Balanced);
        assert_eq!(intent_for(5061), Intent::Realtime);
    }

    #[test]
    fn flow_record_destination_tag_is_salted_and_never_the_destination() {
        let a = destination_tag("Example.com", 443);
        assert_eq!(a, destination_tag("example.com", 443));
        assert_ne!(a, destination_tag("example.com", 80));
        assert_eq!(a.len(), 16);
        assert!(!a.contains("example"));
    }

    #[tokio::test]
    async fn plan_reports_its_evidence_and_ttfb_is_request_to_first_reply() -> Result<()> {
        let wifi = parse_path("en0=192.168.1.2,false")?;
        let lan = parse_path("en7=192.168.1.3,false")?;
        wifi.rtt_us.store(70_000, Ordering::Relaxed);
        lan.rtt_us.store(15_000, Ordering::Relaxed);
        let runtime = runtime(vec![wifi, lan], Policy::Smart);
        let plan = runtime.plan(Intent::Balanced).await;
        assert_eq!(plan.source, "none");
        assert_eq!(plan.features.len(), 2);
        assert!(
            plan.features
                .iter()
                .any(|f| f["name"] == "en7" && f["penalty"] == 1.0)
        );
        *runtime.local_advice.write().await =
            Some(crate::brain::advise(&runtime.report().await, 1));
        let plan = runtime.plan(Intent::Balanced).await;
        assert_eq!(plan.source, "local");
        assert_eq!(plan.primary.as_deref(), Some("en7"));

        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let socket = TcpStream::connect(listener.local_addr()?).await?;
        let (mut peer, _) = listener.accept().await?;
        let mut stream = MeteredStream::new(socket, None);
        assert_eq!(stream.ttfb_ms(), None);
        stream.write_all(b"ping").await?;
        peer.read_exact(&mut [0; 4]).await?;
        time::sleep(Duration::from_millis(50)).await;
        peer.write_all(b"pong").await?;
        stream.read_exact(&mut [0; 4]).await?;
        assert!(stream.ttfb_ms().is_some_and(|v| v >= 50.0));
        Ok(())
    }

    #[test]
    fn failover_wait_scales_with_measured_handshake_within_bounds() {
        assert_eq!(preferred_budget(0), CONNECT_ATTEMPT);
        assert_eq!(preferred_budget(70_000), Duration::from_millis(310));
        assert_eq!(preferred_budget(10_000), PREFERRED_MINIMUM);
        assert_eq!(preferred_budget(900_000), CONNECT_ATTEMPT);
    }

    #[test]
    fn latency_penalty_ignores_small_differences_and_unknowns() {
        assert_eq!(latency_factor(0, 66_000), 1.0);
        assert_eq!(latency_factor(66_000, 0), 1.0);
        assert_eq!(latency_factor(40_000, 20_000), 1.0);
        assert_eq!(latency_factor(66_000, 66_000), 1.0);
        let lan = latency_factor(620_000, 66_000);
        assert!((6.0..6.1).contains(&lan), "{lan}");
        assert_eq!(latency_factor(10_000_000, 1_000), 16.0);
    }

    #[tokio::test]
    async fn probe_times_the_response_not_the_handshake() -> Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let destination = listener.local_addr()?;
        // Middlebox stand-in: accepts instantly, answers 200 ms later.
        tokio::spawn(async move {
            let (mut peer, _) = listener.accept().await.unwrap();
            let mut request = vec![0; 512];
            let read = peer.read(&mut request).await.unwrap();
            assert!(request[..read].starts_with(b"HEAD /verz-probe/"));
            time::sleep(Duration::from_millis(200)).await;
            peer.write_all(b"HTTP/1.1 301 Moved Permanently\r\n\r\n")
                .await
                .unwrap();
        });
        let loopback = if cfg!(target_os = "macos") {
            "lo0"
        } else {
            "lo"
        };
        let path = parse_path(&format!("{loopback}=192.0.2.1,false"))?;
        let path = Path {
            address: Ipv4Addr::LOCALHOST,
            ..Arc::into_inner(path).expect("unshared path")
        };
        let (connect, response) = probe_once(&path, destination).await?;
        assert!(connect < Duration::from_millis(100), "{connect:?}");
        assert!(response >= Duration::from_millis(200), "{response:?}");
        Ok(())
    }

    #[tokio::test]
    async fn cloud_advice_without_evidence_defers_to_local_delay_measurement() -> Result<()> {
        let hotspot = parse_path("en0=192.168.1.2,false")?;
        let lan = parse_path("en7=192.168.1.3,false")?;
        hotspot.rtt_us.store(70_000, Ordering::Relaxed);
        lan.rtt_us.store(15_000, Ordering::Relaxed);
        let runtime = runtime(vec![hotspot, lan], Policy::Smart);
        let report = runtime.report().await;
        // Deployed server behaviour observed 2026-09-09: first-listed adapter
        // becomes champion with no delivery evidence (learned_paths == 0).
        let mut remote = crate::brain::advise(&report, 1);
        remote.balanced_champion = Some("en0".into());
        remote.weights = BTreeMap::from([("en0".into(), 64), ("en7".into(), 1)]);
        remote.learned_paths = 0;
        *runtime.brain_advice.write().await = Some((Instant::now(), remote.clone()));
        *runtime.local_advice.write().await = Some(crate::brain::advise(&report, 1));
        assert_eq!(runtime.candidates(Intent::Balanced).await[0].name, "en7");
        // Once the cloud has delivery evidence its advice is used again.
        remote.learned_paths = 1;
        *runtime.brain_advice.write().await = Some((Instant::now(), remote));
        assert_eq!(runtime.candidates(Intent::Balanced).await[0].name, "en0");
        Ok(())
    }

    #[tokio::test]
    async fn busy_fast_path_is_not_relieved_by_a_much_slower_idle_path() -> Result<()> {
        let wifi = parse_path("en0=192.168.1.2,false")?;
        let lan = parse_path("en7=192.168.1.3,false")?;
        wifi.rtt_us.store(66_000, Ordering::Relaxed);
        lan.rtt_us.store(620_000, Ordering::Relaxed);
        for path in [&wifi, &lan] {
            path.acknowledged.store(1_000_000, Ordering::Relaxed);
            path.received.store(1_000_000, Ordering::Relaxed);
        }
        let runtime = runtime(vec![wifi.clone(), lan.clone()], Policy::Smart);
        let mut advice = learned_advice(&runtime).await;
        advice.balanced_champion = Some("en0".into());
        // Learned shape of the measured setup: ~225/33 Mbps down.
        advice.weights = BTreeMap::from([("en0".into(), 64), ("en7".into(), 9)]);
        *runtime.brain_advice.write().await = Some((Instant::now(), advice));
        // Ten concurrent page-load flows on Wi-Fi previously sent the next
        // request to the 620 ms path.
        wifi.busy.store(10, Ordering::Relaxed);
        assert_eq!(runtime.candidates(Intent::Balanced).await[0].name, "en0");
        wifi.busy.store(40, Ordering::Relaxed);
        assert_eq!(runtime.candidates(Intent::Balanced).await[0].name, "en0");
        // Under heavy concurrency the slower path still adds capacity.
        wifi.busy.store(60, Ordering::Relaxed);
        assert_eq!(runtime.candidates(Intent::Balanced).await[0].name, "en7");
        // Comparable delay keeps the capacity-proportional sharing.
        lan.rtt_us.store(90_000, Ordering::Relaxed);
        wifi.busy.store(10, Ordering::Relaxed);
        assert_eq!(runtime.candidates(Intent::Balanced).await[0].name, "en7");
        Ok(())
    }

    #[tokio::test]
    async fn much_slower_unproven_path_is_trialled_only_under_real_load() -> Result<()> {
        let mut wifi = parse_path("en0=192.168.1.2,false")?;
        let mut lan = parse_path("en7=192.168.1.3,false")?;
        for path in [&mut wifi, &mut lan] {
            Arc::get_mut(path).unwrap().created = Instant::now() - Duration::from_secs(10);
        }
        wifi.rtt_us.store(66_000, Ordering::Relaxed);
        lan.rtt_us.store(620_000, Ordering::Relaxed);
        wifi.acknowledged.store(1_000_000, Ordering::Relaxed);
        wifi.received.store(1_000_000, Ordering::Relaxed);
        let runtime = runtime(vec![wifi.clone(), lan.clone()], Policy::Smart);
        let mut advice = learned_advice(&runtime).await;
        advice.balanced_champion = Some("en0".into());
        advice.weights = BTreeMap::from([("en0".into(), 64), ("en7".into(), 1)]);
        *runtime.brain_advice.write().await = Some((Instant::now(), advice));
        wifi.busy.store(1, Ordering::Relaxed);
        assert_eq!(runtime.candidates(Intent::Balanced).await[0].name, "en0");
        wifi.busy.store(8, Ordering::Relaxed);
        assert_eq!(runtime.candidates(Intent::Balanced).await[0].name, "en7");
        // One trial per five seconds; the next flow returns to the primary.
        assert_eq!(runtime.candidates(Intent::Balanced).await[0].name, "en0");
        // A similarly fast unproven path is trialled as soon as work exists.
        lan.rtt_us.store(80_000, Ordering::Relaxed);
        lan.last_trial_ms.store(0, Ordering::Relaxed);
        wifi.busy.store(1, Ordering::Relaxed);
        assert_eq!(runtime.candidates(Intent::Balanced).await[0].name, "en7");
        Ok(())
    }

    #[test]
    fn upload_guard_uses_backlog_and_loaded_delay_not_geographic_rtt() {
        assert!(!upload_congested(
            1_000_000,
            100_000,
            0,
            200_000,
            0,
            Duration::ZERO
        ));
        assert!(upload_congested(
            1_000_000,
            100_000,
            750_000,
            100_000,
            0,
            Duration::ZERO
        ));
        assert!(upload_congested(
            1_000_000,
            100_000,
            0,
            0,
            0,
            Duration::from_secs(1)
        ));
        assert!(upload_congested(
            1_000_000,
            100_000,
            0,
            10_000,
            5_000,
            Duration::ZERO
        ));
        assert!(!upload_congested(
            500,
            500,
            750_000,
            0,
            0,
            Duration::from_secs(1)
        ));
    }

    #[tokio::test]
    async fn local_congestion_overrides_remote_advice_but_never_blackholes_only_path() -> Result<()>
    {
        let a = parse_path("en0=192.168.1.2,false")?;
        let b = parse_path("en7=192.168.1.3,false")?;
        a.acknowledged.store(1_000_000, Ordering::Relaxed);
        b.acknowledged.store(1_000_000, Ordering::Relaxed);
        a.hold_uploads();
        b.busy.store(100, Ordering::Relaxed);
        let runtime = runtime(vec![a.clone(), b], Policy::Smart);
        let mut advice = learned_advice(&runtime).await;
        advice.weights = BTreeMap::from([("en0".into(), 64), ("en7".into(), 1)]);
        *runtime.brain_advice.write().await = Some((Instant::now(), advice));
        for _ in 0..20 {
            assert_eq!(runtime.candidates(Intent::Balanced).await[0].name, "en7");
        }
        *runtime.paths.write().await = vec![a];
        assert_eq!(runtime.candidates(Intent::Balanced).await[0].name, "en0");
        Ok(())
    }
}
