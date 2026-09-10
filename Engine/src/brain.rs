//! Authenticated, encrypted control channel for Automatic Hybrid. The channel
//! carries path health metadata and scheduling advice only; application
//! destinations and payloads never enter the brain protocol.
use crate::{bond::Policy, load_secret};
use anyhow::{Context, Result, ensure};
use clap::Args;
use serde::{Deserialize, Serialize};
use snow::{HandshakeState, TransportState};
use std::{
    collections::BTreeMap,
    net::SocketAddr,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

const NOISE_PATTERN: &str = "Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s";
const PROLOGUE: &[u8] = b"VERZ Link brain v1 / path metadata only";
const MAX_FRAME: usize = 65_535;
const CUTOFF_MS: f64 = 75.0;
const RECOVERY_MS: f64 = 65.0;
/// Bumped whenever the controller's learning rules change. A client only
/// follows a server that speaks the same version; otherwise it uses its own
/// controller, so a stale deployment cannot steer newer clients.
pub const STRATEGY: &str = "champion-challenger-v7";

#[derive(Args, Debug)]
pub struct BrainServerArgs {
    #[arg(long, default_value = "0.0.0.0:39003")]
    pub listen: SocketAddr,
    #[arg(long)]
    pub secret_file: PathBuf,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct PathReport {
    #[serde(rename = "n", alias = "name")]
    pub name: String,
    #[serde(rename = "l", alias = "rtt_ms")]
    pub rtt_ms: Option<f64>,
    #[serde(rename = "h", alias = "healthy")]
    pub healthy: bool,
    #[serde(rename = "m", alias = "metered")]
    pub metered: bool,
    #[serde(default, skip_serializing)]
    pub failures: u64,
    /// Legacy accepted-write counter is readable but never sent or used to
    /// learn upload capacity. v3 sends TCP-acknowledged bytes instead.
    #[serde(default, skip_serializing, rename = "tx", alias = "sent_bytes")]
    pub sent_bytes: u64,
    #[serde(default, rename = "rx", alias = "received_bytes")]
    pub received_bytes: u64,
    #[serde(default, rename = "f", alias = "flows", alias = "active_flows")]
    pub active_flows: u64,
    #[serde(default, rename = "j", alias = "jitter_ms")]
    pub jitter_ms: f64,
    /// Failed reachability probes / probes, smoothed locally. NOT packet loss.
    #[serde(
        default,
        rename = "p",
        alias = "probe_fail",
        alias = "probe_failure_ratio"
    )]
    pub probe_failure_ratio: f64,
    /// Changes when an adapter changes address; contains no address itself.
    #[serde(default, rename = "e", alias = "epoch", alias = "incarnation")]
    pub incarnation: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tcp: Option<TcpReport>,
}

/// TCP transport feedback only; no destinations, payloads or interface IPs.
/// Short wire keys keep the authenticated 256-adapter report within one frame.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct TcpReport {
    #[serde(rename = "a")]
    pub acknowledged: u64,
    #[serde(rename = "r")]
    pub retransmitted: u64,
    #[serde(rename = "q")]
    pub queued: u64,
    #[serde(rename = "b")]
    pub busy: u64,
    #[serde(rename = "h")]
    pub held: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ClientReport {
    pub policy: Policy,
    pub paths: Vec<PathReport>,
    #[serde(default)]
    pub sample_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BrainAdvice {
    pub generation: u64,
    pub strategy: String,
    pub cutoff_ms: f64,
    pub recovery_ms: f64,
    pub relay_fallback: bool,
    pub weights: BTreeMap<String, u32>,
    #[serde(default)]
    pub download_weights: BTreeMap<String, u32>,
    #[serde(default)]
    pub upload_weights: BTreeMap<String, u32>,
    #[serde(default)]
    pub realtime_weights: BTreeMap<String, u32>,
    /// Direction-specific proven paths. The Mac treats these as advisory;
    /// immediate health, congestion and cost policy remain authoritative.
    #[serde(default)]
    pub balanced_champion: Option<String>,
    #[serde(default)]
    pub download_champion: Option<String>,
    #[serde(default)]
    pub upload_champion: Option<String>,
    /// True when adding challengers failed to preserve 95% of the champion's
    /// recent delivered-rate envelope. New work contracts to the champion;
    /// existing TCP connections are never reset or migrated.
    #[serde(default)]
    pub download_guarded: bool,
    #[serde(default)]
    pub upload_guarded: bool,
    #[serde(default)]
    pub learned_paths: usize,
    #[serde(default)]
    pub valid_for_ms: u64,
}

pub type Guidance = Option<(std::time::Instant, BrainAdvice)>;

#[derive(Default)]
struct Observation {
    sample_ms: u64,
    acknowledged: u64,
    tcp_observed: bool,
    received: u64,
    upload_bps: f64,
    download_bps: f64,
    current_upload_bps: f64,
    current_download_bps: f64,
    upload_samples: u32,
    download_samples: u32,
    upload_learned: u64,
    download_learned: u64,
    /// Highest observed goodput on this path, decayed slowly regardless of
    /// current workload. Prevents the champion from oscillating away from a
    /// proven fast link merely because current traffic is small.
    upload_peak_bps: f64,
    download_peak_bps: f64,
    incarnation: u64,
}

/// Online feedback controller, not a pretrained AI model. Learns a decaying
/// goodput envelope separately in each direction. Goodput is only an observed
/// lower bound on capacity, not a claim that writes reached the network. The
/// Mac bounds unknown/recovering-path trials and handles congestion locally.
#[derive(Default)]
pub struct Controller {
    observations: BTreeMap<String, Observation>,
    download_champion: Option<String>,
    upload_champion: Option<String>,
    balanced_champion: Option<String>,
}

const LEARNING_BYTES: u64 = 64 * 1024;
/// Delivered bytes that prove a path on their own. A fast link finishes a
/// trial transfer in one or two intervals; requiring three separate seconds
/// left a 300 Mbps path unproven forever behind an 85 Mbps champion.
const PROVEN_BYTES: u64 = 8 * 1024 * 1024;
const IDLE_DECAY_MS: f64 = 600_000.0;
const CHAMPION_SWITCH_MARGIN: f64 = 1.15;
const PERFORMANCE_FLOOR: f64 = 0.95;
const MIN_CAPACITY_SAMPLES: u32 = 3;
const CHALLENGER_WEIGHT: u32 = 1;

/// Evidence count used for proof: interval samples, or the full requirement
/// once enough bytes have been delivered in total.
fn evidence(samples: u32, learned_bytes: u64) -> u32 {
    if learned_bytes >= PROVEN_BYTES {
        samples.max(MIN_CAPACITY_SAMPLES)
    } else {
        samples
    }
}

fn learned_rate(observation: &Observation, upload: bool) -> f64 {
    let samples = if upload {
        observation.upload_samples
    } else {
        observation.download_samples
    };
    if samples == 0 {
        0.0
    } else if upload {
        observation.upload_bps
    } else {
        observation.download_bps
    }
}

/// Rate used when choosing a champion: the higher of the current envelope and
/// the slowly-decayed peak. Allocation weights keep tracking the envelope so
/// pacing follows what the path is actually delivering right now.
fn champion_rate(observation: &Observation, upload: bool) -> f64 {
    let peak = if upload {
        observation.upload_peak_bps
    } else {
        observation.download_peak_bps
    };
    learned_rate(observation, upload).max(peak)
}

fn download_evidence(o: &Observation) -> u32 {
    evidence(o.download_samples, o.download_learned)
}

fn upload_evidence(o: &Observation) -> u32 {
    evidence(o.upload_samples, o.upload_learned)
}

/// Two-way placement rate. Both directions known: the weaker one. Only one
/// known: that one, because a download-only workload otherwise never produces
/// upload evidence and the balanced champion would stay at its cold-start
/// tie-break forever. Local upload holds still protect against a poor uplink.
fn balanced_rate(o: &Observation) -> f64 {
    match (learned_rate(o, true), learned_rate(o, false)) {
        (up, down) if up > 0.0 && down > 0.0 => up.min(down),
        (up, down) => up.max(down),
    }
}

fn balanced_evidence(o: &Observation) -> u32 {
    upload_evidence(o).max(download_evidence(o))
}

fn choose_champion(
    previous: &Option<String>,
    paths: &[&PathReport],
    observations: &BTreeMap<String, Observation>,
    score: impl Fn(&Observation) -> f64,
    samples: impl Fn(&Observation) -> u32,
) -> Option<String> {
    // Capacity is unknowable before delivery evidence exists. During cold
    // start, bulk traffic follows the path with the lowest measured end-to-end
    // request delay (the Mac's probe times a real response, not a handshake a
    // local middlebox can complete). Adapter order is only the last resort; the
    // UI lists Wi-Fi first, which is not evidence of anything.
    let fallback = || {
        paths
            .iter()
            .filter(|p| p.rtt_ms.is_some_and(|v| v.is_finite() && v > 0.0))
            .min_by(|a, b| realtime_cost(a).total_cmp(&realtime_cost(b)))
            .or(paths.first())
            .map(|p| p.name.clone())
    };
    let best = paths
        .iter()
        .filter_map(|p| {
            let observation = &observations[&p.name];
            let value = score(observation);
            (samples(observation) >= MIN_CAPACITY_SAMPLES && value >= 64_000.0)
                .then_some((p.name.as_str(), value))
        })
        .max_by(|a, b| a.1.total_cmp(&b.1));
    let Some((best_name, best_score)) = best else {
        return fallback();
    };
    if let Some(current) = previous
        && paths.iter().any(|p| p.name == *current)
    {
        let observation = &observations[current];
        let current_score = score(observation);
        if samples(observation) >= MIN_CAPACITY_SAMPLES
            && current_score >= 64_000.0
            && best_score < current_score * CHAMPION_SWITCH_MARGIN
        {
            return Some(current.clone());
        }
    }
    Some(best_name.to_owned())
}

fn allocation_weight(
    eligible: bool,
    champion: bool,
    rate: f64,
    champion_rate: f64,
    samples: u32,
    reliability: f64,
) -> u32 {
    if !eligible {
        return 0;
    }
    if champion {
        return 64;
    }
    if samples < MIN_CAPACITY_SAMPLES || rate < 64_000.0 || champion_rate < 64_000.0 {
        return CHALLENGER_WEIGHT;
    }
    (64.0 * (rate / champion_rate).clamp(1.0 / 64.0, 1.0) * reliability)
        .round()
        .clamp(1.0, 64.0) as u32
}

impl Controller {
    pub fn advise(&mut self, report: &ClientReport, generation: u64) -> BrainAdvice {
        self.observations
            .retain(|name, _| report.paths.iter().any(|p| p.name == *name));
        for p in &report.paths {
            let prior = self.observations.entry(p.name.clone()).or_default();
            let acknowledged = p.tcp.as_ref().map(|t| t.acknowledged).unwrap_or(0);
            let elapsed = report.sample_ms.saturating_sub(prior.sample_ms);
            let same = p.incarnation == prior.incarnation
                && acknowledged >= prior.acknowledged
                && p.received_bytes >= prior.received
                && (100..=10_000).contains(&elapsed);
            if same {
                let rate = |bytes: u64| bytes as f64 * 8_000.0 / elapsed as f64;
                let uploaded = acknowledged - prior.acknowledged;
                let downloaded = p.received_bytes - prior.received;
                // Under load the envelope tracks what the path delivers now
                // (30 s). Idle is not evidence of less capacity: the 2026-09-09
                // log shows a fast LAN losing the champion to a hotspot merely
                // because a speed test paused for 40 s. Idle decays slowly.
                let decay = |learning: u64| {
                    let horizon = if learning >= LEARNING_BYTES {
                        30_000.0
                    } else {
                        IDLE_DECAY_MS
                    };
                    (-(elapsed as f64) / horizon).exp()
                };
                let upload_decay = decay(uploaded);
                let download_decay = decay(downloaded);
                // Peak decays only on the idle horizon (~10 minutes), so the
                // measured ceiling of a proven fast link survives long stretches
                // of small traffic that would otherwise drag its envelope down.
                let peak_decay = (-(elapsed as f64) / IDLE_DECAY_MS).exp();
                let current_upload = if p.tcp.is_some() && prior.tcp_observed {
                    rate(uploaded)
                } else {
                    0.0
                };
                let current_download = rate(downloaded);
                prior.current_upload_bps = current_upload;
                prior.current_download_bps = current_download;
                if uploaded >= LEARNING_BYTES {
                    prior.upload_samples = prior.upload_samples.saturating_add(1);
                    prior.upload_learned = prior.upload_learned.saturating_add(uploaded);
                }
                if downloaded >= LEARNING_BYTES {
                    prior.download_samples = prior.download_samples.saturating_add(1);
                    prior.download_learned = prior.download_learned.saturating_add(downloaded);
                }
                prior.upload_bps = if p.tcp.is_some() && prior.tcp_observed {
                    if p.tcp.as_ref().is_some_and(|t| t.held) {
                        current_upload // old peak must not immediately refill a congested path
                    } else {
                        (prior.upload_bps * upload_decay).max(current_upload)
                    }
                } else {
                    0.0
                };
                prior.download_bps = (prior.download_bps * download_decay).max(current_download);
                prior.upload_peak_bps = if p.tcp.as_ref().is_some_and(|t| t.held) {
                    current_upload
                } else {
                    (prior.upload_peak_bps * peak_decay).max(prior.upload_bps)
                };
                prior.download_peak_bps =
                    (prior.download_peak_bps * peak_decay).max(prior.download_bps);
            } else {
                prior.upload_bps = 0.0;
                prior.download_bps = 0.0;
                prior.current_upload_bps = 0.0;
                prior.current_download_bps = 0.0;
                prior.upload_samples = 0;
                prior.download_samples = 0;
                prior.upload_learned = 0;
                prior.download_learned = 0;
                prior.upload_peak_bps = 0.0;
                prior.download_peak_bps = 0.0;
            }
            prior.sample_ms = report.sample_ms;
            prior.acknowledged = acknowledged;
            prior.tcp_observed = p.tcp.is_some();
            prior.received = p.received_bytes;
            prior.incarnation = p.incarnation;
        }
        let usable: Vec<_> = report.paths.iter().filter(|p| p.healthy).collect();
        let has_unmetered = usable.iter().any(|p| !p.metered);
        let eligible = |p: &PathReport| {
            p.healthy && !(report.policy == Policy::DataSaver && p.metered && has_unmetered)
        };
        let eligible_paths: Vec<_> = report.paths.iter().filter(|p| eligible(p)).collect();
        let download_champion = choose_champion(
            &self.download_champion,
            &eligible_paths,
            &self.observations,
            |o| champion_rate(o, false),
            download_evidence,
        );
        let upload_champion = choose_champion(
            &self.upload_champion,
            &eligible_paths,
            &self.observations,
            |o| champion_rate(o, true),
            upload_evidence,
        );
        let balanced_champion = choose_champion(
            &self.balanced_champion,
            &eligible_paths,
            &self.observations,
            |o| match (champion_rate(o, true), champion_rate(o, false)) {
                (up, down) if up > 0.0 && down > 0.0 => up.min(down),
                (up, down) => up.max(down),
            },
            balanced_evidence,
        );
        self.download_champion = download_champion.clone();
        self.upload_champion = upload_champion.clone();
        self.balanced_champion = balanced_champion.clone();

        let champion_rate = |name: &Option<String>, upload: bool| {
            name.as_ref()
                .and_then(|name| self.observations.get(name))
                .map(|o| learned_rate(o, upload))
                .unwrap_or(0.0)
        };
        let download_champion_rate = champion_rate(&download_champion, false);
        let upload_champion_rate = champion_rate(&upload_champion, true);
        let active_download_paths = eligible_paths
            .iter()
            .filter(|p| self.observations[&p.name].current_download_bps >= 64_000.0)
            .count();
        let active_upload_paths = eligible_paths
            .iter()
            .filter(|p| self.observations[&p.name].current_upload_bps >= 64_000.0)
            .count();
        let current_download: f64 = eligible_paths
            .iter()
            .map(|p| self.observations[&p.name].current_download_bps)
            .sum();
        let current_upload: f64 = eligible_paths
            .iter()
            .map(|p| self.observations[&p.name].current_upload_bps)
            .sum();
        let download_guarded = active_download_paths > 1
            && download_champion_rate >= 1_000_000.0
            && current_download >= 1_000_000.0
            && current_download < download_champion_rate * PERFORMANCE_FLOOR;
        let upload_guarded = active_upload_paths > 1
            && upload_champion_rate >= 1_000_000.0
            && current_upload >= 1_000_000.0
            && current_upload < upload_champion_rate * PERFORMANCE_FLOOR;
        let has_fast = report
            .paths
            .iter()
            .any(|p| eligible(p) && p.rtt_ms.is_some_and(|v| v > 0.0 && v < CUTOFF_MS));
        let best = report
            .paths
            .iter()
            .filter(|p| eligible(p))
            .min_by(|a, b| realtime_cost(a).total_cmp(&realtime_cost(b)))
            .map(|p| p.name.as_str());
        let mut advice = BrainAdvice {
            generation,
            strategy: STRATEGY.into(),
            cutoff_ms: CUTOFF_MS,
            recovery_ms: RECOVERY_MS,
            relay_fallback: true,
            weights: BTreeMap::new(),
            download_weights: BTreeMap::new(),
            upload_weights: BTreeMap::new(),
            realtime_weights: BTreeMap::new(),
            balanced_champion: balanced_champion.clone(),
            download_champion: download_champion.clone(),
            upload_champion: upload_champion.clone(),
            download_guarded,
            upload_guarded,
            learned_paths: 0,
            valid_for_ms: 5_000,
        };
        for p in &report.paths {
            let o = &self.observations[&p.name];
            if o.upload_samples > 0 || o.download_samples > 0 {
                advice.learned_paths += 1;
            }
            let reliability = 1.0 - finite(p.probe_failure_ratio, 0.0).clamp(0.0, 1.0) * 0.8;
            let up = if p.tcp.as_ref().is_some_and(|t| t.held) {
                0
            } else if upload_guarded && upload_champion.as_deref() != Some(p.name.as_str()) {
                1
            } else {
                allocation_weight(
                    eligible(p),
                    upload_champion.as_deref() == Some(p.name.as_str()),
                    learned_rate(o, true),
                    upload_champion_rate,
                    upload_evidence(o),
                    reliability,
                )
            };
            let down = if download_guarded && download_champion.as_deref() != Some(p.name.as_str())
            {
                1
            } else {
                allocation_weight(
                    eligible(p),
                    download_champion.as_deref() == Some(p.name.as_str()),
                    learned_rate(o, false),
                    download_champion_rate,
                    download_evidence(o),
                    reliability,
                )
            };
            advice.upload_weights.insert(p.name.clone(), up);
            advice.download_weights.insert(p.name.clone(), down);
            let balanced_champion_rate = balanced_champion
                .as_ref()
                .and_then(|name| self.observations.get(name))
                .map(balanced_rate)
                .unwrap_or(0.0);
            let balanced = if p.tcp.as_ref().is_some_and(|t| t.held) {
                0
            } else {
                allocation_weight(
                    eligible(p),
                    balanced_champion.as_deref() == Some(p.name.as_str()),
                    balanced_rate(o),
                    balanced_champion_rate,
                    balanced_evidence(o),
                    reliability,
                )
            };
            advice.weights.insert(p.name.clone(), balanced);
            let realtime = eligible(p)
                && if has_fast {
                    p.rtt_ms.is_some_and(|v| v > 0.0 && v < CUTOFF_MS)
                } else {
                    best == Some(p.name.as_str())
                };
            advice.realtime_weights.insert(
                p.name.clone(),
                if realtime {
                    (640.0 / realtime_cost(p)).round().clamp(1.0, 64.0) as u32
                } else {
                    0
                },
            );
        }
        advice
    }
}

fn finite(value: f64, fallback: f64) -> f64 {
    if value.is_finite() { value } else { fallback }
}
fn realtime_cost(p: &PathReport) -> f64 {
    finite(p.rtt_ms.unwrap_or(1_000.0), 1_000.0).clamp(1.0, 10_000.0)
        + 4.0 * finite(p.jitter_ms, 0.0).clamp(0.0, 1_000.0)
        + 500.0 * finite(p.probe_failure_ratio, 0.0).clamp(0.0, 1.0)
}

pub struct BrainClient {
    stream: TcpStream,
    noise: TransportState,
}

fn handshake(secret: &[u8; 32], initiator: bool) -> Result<HandshakeState> {
    let builder = snow::Builder::new(NOISE_PATTERN.parse()?)
        .psk(0, secret)?
        .prologue(PROLOGUE)?;
    Ok(if initiator {
        builder.build_initiator()?
    } else {
        builder.build_responder()?
    })
}

async fn write_frame(stream: &mut TcpStream, payload: &[u8]) -> Result<()> {
    ensure!(
        !payload.is_empty() && payload.len() <= MAX_FRAME,
        "invalid brain frame length"
    );
    stream.write_u32(payload.len() as u32).await?;
    stream.write_all(payload).await?;
    Ok(())
}

async fn read_frame(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let length = stream.read_u32().await? as usize;
    ensure!(
        (1..=MAX_FRAME).contains(&length),
        "invalid brain frame length"
    );
    let mut payload = vec![0; length];
    stream.read_exact(&mut payload).await?;
    Ok(payload)
}

async fn client_handshake(stream: &mut TcpStream, secret: &[u8; 32]) -> Result<TransportState> {
    let mut noise = handshake(secret, true)?;
    let mut wire = vec![0; MAX_FRAME];
    let size = noise.write_message(&[], &mut wire)?;
    write_frame(stream, &wire[..size]).await?;
    let response = read_frame(stream).await?;
    noise.read_message(&response, &mut wire)?;
    Ok(noise.into_transport_mode()?)
}

async fn server_handshake(stream: &mut TcpStream, secret: &[u8; 32]) -> Result<TransportState> {
    let mut noise = handshake(secret, false)?;
    let request = read_frame(stream).await?;
    let mut wire = vec![0; MAX_FRAME];
    noise.read_message(&request, &mut wire)?;
    let size = noise.write_message(&[], &mut wire)?;
    write_frame(stream, &wire[..size]).await?;
    Ok(noise.into_transport_mode()?)
}

impl BrainClient {
    pub async fn connect(address: SocketAddr, secret: &[u8; 32]) -> Result<Self> {
        let stream = TcpStream::connect(address)
            .await
            .with_context(|| format!("connect brain {address}"))?;
        Self::from_stream(stream, secret).await
    }

    /// Complete the encrypted protocol on a pre-connected stream. Hybrid uses
    /// this entry point after binding the TCP socket to a physical adapter, so
    /// control reconnects can never recurse into the data tunnel.
    pub async fn from_stream(mut stream: TcpStream, secret: &[u8; 32]) -> Result<Self> {
        stream.set_nodelay(true)?;
        let noise = client_handshake(&mut stream, secret).await?;
        Ok(Self { stream, noise })
    }

    pub async fn exchange(&mut self, report: &ClientReport) -> Result<BrainAdvice> {
        let plain = serde_json::to_vec(report)?;
        let mut encrypted = vec![0; plain.len() + 64];
        let size = self.noise.write_message(&plain, &mut encrypted)?;
        write_frame(&mut self.stream, &encrypted[..size]).await?;
        let encrypted = read_frame(&mut self.stream).await?;
        let mut plain = vec![0; encrypted.len()];
        let size = self.noise.read_message(&encrypted, &mut plain)?;
        Ok(serde_json::from_slice(&plain[..size])?)
    }
}

pub fn advise(report: &ClientReport, generation: u64) -> BrainAdvice {
    Controller::default().advise(report, generation)
}

async fn serve_connection(
    mut stream: TcpStream,
    secret: [u8; 32],
    generations: Arc<AtomicU64>,
) -> Result<()> {
    stream.set_nodelay(true)?;
    let mut noise = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        server_handshake(&mut stream, &secret),
    )
    .await??;
    let mut controller = Controller::default();
    loop {
        let encrypted =
            tokio::time::timeout(std::time::Duration::from_secs(15), read_frame(&mut stream))
                .await??;
        let mut plain = vec![0; encrypted.len()];
        let size = noise.read_message(&encrypted, &mut plain)?;
        let report: ClientReport = serde_json::from_slice(&plain[..size])?;
        ensure!(report.paths.len() <= 256, "too many reported paths");
        let generation = generations.fetch_add(1, Ordering::Relaxed) + 1;
        let advice = controller.advise(&report, generation);
        let plain = serde_json::to_vec(&advice)?;
        let mut encrypted = vec![0; plain.len() + 64];
        let size = noise.write_message(&plain, &mut encrypted)?;
        write_frame(&mut stream, &encrypted[..size]).await?;
    }
}

pub async fn run_server(args: BrainServerArgs) -> Result<()> {
    let secret = load_secret(&args.secret_file)?;
    let listener = TcpListener::bind(args.listen).await?;
    let generations = Arc::new(AtomicU64::new(0));
    println!("BRAIN LISTENING: {}", listener.local_addr()?);
    loop {
        let (stream, _) = listener.accept().await?;
        let generations = generations.clone();
        tokio::spawn(async move {
            // Authentication failures and disconnects are isolated to one
            // client and never stop the shared control service.
            let _ = serve_connection(stream, secret, generations).await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(policy: Policy) -> ClientReport {
        ClientReport {
            policy,
            sample_ms: 0,
            paths: vec![
                PathReport {
                    name: "en0".into(),
                    rtt_ms: Some(20.0),
                    healthy: true,
                    metered: false,
                    failures: 0,
                    ..PathReport::default()
                },
                PathReport {
                    name: "en7".into(),
                    rtt_ms: Some(40.0),
                    healthy: true,
                    metered: false,
                    failures: 0,
                    ..PathReport::default()
                },
                PathReport {
                    name: "en8".into(),
                    rtt_ms: Some(80.0),
                    healthy: true,
                    metered: true,
                    failures: 0,
                    ..PathReport::default()
                },
            ],
        }
    }

    #[test]
    fn high_latency_is_bulk_capacity_but_not_realtime_preferred() {
        let advice = advise(&report(Policy::Performance), 9);
        assert_eq!(advice.balanced_champion.as_deref(), Some("en0"));
        assert_eq!(advice.weights["en0"], 64);
        assert_eq!(advice.weights["en7"], CHALLENGER_WEIGHT);
        assert!(advice.weights["en8"] > 0);
        assert_eq!(advice.realtime_weights["en8"], 0);
        assert_eq!(advice.generation, 9);
        assert!(advice.relay_fallback);
    }

    #[test]
    fn data_saver_excludes_metered_when_unmetered_exists() {
        let mut report = report(Policy::DataSaver);
        report.paths[2].rtt_ms = Some(10.0);
        assert_eq!(advise(&report, 1).weights["en8"], 0);
    }

    #[test]
    fn cold_start_champion_follows_measured_delay_not_adapter_order() {
        let mut report = report(Policy::Smart);
        // Wi-Fi is listed first by the UI but has a 620 ms end-to-end delay.
        report.paths[0].rtt_ms = Some(620.0);
        report.paths[1].rtt_ms = Some(66.0);
        let advice = advise(&report, 1);
        assert_eq!(advice.balanced_champion.as_deref(), Some("en7"));
        assert_eq!(advice.download_champion.as_deref(), Some("en7"));
        assert_eq!(advice.weights["en7"], 64);
        assert_eq!(advice.weights["en0"], CHALLENGER_WEIGHT);
        // Without any delay measurement the order remains the only tie-break.
        for p in &mut report.paths {
            p.rtt_ms = None;
        }
        assert_eq!(advise(&report, 2).balanced_champion.as_deref(), Some("en0"));
    }

    #[test]
    fn all_slow_keeps_bulk_paths_and_best_realtime_last_resort() {
        let mut report = report(Policy::Smart);
        report.paths[0].rtt_ms = Some(100.0);
        report.paths[1].rtt_ms = Some(90.0);
        report.paths[2].rtt_ms = Some(110.0);
        let advice = advise(&report, 1);
        assert!(advice.weights.values().all(|v| *v > 0));
        assert!(advice.realtime_weights["en7"] > 0);
        assert_eq!(advice.realtime_weights["en0"], 0);
        assert_eq!(advice.realtime_weights["en8"], 0);
    }

    #[test]
    fn learns_opposite_upload_download_strengths_without_starving_new_paths() {
        let mut report = report(Policy::Smart);
        for p in &mut report.paths {
            p.tcp = Some(TcpReport::default());
        }
        let mut controller = Controller::default();
        controller.advise(&report, 1);
        let mut advice = controller.advise(&report, 1);
        for sample in 1..=MIN_CAPACITY_SAMPLES {
            report.sample_ms = u64::from(sample) * 1_000;
            report.paths[0].received_bytes += 30_000_000;
            report.paths[1].received_bytes += 1_000_000;
            report.paths[0].tcp.as_mut().unwrap().acknowledged += 1_000_000;
            report.paths[1].tcp.as_mut().unwrap().acknowledged += 30_000_000;
            advice = controller.advise(&report, u64::from(sample) + 1);
            // 30 MB delivered in one interval is proof on its own; the small
            // 1 MB/s uploader still needs three intervals.
            assert_eq!(advice.upload_champion.as_deref(), Some("en7"));
            if sample < MIN_CAPACITY_SAMPLES {
                assert_eq!(advice.upload_weights["en0"], CHALLENGER_WEIGHT);
            }
        }
        assert!(advice.download_weights["en0"] > advice.download_weights["en7"]);
        assert!(advice.upload_weights["en7"] > advice.upload_weights["en0"]);
        assert_eq!(advice.download_champion.as_deref(), Some("en0"));
        assert_eq!(advice.upload_champion.as_deref(), Some("en7"));
        assert!(advice.weights["en8"] > 0);
        assert_eq!(advice.learned_paths, 2);
        report.paths[0].incarnation += 1;
        report.sample_ms += 1_000;
        assert_eq!(controller.advise(&report, 5).learned_paths, 1);
    }

    #[test]
    fn one_full_trial_transfer_proves_a_fast_challenger_for_download_only_work() {
        // Measured 2026-09-09: hotspot listed first (~85 Mbps), LAN ~306 Mbps.
        // Eight parallel downloads put seven on the hotspot because a 50 MB
        // trial finishing in 1.4 s could never accumulate three samples.
        let mut report = report(Policy::Smart);
        report.paths.truncate(2);
        for p in &mut report.paths {
            p.rtt_ms = None;
            p.tcp = Some(TcpReport::default());
        }
        let mut controller = Controller::default();
        controller.advise(&report, 0);
        for second in 1..=3 {
            report.sample_ms = second * 1_000;
            report.paths[0].received_bytes += 10_600_000;
            controller.advise(&report, second);
        }
        let advice = controller.advise(&report, 4);
        assert_eq!(advice.download_champion.as_deref(), Some("en0"));
        assert_eq!(advice.balanced_champion.as_deref(), Some("en0"));
        report.sample_ms += 1_000;
        report.paths[0].received_bytes += 10_600_000;
        report.paths[1].received_bytes += 40_000_000;
        let advice = controller.advise(&report, 5);
        assert_eq!(advice.download_champion.as_deref(), Some("en7"));
        assert_eq!(advice.download_weights["en7"], 64);
        assert!((15..=20).contains(&advice.download_weights["en0"]));
        // Download-only evidence also moves two-way placement.
        assert_eq!(advice.balanced_champion.as_deref(), Some("en7"));
        assert_eq!(advice.weights["en7"], 64);
        assert!(advice.weights["en0"] < 64);
    }

    #[test]
    fn champion_challenger_matches_asymmetric_capacity_and_guards_the_floor() {
        let mut report = report(Policy::Smart);
        report.paths.truncate(2);
        for path in &mut report.paths {
            path.active_flows = 4;
            path.tcp = Some(TcpReport {
                busy: 4,
                ..TcpReport::default()
            });
        }
        let mut controller = Controller::default();
        controller.advise(&report, 0);
        let mut advice = None;
        for second in 1..=3 {
            report.sample_ms = second * 1_000;
            // Reproduce the measured shape: Wi-Fi ~= 213/67 Mbps and the
            // challenger LAN ~= 29/39 Mbps. Both paths add upload capacity,
            // but LAN earns only a small download allocation.
            report.paths[0].received_bytes += 26_618_750;
            report.paths[0].tcp.as_mut().unwrap().acknowledged += 8_353_750;
            report.paths[1].received_bytes += 3_608_750;
            report.paths[1].tcp.as_mut().unwrap().acknowledged += 4_922_500;
            advice = Some(controller.advise(&report, second));
        }
        let advice = advice.unwrap();
        assert_eq!(advice.download_champion.as_deref(), Some("en0"));
        assert_eq!(advice.upload_champion.as_deref(), Some("en0"));
        assert_eq!(advice.download_weights["en0"], 64);
        assert!((8..=10).contains(&advice.download_weights["en7"]));
        assert!((37..=39).contains(&advice.upload_weights["en7"]));
        assert!(!advice.download_guarded);

        // If using both paths now delivers less than 95% of the champion's
        // recent envelope, new download work contracts to the champion. This
        // does not reset already-established TCP connections.
        report.sample_ms += 1_000;
        report.paths[0].received_bytes += 10_000_000;
        report.paths[1].received_bytes += 5_000_000;
        let guarded = controller.advise(&report, 4);
        assert!(guarded.download_guarded);
        assert_eq!(guarded.download_weights["en0"], 64);
        assert_eq!(guarded.download_weights["en7"], 1);
    }

    #[test]
    fn a_pause_does_not_hand_the_champion_to_the_path_that_moved_bytes_last() {
        // From the 2026-09-09 flow log: LAN (en7) proven at ~300 Mbps, then a
        // 40 s pause, then one 14 MB upload on the hotspot (en0) made en0 the
        // balanced champion and the next three uploads followed it there.
        let mut report = report(Policy::Smart);
        report.paths.truncate(2);
        for p in &mut report.paths {
            p.rtt_ms = None;
            p.tcp = Some(TcpReport::default());
        }
        let mut controller = Controller::default();
        controller.advise(&report, 0);
        for second in 1..=3 {
            report.sample_ms = second * 1_000;
            report.paths[1].received_bytes += 37_000_000;
            report.paths[1].tcp.as_mut().unwrap().acknowledged += 25_000_000;
            report.paths[0].received_bytes += 10_000_000;
            report.paths[0].tcp.as_mut().unwrap().acknowledged += 4_000_000;
            controller.advise(&report, second);
        }
        report.sample_ms = 4_000;
        assert_eq!(
            controller.advise(&report, 4).balanced_champion.as_deref(),
            Some("en7")
        );
        for second in 5..=45 {
            report.sample_ms = second * 1_000;
            controller.advise(&report, second);
        }
        report.sample_ms = 46_000;
        report.paths[0].tcp.as_mut().unwrap().acknowledged += 14_000_000;
        let advice = controller.advise(&report, 46);
        assert_eq!(advice.balanced_champion.as_deref(), Some("en7"));
        assert_eq!(advice.upload_champion.as_deref(), Some("en7"));
        assert!(advice.weights["en7"] > advice.weights["en0"]);
    }

    #[test]
    fn champion_survives_small_bursts_and_light_traffic() {
        // Log evidence 2026-09-09: LAN (en7) proven at ~300 Mbps download,
        // then Cloudflare's upload phase moved to hotspot (en0) briefly. Old
        // brain flipped champion to en0 within 14 s because en0's 9 Mbps last
        // sample beat en7's 5 Mbps last sample. Peak tracking must prevent it.
        let mut report = report(Policy::Smart);
        report.paths.truncate(2);
        for p in &mut report.paths {
            p.tcp = Some(TcpReport::default());
        }
        let mut controller = Controller::default();
        controller.advise(&report, 0);
        // 5 s of full-speed download on en7 proves its capacity.
        for second in 1..=5 {
            report.sample_ms = second * 1_000;
            report.paths[1].received_bytes += 37_000_000;
            report.paths[1].tcp.as_mut().unwrap().acknowledged += 5_000_000;
            controller.advise(&report, second);
        }
        report.sample_ms = 6_000;
        assert_eq!(
            controller.advise(&report, 6).download_champion.as_deref(),
            Some("en7")
        );
        // Two minutes of small mixed traffic: en0 gets a light 9 Mbps upload
        // phase, en7 idles or trickles. Champion must not flip.
        for second in 7..=125 {
            report.sample_ms = second * 1_000;
            report.paths[0].tcp.as_mut().unwrap().acknowledged += 1_100_000;
            report.paths[0].received_bytes += 100_000;
            report.paths[1].received_bytes += 100_000;
            let advice = controller.advise(&report, second);
            assert_eq!(
                advice.download_champion.as_deref(),
                Some("en7"),
                "flipped at t={second}s"
            );
            assert_eq!(advice.balanced_champion.as_deref(), Some("en7"));
        }
    }

    #[test]
    fn evidence_adapts_after_capacity_changes_and_counters_reset() {
        // Peak tracking makes the champion sticky against workload variation.
        // A real capacity change still moves it, but requires either a long
        // idle-decay window or a fresh incarnation. Both are covered here.
        let mut report = report(Policy::Smart);
        let mut controller = Controller::default();
        controller.advise(&report, 0);
        for second in 1..=5 {
            report.sample_ms = second * 1_000;
            report.paths[0].received_bytes += 30_000_000;
            report.paths[1].received_bytes += 10_000_000;
            controller.advise(&report, second);
        }
        report.sample_ms = 6_000;
        assert_eq!(
            controller.advise(&report, 6).download_champion.as_deref(),
            Some("en0")
        );
        // A fresh incarnation on en0 (e.g., adapter re-address, DHCP renewal)
        // clears its history entirely; en7 becomes champion on new evidence.
        report.paths[0].incarnation += 1;
        report.paths[0].received_bytes = 0;
        report.paths[0].tcp = None;
        report.sample_ms = 7_000;
        controller.advise(&report, 7);
        assert_eq!(controller.observations["en0"].download_bps, 0.0);
        assert_eq!(controller.observations["en0"].download_peak_bps, 0.0);
        for second in 8..=15 {
            report.sample_ms = second * 1_000;
            report.paths[1].received_bytes += 10_000_000;
            controller.advise(&report, second);
        }
        report.sample_ms = 16_000;
        assert_eq!(
            controller.advise(&report, 16).download_champion.as_deref(),
            Some("en7")
        );
    }

    #[test]
    fn failed_paths_are_excluded_and_invalid_metrics_are_bounded() {
        let mut report = report(Policy::Smart);
        report.paths[0].healthy = false;
        report.paths[1].jitter_ms = f64::NAN;
        report.paths[1].probe_failure_ratio = f64::INFINITY;
        let advice = advise(&report, 1);
        assert_eq!(advice.weights["en0"], 0);
        assert!(advice.weights.values().all(|v| *v <= 64));
        assert!(advice.realtime_weights["en7"] > 0);
    }

    #[test]
    fn metadata_is_bounded_for_256_adapters_and_v1_is_readable() {
        let mut report = report(Policy::Smart);
        report.paths = (0..256)
            .map(|i| PathReport {
                name: format!("en{i}"),
                sent_bytes: u64::MAX,
                received_bytes: u64::MAX,
                incarnation: u64::MAX,
                active_flows: 1_024,
                rtt_ms: Some(123.123456789),
                jitter_ms: 123.123456789,
                probe_failure_ratio: 0.123456789,
                tcp: Some(TcpReport {
                    acknowledged: u64::MAX,
                    retransmitted: u64::MAX,
                    queued: u64::MAX,
                    busy: 1_024,
                    held: true,
                }),
                ..PathReport::default()
            })
            .collect();
        assert!(serde_json::to_vec(&report).unwrap().len() + 16 < MAX_FRAME);
        let legacy: ClientReport = serde_json::from_str(r#"{"policy":"smart","paths":[{"name":"en0","rtt_ms":20,"healthy":true,"metered":false,"failures":0}]}"#).unwrap();
        assert!(advise(&legacy, 1).weights["en0"] > 0);
    }

    #[tokio::test]
    async fn encrypted_channel_exchanges_advice() -> Result<()> {
        let secret = [7; 32];
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await?;
            serve_connection(stream, secret, Arc::new(AtomicU64::new(0))).await
        });
        let mut client = BrainClient::connect(address, &secret).await?;
        let advice = client.exchange(&report(Policy::Smart)).await?;
        assert_eq!(advice.generation, 1);
        assert_eq!(advice.strategy, STRATEGY);
        drop(client);
        assert!(server.await?.is_err());
        Ok(())
    }

    #[tokio::test]
    async fn wrong_key_cannot_authenticate_brain() -> Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            server_handshake(&mut stream, &[1; 32]).await
        });
        assert!(BrainClient::connect(address, &[2; 32]).await.is_err());
        let _ = server.await?;
        Ok(())
    }

    #[test]
    fn buffered_uploads_and_downloads_cannot_invent_upload_capacity() {
        let mut report = report(Policy::Smart);
        for p in &mut report.paths {
            p.tcp = Some(TcpReport::default());
        }
        let mut controller = Controller::default();
        controller.advise(&report, 0);
        let mut advice = controller.advise(&report, 0);
        for sample in 1..=MIN_CAPACITY_SAMPLES {
            report.sample_ms = u64::from(sample) * 1_000;
            report.paths[0].sent_bytes += 30_000_000;
            report.paths[0].received_bytes += 50_000_000;
            report.paths[0].tcp.as_mut().unwrap().acknowledged += 100_000;
            report.paths[1].tcp.as_mut().unwrap().acknowledged += 30_000_000;
            advice = controller.advise(&report, u64::from(sample));
        }
        assert_eq!(controller.observations["en0"].upload_bps, 800_000.0);
        assert!(advice.upload_weights["en0"] < advice.upload_weights["en7"]);
        report.paths[0].tcp.as_mut().unwrap().held = true;
        report.sample_ms += 1_000;
        let advice = controller.advise(&report, 4);
        assert_eq!(advice.weights["en0"], 0);
        assert!(advice.download_weights["en0"] > 0);
    }
}
