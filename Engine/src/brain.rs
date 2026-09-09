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
    #[serde(default, skip_serializing, rename = "flows", alias = "active_flows")]
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
    incarnation: u64,
}

/// Online feedback controller, not a pretrained AI model. Learns a decaying
/// goodput envelope separately in each direction. Goodput is only an observed
/// lower bound on capacity, not a claim that writes reached the network. The
/// Mac bounds unknown/recovering-path trials and handles congestion locally.
#[derive(Default)]
pub struct Controller {
    observations: BTreeMap<String, Observation>,
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
                // Decay old evidence over 30 seconds. Sparse/idle traffic is
                // not evidence of poor capacity, so it cannot create a cap.
                let decay = (-(elapsed as f64) / 30_000.0).exp();
                let rate = |bytes: u64| bytes as f64 * 8_000.0 / elapsed as f64;
                prior.upload_bps = if p.tcp.is_some() && prior.tcp_observed {
                    let observed = rate(acknowledged - prior.acknowledged);
                    if p.tcp.as_ref().is_some_and(|t| t.held) {
                        observed // old peak must not immediately refill a congested path
                    } else {
                        (prior.upload_bps * decay).max(observed)
                    }
                } else {
                    0.0
                };
                prior.download_bps =
                    (prior.download_bps * decay).max(rate(p.received_bytes - prior.received));
            } else {
                prior.upload_bps = 0.0;
                prior.download_bps = 0.0;
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
        let reference = |upload: bool| {
            let mut rates: Vec<f64> = report
                .paths
                .iter()
                .filter(|p| eligible(p))
                .filter_map(|p| self.observations.get(&p.name))
                .map(|o| if upload { o.upload_bps } else { o.download_bps })
                .filter(|v| *v >= 64_000.0)
                .collect();
            rates.sort_by(f64::total_cmp);
            rates.get(rates.len() / 2).copied().unwrap_or(1_000_000.0)
        };
        let up_reference = reference(true);
        let down_reference = reference(false);
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
            strategy: "delivery-aware-v3".into(),
            cutoff_ms: CUTOFF_MS,
            recovery_ms: RECOVERY_MS,
            relay_fallback: true,
            weights: BTreeMap::new(),
            download_weights: BTreeMap::new(),
            upload_weights: BTreeMap::new(),
            realtime_weights: BTreeMap::new(),
            learned_paths: 0,
            valid_for_ms: 5_000,
        };
        for p in &report.paths {
            let o = &self.observations[&p.name];
            if o.upload_bps >= 64_000.0 || o.download_bps >= 64_000.0 {
                advice.learned_paths += 1;
            }
            let reliability = 1.0 - finite(p.probe_failure_ratio, 0.0).clamp(0.0, 1.0) * 0.8;
            let weight = |rate: f64, reference: f64| {
                if !eligible(p) {
                    return 0;
                }
                let relative = if rate > 0.0 { rate / reference } else { 1.0 };
                (16.0 * relative.clamp(0.0625, 4.0) * reliability)
                    .round()
                    .clamp(1.0, 64.0) as u32
            };
            let up = if p.tcp.as_ref().is_some_and(|t| t.held) {
                0
            } else {
                weight(o.upload_bps, up_reference)
            };
            let down = weight(o.download_bps, down_reference);
            advice.upload_weights.insert(p.name.clone(), up);
            advice.download_weights.insert(p.name.clone(), down);
            advice.weights.insert(p.name.clone(), up.min(down));
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
        assert_eq!(advice.weights["en0"], advice.weights["en7"]);
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
        report.sample_ms = 1_000;
        report.paths[0].received_bytes = 30_000_000;
        report.paths[0].sent_bytes = 1_000_000;
        report.paths[1].received_bytes = 1_000_000;
        report.paths[1].sent_bytes = 30_000_000;
        report.paths[0].tcp.as_mut().unwrap().acknowledged = 1_000_000;
        report.paths[1].tcp.as_mut().unwrap().acknowledged = 30_000_000;
        let advice = controller.advise(&report, 2);
        assert!(advice.download_weights["en0"] > advice.download_weights["en7"]);
        assert!(advice.upload_weights["en7"] > advice.upload_weights["en0"]);
        assert!(advice.weights["en8"] > 0);
        assert_eq!(advice.learned_paths, 2);
        report.paths[0].incarnation += 1;
        report.sample_ms += 1_000;
        assert_eq!(controller.advise(&report, 3).learned_paths, 1);
    }

    #[test]
    fn evidence_adapts_after_capacity_changes_and_counters_reset() {
        let mut report = report(Policy::Smart);
        let mut controller = Controller::default();
        controller.advise(&report, 0);
        for second in 1..=180 {
            report.sample_ms = second * 1_000;
            report.paths[0].received_bytes += if second <= 5 { 30_000_000 } else { 100_000 };
            report.paths[1].received_bytes += 10_000_000;
            controller.advise(&report, second);
        }
        let advice = controller.advise(
            &ClientReport {
                sample_ms: 181_000,
                ..report.clone()
            },
            181,
        );
        assert!(advice.download_weights["en7"] > advice.download_weights["en0"]);
        report.paths[0].received_bytes = 0;
        report.sample_ms = 182_000;
        controller.advise(&report, 182);
        assert_eq!(controller.observations["en0"].download_bps, 0.0);
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
        assert_eq!(advice.strategy, "delivery-aware-v3");
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
        report.sample_ms = 1_000;
        report.paths[0].sent_bytes = 30_000_000;
        report.paths[0].received_bytes = 50_000_000;
        report.paths[0].tcp.as_mut().unwrap().acknowledged = 100_000;
        report.paths[1].tcp.as_mut().unwrap().acknowledged = 30_000_000;
        let advice = controller.advise(&report, 1);
        assert_eq!(controller.observations["en0"].upload_bps, 800_000.0);
        assert!(advice.weights["en0"] < advice.weights["en7"]);
        report.paths[0].tcp.as_mut().unwrap().held = true;
        report.sample_ms += 1_000;
        let advice = controller.advise(&report, 2);
        assert_eq!(advice.weights["en0"], 0);
        assert!(advice.download_weights["en0"] > 0);
    }
}
