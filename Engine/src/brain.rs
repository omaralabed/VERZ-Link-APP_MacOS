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

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PathReport {
    pub name: String,
    pub rtt_ms: Option<f64>,
    pub healthy: bool,
    pub metered: bool,
    pub failures: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ClientReport {
    pub policy: Policy,
    pub paths: Vec<PathReport>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BrainAdvice {
    pub generation: u64,
    pub strategy: String,
    pub cutoff_ms: f64,
    pub recovery_ms: f64,
    pub relay_fallback: bool,
    pub weights: BTreeMap<String, u32>,
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
    let mut weights = BTreeMap::new();
    let healthy: Vec<_> = report.paths.iter().filter(|path| path.healthy).collect();
    let has_unmetered = healthy.iter().any(|path| !path.metered);
    let has_fast = healthy
        .iter()
        .any(|path| path.rtt_ms.is_some_and(|rtt| rtt < CUTOFF_MS));
    let best_slow = (!has_fast)
        .then(|| {
            healthy
                .iter()
                .filter_map(|path| path.rtt_ms)
                .min_by(f64::total_cmp)
        })
        .flatten();

    for path in &report.paths {
        let excluded = !path.healthy
            || (report.policy == Policy::DataSaver && path.metered && has_unmetered)
            || (has_fast && path.rtt_ms.is_some_and(|rtt| rtt >= CUTOFF_MS))
            || best_slow.is_some_and(|best| path.rtt_ms.is_some_and(|rtt| rtt > best));
        let weight = if excluded {
            0
        } else if report.policy == Policy::Continuity {
            1
        } else {
            let rtt = path.rtt_ms.unwrap_or(25.0).clamp(1.0, CUTOFF_MS);
            ((CUTOFF_MS / rtt).round() as u32).clamp(1, 8)
        };
        weights.insert(path.name.clone(), weight);
    }
    BrainAdvice {
        generation,
        strategy: "adaptive-weighted-flow-v1".into(),
        cutoff_ms: CUTOFF_MS,
        recovery_ms: RECOVERY_MS,
        relay_fallback: true,
        weights,
    }
}

async fn serve_connection(
    mut stream: TcpStream,
    secret: [u8; 32],
    generations: Arc<AtomicU64>,
) -> Result<()> {
    stream.set_nodelay(true)?;
    let mut noise = server_handshake(&mut stream, &secret).await?;
    loop {
        let encrypted = read_frame(&mut stream).await?;
        let mut plain = vec![0; encrypted.len()];
        let size = noise.read_message(&encrypted, &mut plain)?;
        let report: ClientReport = serde_json::from_slice(&plain[..size])?;
        ensure!(report.paths.len() <= 256, "too many reported paths");
        let generation = generations.fetch_add(1, Ordering::Relaxed) + 1;
        let advice = advise(&report, generation);
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
            paths: vec![
                PathReport {
                    name: "en0".into(),
                    rtt_ms: Some(20.0),
                    healthy: true,
                    metered: false,
                    failures: 0,
                },
                PathReport {
                    name: "en7".into(),
                    rtt_ms: Some(40.0),
                    healthy: true,
                    metered: false,
                    failures: 0,
                },
                PathReport {
                    name: "en8".into(),
                    rtt_ms: Some(80.0),
                    healthy: true,
                    metered: true,
                    failures: 0,
                },
            ],
        }
    }

    #[test]
    fn advice_weights_fast_paths_and_excludes_slow_path() {
        let advice = advise(&report(Policy::Performance), 9);
        assert!(advice.weights["en0"] > advice.weights["en7"]);
        assert_eq!(advice.weights["en8"], 0);
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
    fn all_slow_uses_only_lowest_rtt() {
        let mut report = report(Policy::Smart);
        report.paths[0].rtt_ms = Some(100.0);
        report.paths[1].rtt_ms = Some(90.0);
        report.paths[2].rtt_ms = Some(110.0);
        let advice = advise(&report, 1);
        assert_eq!(advice.weights["en7"], 1);
        assert_eq!(advice.weights["en0"], 0);
        assert_eq!(advice.weights["en8"], 0);
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
        assert_eq!(advice.strategy, "adaptive-weighted-flow-v1");
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
}
