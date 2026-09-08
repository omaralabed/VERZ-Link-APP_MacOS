use std::{net::SocketAddr, path::PathBuf, time::Duration};

use anyhow::{Context, Result, bail};
use clap::Parser;
use serde::Serialize;
use tokio::{net::UdpSocket, time};
use verz_link_lab::{
    Channel, DEFAULT_PAYLOAD, Kind, Role, SessionId, bind_interface_socket, load_secret,
    monotonic_micros, synthetic_payload,
};

#[derive(Parser)]
#[command(about = "Verify one authenticated VERZ Link lab path")]
struct Args {
    #[arg(long)]
    relay: SocketAddr,
    #[arg(long)]
    interface: String,
    #[arg(long)]
    secret_file: PathBuf,
    #[arg(long, default_value_t = 10)]
    count: u64,
    #[arg(long, default_value_t = 200)]
    data_packets: u64,
}

#[derive(Serialize)]
struct Report {
    status: &'static str,
    interface: String,
    source: SocketAddr,
    probe_sent: u64,
    probe_received: u64,
    probe_loss_percent: f64,
    probe_minimum_rtt_ms: Option<f64>,
    probe_average_rtt_ms: Option<f64>,
    probe_maximum_rtt_ms: Option<f64>,
    data_sent: u64,
    data_acknowledged: u64,
    data_loss_percent: f64,
    encrypted_payload_bytes: u64,
    data_minimum_rtt_ms: Option<f64>,
    data_average_rtt_ms: Option<f64>,
    data_maximum_rtt_ms: Option<f64>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    if !(1..=100).contains(&args.count) {
        bail!("count must be between 1 and 100");
    }
    if !(1..=10_000).contains(&args.data_packets) {
        bail!("data-packets must be between 1 and 10000");
    }

    let secret = load_secret(&args.secret_file)?;
    let socket = bind_interface_socket(&args.interface, args.relay)?;
    let source = socket.local_addr()?;
    let session = SessionId::random();
    let mut channel = Channel::new(&secret, session, 0, Role::Client)?;
    let epoch = std::time::Instant::now();
    let mut buffer = [0_u8; 2_048];
    let mut probe_samples = Vec::new();

    for sequence in 0..args.count {
        let sent_at = monotonic_micros(epoch);
        let packet = channel.seal(Kind::Probe, 0, sequence, sent_at, &[])?;
        socket
            .send(&packet)
            .await
            .context("send authenticated probe")?;
        if let Some(sample) = receive_matching(
            &socket,
            &mut channel,
            &mut buffer,
            Kind::Pong,
            sequence,
            epoch,
        )
        .await?
        {
            probe_samples.push(sample);
        }
        time::sleep(Duration::from_millis(20)).await;
    }

    let mut data_samples = Vec::new();
    for sequence in 0..args.data_packets {
        let sent_at = monotonic_micros(epoch);
        let payload = synthetic_payload(sequence, DEFAULT_PAYLOAD);
        let packet = channel.seal(Kind::Data, 0, sequence, sent_at, &payload)?;
        socket
            .send(&packet)
            .await
            .context("send encrypted data packet")?;
        if let Some(sample) = receive_matching(
            &socket,
            &mut channel,
            &mut buffer,
            Kind::Ack,
            sequence,
            epoch,
        )
        .await?
        {
            data_samples.push(sample);
        }
    }

    let probe_received = probe_samples.len() as u64;
    let data_acknowledged = data_samples.len() as u64;
    let (probe_minimum, probe_average, probe_maximum) = distribution(&probe_samples);
    let (data_minimum, data_average, data_maximum) = distribution(&data_samples);
    let passed = probe_received == args.count && data_acknowledged == args.data_packets;
    let report = Report {
        status: if passed { "pass" } else { "fail" },
        interface: args.interface,
        source,
        probe_sent: args.count,
        probe_received,
        probe_loss_percent: (args.count - probe_received) as f64 * 100.0 / args.count as f64,
        probe_minimum_rtt_ms: probe_minimum,
        probe_average_rtt_ms: probe_average,
        probe_maximum_rtt_ms: probe_maximum,
        data_sent: args.data_packets,
        data_acknowledged,
        data_loss_percent: (args.data_packets - data_acknowledged) as f64 * 100.0
            / args.data_packets as f64,
        encrypted_payload_bytes: args.data_packets * DEFAULT_PAYLOAD as u64,
        data_minimum_rtt_ms: data_minimum,
        data_average_rtt_ms: data_average,
        data_maximum_rtt_ms: data_maximum,
    };
    println!("{}", serde_json::to_string_pretty(&report)?);
    if !passed {
        bail!(
            "received {probe_received}/{} probes and {data_acknowledged}/{} data acknowledgements",
            args.count,
            args.data_packets
        );
    }
    Ok(())
}

async fn receive_matching(
    socket: &UdpSocket,
    channel: &mut Channel,
    buffer: &mut [u8],
    expected_kind: Kind,
    expected_sequence: u64,
    epoch: std::time::Instant,
) -> Result<Option<f64>> {
    let deadline = time::Instant::now() + Duration::from_secs(1);
    loop {
        let Some(remaining) = deadline.checked_duration_since(time::Instant::now()) else {
            return Ok(None);
        };
        let length = match time::timeout(remaining, socket.recv(buffer)).await {
            Ok(value) => value.context("receive encrypted response")?,
            Err(_) => return Ok(None),
        };
        let message = channel
            .open(&buffer[..length])
            .context("authenticate encrypted response")?;
        if message.kind == expected_kind && message.sequence == expected_sequence {
            let elapsed = epoch.elapsed().as_secs_f64() * 1_000.0;
            let origin = message.echo_micros as f64 / 1_000.0;
            return Ok(Some((elapsed - origin).max(0.0)));
        }
    }
}

fn distribution(samples: &[f64]) -> (Option<f64>, Option<f64>, Option<f64>) {
    let minimum = samples.iter().copied().reduce(f64::min);
    let maximum = samples.iter().copied().reduce(f64::max);
    let average = (!samples.is_empty()).then(|| samples.iter().sum::<f64>() / samples.len() as f64);
    (minimum, average, maximum)
}
