use std::{
    collections::HashMap,
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, ensure};
use clap::{Args, Parser, Subcommand};
use serde::Serialize;
use tokio::{net::UdpSocket, time};
use tun_rs::DeviceBuilder;
use verz_link_lab::{bind_interface_socket, load_secret, tunnel::*};

#[derive(Parser)]
#[command(about = "Real IPv4 tunnel between macOS/Linux network interfaces")]
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
    /// Permit authenticated client IPv4 internet traffic (requires server NAT).
    #[arg(long)]
    internet: bool,
    #[arg(long, default_value = "0.0.0.0:39001")]
    listen: SocketAddr,
    #[arg(long)]
    secret_file: PathBuf,
    #[arg(long, default_value = "verz0")]
    tun_name: String,
}

#[derive(Args)]
struct Client {
    /// Carry internet IPv4 packets; the native app manages routes and DNS.
    #[arg(long)]
    internet: bool,
    #[arg(long, default_value = "69.164.213.57:39001")]
    relay: SocketAddr,
    #[arg(long, default_value = "en0")]
    interface: String,
    #[arg(long)]
    secret_file: PathBuf,
    #[arg(long, default_value_t = 300)]
    duration_seconds: u64,
    /// Run OS ping, real HTTP download/upload and SHA-256 verification, then exit.
    #[arg(long)]
    self_test: bool,
    /// A local file to upload during --self-test (never uploaded unless specified).
    #[arg(long, requires = "self_test")]
    upload_file: Option<PathBuf>,
}

#[derive(Default, Serialize)]
struct Stats {
    ip_packets_sent: u64,
    ip_packets_received: u64,
    ip_bytes_sent: u64,
    ip_bytes_received: u64,
    rejected_datagrams: u64,
    send_errors: u64,
}

struct Peer {
    assigned_ip: [u8; 4],
    transport: Transport,
    address: SocketAddr,
    hello: Vec<u8>,
    welcome: Vec<u8>,
    last_seen: Instant,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    match Cli::parse().command {
        Mode::Server(args) => server(args).await,
        Mode::Client(args) => client(args).await,
    }
}

async fn stop_signal() {
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("install SIGTERM handler");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {},
        _ = terminate.recv() => {},
    }
}

async fn server(args: Server) -> Result<()> {
    ensure!(cfg!(target_os = "linux"), "server currently requires Linux");
    let secret = load_secret(&args.secret_file)?;
    let tun = DeviceBuilder::new()
        .name(&args.tun_name)
        .ipv4(Ipv4Addr::from(SERVER_IP), 24, None)
        .mtu(MTU as u16)
        .build_async()
        .context("create Linux TUN interface")?;
    let socket = UdpSocket::bind(args.listen).await?;
    println!(
        "TUNNEL SERVER ready: {} / 10.77.0.1: {}",
        tun.name()?,
        args.listen
    );
    let mut peers: HashMap<[u8; 16], Peer> = HashMap::new();
    let mut wire = [0; MAX_WIRE + 1];
    let mut ip = [0; 65536];
    let mut stats = Stats::default();
    let mut report = time::interval(Duration::from_secs(5));
    let stop = stop_signal();
    tokio::pin!(stop);
    loop {
        tokio::select! {
            _ = &mut stop => break,
            _ = report.tick() => {
                peers.retain(|_, p| p.last_seen.elapsed() <= Duration::from_secs(15));
                println!("{}", serde_json::to_string(&stats)?);
            }
            received = socket.recv_from(&mut wire) => {
                let (len, address) = received?;
                let packet = &wire[..len];
                let Ok(header) = Header::parse(packet) else { stats.rejected_datagrams += 1; continue; };
                if header.kind == HELLO {
                    if let Some(p) = peers.get(&header.session) {
                        // Repeat the exact welcome if UDP lost the handshake response.
                        if p.address == address && p.hello == packet {
                            let _ = socket.send_to(&p.welcome, address).await;
                        }
                        continue;
                    }
                    let Some(assigned_ip) = allocate_client_ip(peers.values().map(|p| p.assigned_ip)) else { continue; };
                    let mut noise = handshake(&secret, &header.session, false)?;
                    let mut plain = [0; MAX_WIRE];
                    if noise.read_message(&packet[HEADER..], &mut plain).is_err() {
                        stats.rejected_datagrams += 1;
                        continue;
                    }
                    let mut response = [0; MAX_WIRE];
                    // The address lease is authenticated inside the Noise welcome.
                    let length = noise.write_message(&assigned_ip, &mut response)?;
                    let welcome = Header { kind: WELCOME, session: header.session, counter: 0 }
                        .wrap(&response[..length]);
                    let transport = Transport::new(header.session, noise)?;
                    socket.send_to(&welcome, address).await?;
                    peers.insert(header.session, Peer { assigned_ip, transport, address, hello: packet.to_vec(), welcome, last_seen: Instant::now() });
                    println!("authenticated handshake from {address}, assigned {}", Ipv4Addr::from(assigned_ip));
                    continue;
                }
                let Some(p) = peers.get_mut(&header.session) else { continue; };
                if p.address != address { stats.rejected_datagrams += 1; continue; }
                let Ok((kind, payload)) = p.transport.open(packet) else { stats.rejected_datagrams += 1; continue; };
                p.last_seen = Instant::now();
                match kind {
                    IP => {
                        // Enforce the authenticated lease; clients cannot impersonate each other.
                        if validate_ipv4(&payload, Some(p.assigned_ip), if args.internet { None } else { Some(SERVER_IP) }).is_err()
                            || (args.internet && !internet_destination_allowed(&payload)) {
                            stats.rejected_datagrams += 1; continue;
                        }
                        tun.send(&payload).await?;
                        stats.ip_packets_received += 1;
                        stats.ip_bytes_received += payload.len() as u64;
                    }
                    PING => { let response = p.transport.seal(PONG, &[])?; let _ = socket.send_to(&response, address).await; }
                    CLOSE => { peers.remove(&header.session); println!("client disconnected cleanly"); }
                    _ => {},
                }
            }
            received = tun.recv(&mut ip) => {
                let len = received?;
                if validate_ipv4(&ip[..len], if args.internet { None } else { Some(SERVER_IP) }, None).is_err() { continue; }
                if let Some(p) = peers.values_mut().find(|p| ip[16..20] == p.assigned_ip) {
                    let packet = p.transport.seal(IP, &ip[..len])?;
                    if socket.send_to(&packet, p.address).await.is_ok() {
                        stats.ip_packets_sent += 1;
                        stats.ip_bytes_sent += len as u64;
                    } else { stats.send_errors += 1; }
                }
            }
        }
    }
    println!("{}", serde_json::to_string(&stats)?);
    Ok(())
}

async fn establish(socket: &UdpSocket, secret: &[u8; 32]) -> Result<(Transport, [u8; 4])> {
    let session = rand::random();
    let mut noise = handshake(secret, &session, true)?;
    let mut buf = [0; MAX_WIRE + 1];
    let len = noise.write_message(&[], &mut buf)?;
    let hello = Header {
        kind: HELLO,
        session,
        counter: 0,
    }
    .wrap(&buf[..len]);
    let deadline = time::Instant::now() + Duration::from_secs(10);
    loop {
        ensure!(
            time::Instant::now() < deadline,
            "encrypted handshake timed out"
        );
        socket.send(&hello).await?;
        if let Ok(Ok(length)) =
            time::timeout(Duration::from_millis(500), socket.recv(&mut buf)).await
        {
            let Ok(header) = Header::parse(&buf[..length]) else {
                continue;
            };
            if header.kind == WELCOME && header.session == session {
                let mut configuration = [0; MAX_WIRE];
                let size = noise
                    .read_message(&buf[HEADER..length], &mut configuration)
                    .context("authenticate server handshake")?;
                ensure!(
                    size == 4
                        && configuration[..3] == [10, 77, 0]
                        && (2..=254).contains(&configuration[3]),
                    "invalid authenticated client assignment"
                );
                return Ok((
                    Transport::new(session, noise)?,
                    configuration[..4].try_into()?,
                ));
            }
        }
    }
}

async fn client(args: Client) -> Result<()> {
    ensure!(
        args.duration_seconds <= 86400,
        "duration must be 0 (unlimited) to 86400 seconds"
    );
    let secret = load_secret(&args.secret_file)?;
    let socket = bind_interface_socket(&args.interface, args.relay)?;
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "the tunnel requires administrator authorization"
    );
    let (mut transport, assigned_ip) = establish(&socket, &secret).await?;
    let tun = DeviceBuilder::new()
        .ipv4(
            Ipv4Addr::from(assigned_ip),
            32,
            Some(Ipv4Addr::from(SERVER_IP)),
        )
        .mtu(MTU as u16)
        .build_async()
        .context("create tunnel interface; macOS requires administrator authentication (sudo)")?;
    let name = tun.name()?;
    println!(
        "TUNNEL CONNECTED: {name} {} -> 10.77.0.1 over {} -> {}",
        Ipv4Addr::from(assigned_ip),
        args.interface,
        args.relay
    );
    println!("Encryption: Noise NNpsk0 / X25519 / ChaCha20-Poly1305; MTU {MTU}");
    println!("Real test: ping 10.77.0.1; curl --noproxy '*' http://10.77.0.1:8080/health");
    let mut wire = [0; MAX_WIRE + 1];
    let mut ip = [0; 65536];
    let mut stats = Stats::default();
    let mut keepalive = time::interval(Duration::from_secs(1));
    let mut last_response = Instant::now();
    let finish = async {
        if args.duration_seconds == 0 {
            std::future::pending::<()>().await;
        } else {
            time::sleep(Duration::from_secs(args.duration_seconds)).await;
        }
    };
    tokio::pin!(finish);
    let stop = stop_signal();
    tokio::pin!(stop);
    let self_test = async {
        if args.self_test {
            run_self_test(args.upload_file.as_deref()).await
        } else {
            std::future::pending::<Result<()>>().await
        }
    };
    tokio::pin!(self_test);
    let outcome = loop {
        tokio::select! {
            _ = &mut stop => break Ok(()),
            _ = &mut finish => {
                if args.self_test { break Err(anyhow::anyhow!("self-test exceeded duration")); }
                break Ok(());
            },
            result = &mut self_test => break result,
            _ = keepalive.tick() => {
                if last_response.elapsed() > Duration::from_secs(10) { break Err(anyhow::anyhow!("relay stopped responding")); }
                let packet = transport.seal(PING, &[])?;
                let _ = socket.send(&packet).await;
            }
            received = socket.recv(&mut wire) => {
                let len = received?;
                let Ok((kind, payload)) = transport.open(&wire[..len]) else { stats.rejected_datagrams += 1; continue; };
                last_response = Instant::now();
                if kind == IP {
                    if validate_ipv4(&payload, if args.internet { None } else { Some(SERVER_IP) }, Some(assigned_ip)).is_err() { stats.rejected_datagrams += 1; continue; }
                    tun.send(&payload).await?;
                    stats.ip_packets_received += 1;
                    stats.ip_bytes_received += payload.len() as u64;
                }
            }
            received = tun.recv(&mut ip) => {
                let len = received?;
                if validate_ipv4(&ip[..len], Some(assigned_ip), if args.internet { None } else { Some(SERVER_IP) }).is_err() { continue; }
                let packet = transport.seal(IP, &ip[..len])?;
                if socket.send(&packet).await.is_ok() {
                    stats.ip_packets_sent += 1;
                    stats.ip_bytes_sent += len as u64;
                } else { stats.send_errors += 1; }
            }
        }
    };
    let goodbye = transport.seal(CLOSE, &[])?;
    let _ = socket.send(&goodbye).await;
    drop(tun); // Kernel removes this utun and its connected route when the FD closes.
    println!("TUNNEL CLOSED; {}", serde_json::to_string(&stats)?);
    outcome
}

async fn run_command(program: &str, args: &[&str]) -> Result<Vec<u8>> {
    let output = tokio::process::Command::new(program)
        .args(args)
        .kill_on_drop(true)
        .output()
        .await
        .with_context(|| format!("execute {program}"))?;
    ensure!(
        output.status.success(),
        "{program} failed: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(output.stdout)
}

async fn run_self_test(upload: Option<&std::path::Path>) -> Result<()> {
    use sha2::{Digest, Sha256};
    time::sleep(Duration::from_millis(300)).await;
    let ping = if cfg!(target_os = "macos") {
        "/sbin/ping"
    } else {
        "ping"
    };
    let output = run_command(ping, &["-c", "10", "10.77.0.1"]).await?;
    println!("REAL ICMP TEST:\n{}", String::from_utf8_lossy(&output));
    let health = run_command(
        "/usr/bin/curl",
        &[
            "--fail",
            "--silent",
            "--show-error",
            "--noproxy",
            "*",
            "--max-time",
            "15",
            "http://10.77.0.1:8080/health",
        ],
    )
    .await?;
    ensure!(
        health == b"VERZ real TCP over encrypted IP tunnel\n",
        "unexpected server response"
    );
    println!(
        "REAL HTTP TEST: {}",
        String::from_utf8_lossy(&health).trim()
    );
    let started = Instant::now();
    let download = run_command(
        "/usr/bin/curl",
        &[
            "--fail",
            "--silent",
            "--show-error",
            "--noproxy",
            "*",
            "--max-time",
            "60",
            "http://10.77.0.1:8080/download",
        ],
    )
    .await?;
    let elapsed = started.elapsed().as_secs_f64();
    let expected = run_command(
        "/usr/bin/curl",
        &[
            "--fail",
            "--silent",
            "--show-error",
            "--noproxy",
            "*",
            "--max-time",
            "15",
            "http://10.77.0.1:8080/sha256",
        ],
    )
    .await?;
    let digest = hex::encode(Sha256::digest(&download));
    ensure!(
        digest == String::from_utf8_lossy(&expected).trim(),
        "download checksum mismatch"
    );
    println!(
        "REAL DOWNLOAD: {} bytes / {:.3} seconds / {:.3} Mbps / SHA256 {} MATCH",
        download.len(),
        elapsed,
        download.len() as f64 * 8.0 / elapsed / 1e6,
        digest
    );
    if let Some(path) = upload {
        let content = std::fs::read(path)?;
        ensure!(content.len() <= 16 * 1024 * 1024, "upload limit is 16 MiB");
        let expected = hex::encode(Sha256::digest(&content));
        let file_arg = format!("@{}", path.display());
        let started = Instant::now();
        let response = run_command(
            "/usr/bin/curl",
            &[
                "--fail",
                "--silent",
                "--show-error",
                "--noproxy",
                "*",
                "--max-time",
                "60",
                "--data-binary",
                &file_arg,
                "http://10.77.0.1:8080/upload",
            ],
        )
        .await?;
        ensure!(
            String::from_utf8_lossy(&response).trim() == expected,
            "upload checksum mismatch"
        );
        let elapsed = started.elapsed().as_secs_f64();
        println!(
            "REAL UPLOAD: {} bytes / {:.3} seconds / {:.3} Mbps / SHA256 {} MATCH",
            content.len(),
            elapsed,
            content.len() as f64 * 8.0 / elapsed / 1e6,
            expected
        );
    }
    println!("REAL MAC-TO-SERVER TEST PASSED");
    Ok(())
}
