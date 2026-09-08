//! Non-privileged integration check against the real relay IP stack. Injects
//! transport loss without changing the Mac's network settings. This is not a
//! substitute for the V2 physical-WAN/TCP/application acceptance matrix.
use anyhow::{Result, ensure};
use clap::Parser;
use serde_json::json;
use std::{
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{net::UdpSocket, sync::mpsc, time};
use verz_link_lab::{
    bind_interface_socket,
    bond::{Frame, Kind, Policy, Scheduler, handshake},
    load_secret,
    tunnel::{HEADER, HELLO, Header, IP, MAX_WIRE, Transport, WELCOME, validate_ipv4},
};

#[derive(Parser)]
struct Args {
    /// Protocol-only emulation; does not verify independent physical WANs.
    #[arg(long)]
    allow_shared_interface: bool,
    #[arg(long)]
    secret_file: PathBuf,
    #[arg(long, default_value = "69.164.213.57:39002")]
    relay: SocketAddr,
    #[arg(long, num_args = 2.., required = true)]
    interface: Vec<String>,
}
fn clock(epoch: Instant) -> u64 {
    epoch.elapsed().as_millis() as u64
}
fn checksum(bytes: &[u8]) -> u16 {
    let mut sum: u32 = bytes
        .chunks(2)
        .map(|b| u32::from(b[0]) * 256 + u32::from(*b.get(1).unwrap_or(&0)))
        .sum();
    while sum >> 16 != 0 {
        sum = (sum & 65535) + (sum >> 16);
    }
    !(sum as u16)
}
fn echo(source: [u8; 4], sequence: u16) -> Vec<u8> {
    let mut ip = vec![0; 36];
    ip[0] = 0x45;
    ip[3] = 36;
    ip[8] = 64;
    ip[9] = 1;
    ip[12..16].copy_from_slice(&source);
    ip[16..20].copy_from_slice(&[10, 78, 0, 1]);
    let sum = checksum(&ip[..20]);
    ip[10..12].copy_from_slice(&sum.to_be_bytes());
    ip[20] = 8;
    ip[24] = 0x56;
    ip[25] = 0x5a;
    ip[26..28].copy_from_slice(&sequence.to_be_bytes());
    ip[28..].copy_from_slice(b"VERZTEST");
    let sum = checksum(&ip[20..]);
    ip[22..24].copy_from_slice(&sum.to_be_bytes());
    ip
}
fn send(
    frames: Vec<Frame>,
    transport: &mut Transport,
    sockets: &[Arc<UdpSocket>],
    cut: Option<usize>,
) -> Result<()> {
    for frame in frames {
        let index = usize::from(frame.path);
        if cut == Some(index) {
            continue;
        }
        let packet = transport.seal(IP, &frame.encode())?;
        let _ = sockets[index].try_send(&packet);
    }
    Ok(())
}
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let args = Args::parse();
    let distinct = args
        .interface
        .iter()
        .collect::<std::collections::BTreeSet<_>>()
        .len();
    ensure!(
        args.allow_shared_interface || distinct == args.interface.len(),
        "provide distinct physical interfaces, or explicitly request shared-interface protocol emulation"
    );
    let (tx, mut rx) = mpsc::channel(1024);
    let mut sockets = Vec::new();
    let mut readers = Vec::new();
    for (index, name) in args.interface.iter().enumerate() {
        let socket = Arc::new(bind_interface_socket(name, args.relay)?);
        let input = socket.clone();
        let sender = tx.clone();
        readers.push(tokio::spawn(async move {
            let mut packet = [0; MAX_WIRE + 1];
            while let Ok(len) = input.recv(&mut packet).await {
                if sender.send((index, packet[..len].to_vec())).await.is_err() {
                    break;
                }
            }
        }));
        sockets.push(socket);
    }
    let session = rand::random();
    let mut noise = handshake(&load_secret(&args.secret_file)?, &session, true)?;
    let mut buffer = [0; MAX_WIRE];
    let len = noise.write_message(&[], &mut buffer)?;
    let hello = Header {
        kind: HELLO,
        session,
        counter: 0,
    }
    .wrap(&buffer[..len]);
    let deadline = time::Instant::now() + Duration::from_secs(10);
    let assigned = loop {
        ensure!(time::Instant::now() < deadline, "handshake timed out");
        for socket in &sockets {
            let _ = socket.try_send(&hello);
        }
        if let Ok(Some((_, packet))) = time::timeout(Duration::from_millis(250), rx.recv()).await {
            let Ok(header) = Header::parse(&packet) else {
                continue;
            };
            if header.kind == WELCOME && header.session == session {
                let len = noise.read_message(&packet[HEADER..], &mut buffer)?;
                ensure!(len == 4 && buffer[..3] == [10, 78, 0], "bad assignment");
                break <[u8; 4]>::try_from(&buffer[..4])?;
            }
        }
    };
    let mut transport = Transport::new(session, noise)?;
    let mut scheduler = Scheduler::new(
        args.interface
            .iter()
            .map(|name| (name.clone(), false))
            .collect(),
        Policy::Smart,
    )?;
    let epoch = Instant::now();
    let mut tick = time::interval(Duration::from_millis(2));
    tick.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
    let mut stream = time::interval(Duration::from_millis(10));
    stream.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
    let mut join = time::interval(Duration::from_millis(500));
    let mut sequence = 0_u16;
    let mut replies = std::collections::BTreeSet::new();
    let mut last_reply = None;
    let mut max_gap = 0;
    let mut failure_to_reply = None;
    let mut cut_path = None;
    let mut first_cut = None;
    let mut saw_all_healthy = false;
    while clock(epoch) < 6000 {
        let moment = clock(epoch);
        if moment >= 2000 && cut_path.is_none() {
            cut_path = scheduler
                .paths
                .iter()
                .max_by_key(|path| path.sent_bytes)
                .map(|path| usize::from(path.id));
            first_cut = Some(moment);
        }
        let cut = if (2000..3000).contains(&moment) {
            cut_path
        } else {
            None
        };
        tokio::select! {
            _ = tick.tick() => {
                let frames = scheduler.tick(clock(epoch));
                send(frames, &mut transport, &sockets, cut)?;
                if scheduler.paths.iter().all(|path| path.ready(clock(epoch))) { saw_all_healthy = true; }
            }
            _ = join.tick() => {
                let frames = scheduler.paths.iter().map(|path| Frame::control(Kind::Join, path.id, 0, clock(epoch))).collect();
                send(frames, &mut transport, &sockets, cut)?;
            }
            _ = stream.tick() => {
                if clock(epoch) >= 250 && clock(epoch) < 5500 { scheduler.enqueue(echo(assigned, sequence)); sequence += 1; }
            }
            Some((index, packet)) = rx.recv() => {
                if cut == Some(index) { continue; }
                let Ok((kind, bytes)) = transport.open(&packet) else { continue; };
                if kind != IP { continue; }
                let frame = Frame::decode(&bytes)?;
                ensure!(usize::from(frame.path) == index, "cross-path response");
                if frame.kind == Kind::Data { validate_ipv4(&frame.body, Some([10,78,0,1]), Some(assigned))?; }
                let (delivered, responses) = scheduler.receive(&frame, clock(epoch));
                if let Some(ip) = delivered {
                    ensure!(ip.len() == 36 && ip[20] == 0 && ip[24..26] == [0x56,0x5a] && &ip[28..] == b"VERZTEST", "invalid kernel ICMP response");
                    replies.insert(u16::from_be_bytes([ip[26], ip[27]]));
                    let moment = clock(epoch);
                    if let Some(last) = last_reply { max_gap = max_gap.max(moment - last); }
                    if let Some(cut_at) = first_cut && failure_to_reply.is_none() && moment >= cut_at { failure_to_reply = Some(moment - cut_at); }
                    last_reply = Some(moment);
                }
                send(responses, &mut transport, &sockets, cut)?;
            }
        }
    }
    send(
        scheduler
            .paths
            .iter()
            .map(|path| Frame::control(Kind::Close, path.id, 0, clock(epoch)))
            .collect(),
        &mut transport,
        &sockets,
        None,
    )?;
    for reader in readers {
        reader.abort();
    }
    let report = json!({"check":"real relay-kernel ICMP over multiple UDP subflows; controlled transport loss",
        "distinct_physical_interfaces":distinct, "shared_interface_emulation":args.allow_shared_interface,
        "assigned_ip":std::net::Ipv4Addr::from(assigned).to_string(), "all_paths_warmed":saw_all_healthy,
        "cut_interface":cut_path.map(|index| &args.interface[index]), "cut_duration_ms":1000,
        "requests":sequence, "unique_replies":replies.len(), "maximum_reply_gap_ms":max_gap,
        "cut_to_next_reply_ms":failure_to_reply, "paths":scheduler.paths, "counters":scheduler.counters,
        "physical_WAN_and_TCP_acceptance":"not measured by this check"});
    println!("{}", serde_json::to_string_pretty(&report)?);
    ensure!(
        saw_all_healthy && replies.len() == usize::from(sequence) && max_gap <= 100,
        "multipath ICMP integration check failed"
    );
    Ok(())
}
