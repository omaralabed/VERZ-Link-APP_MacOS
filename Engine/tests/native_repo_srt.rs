//! Opt-in real SRT through the imported repo UDP lane and encrypted IP fragments.
//! No TUN, physical adapters, cloud services or user OBS/VLC state are changed.
use anyhow::{Context, Result, ensure};
use std::{collections::VecDeque, net::SocketAddr, process::Stdio, time::Instant};
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    net::UdpSocket,
    process::Command,
    time::{self, Duration},
};
use verz_link_lab::{
    bond::{self, Frame, Kind, Policy, Scheduler},
    tunnel::{IP, Transport},
};

use verz_link_core::{ACK, NACK, Packet, transport::WanWriter};
use verz_link_lab::udp_lane::{self, UdpLane};

struct Capture(Vec<Frame>);
impl WanWriter for Capture {
    fn carrier(&self, _id: u8) -> bool {
        true
    }
    fn send(&mut self, id: u8, wire: &[u8]) -> std::io::Result<()> {
        self.0.push(Frame {
            kind: Kind::Udp,
            path: id,
            id: 0,
            stamp: 0,
            body: wire.to_vec(),
        });
        Ok(())
    }
}
struct Side {
    scheduler: Scheduler,
    transport: Transport,
    udp: UdpLane,
    outbound: Vec<Frame>,
    fragment_id: u16,
    reassembly: std::collections::HashMap<u16, (Vec<u8>, usize, usize)>,
}
impl Side {
    fn enqueue(&mut self, packet: Vec<u8>, now: u64) -> Result<()> {
        self.fragment_id = self.fragment_id.wrapping_add(1);
        let chunk = ((bond::BOND_MTU - 20) / 8) * 8;
        let total = packet.len() - 20;
        for (index, body) in packet[20..].chunks(chunk).enumerate() {
            let mut part = packet[..20].to_vec();
            part.extend_from_slice(body);
            let len = part.len() as u16;
            part[2..4].copy_from_slice(&len.to_be_bytes());
            part[4..6].copy_from_slice(&self.fragment_id.to_be_bytes());
            let offset = ((index * chunk / 8) as u16)
                | if (index + 1) * chunk < total {
                    0x2000
                } else {
                    0
                };
            part[6..8].copy_from_slice(&offset.to_be_bytes());
            let mut capture = Capture(Vec::new());
            self.udp.send(
                &part,
                &udp_lane::links(&self.scheduler, now),
                Policy::Smart,
                now,
                &mut capture,
            )?;
            self.outbound.extend(capture.0);
        }
        Ok(())
    }
    fn controls(&mut self, packets: Vec<Packet>, now: u64) -> Result<()> {
        for mut p in packets {
            for link in udp_lane::links(&self.scheduler, now)
                .into_iter()
                .filter(|p| p.status == 1)
            {
                p.link = link.id;
                self.outbound.push(Frame {
                    kind: Kind::Udp,
                    path: link.id,
                    id: 0,
                    stamp: 0,
                    body: self.udp.encode(&p)?,
                });
            }
        }
        Ok(())
    }
    fn receive_udp(&mut self, frame: &Frame, now: u64) -> Result<Vec<Vec<u8>>> {
        let p = self.udp.decode(&frame.body)?;
        if p.flags == ACK || p.flags == NACK {
            let mut capture = Capture(Vec::new());
            self.udp.control(
                &frame.body,
                &udp_lane::links(&self.scheduler, now),
                &mut capture,
            )?;
            self.outbound.extend(capture.0);
        } else {
            let controls = self.udp.receive(p, now)?;
            self.controls(controls, now)?;
        }
        let mut complete = Vec::new();
        while let Some(p) = self.udp.pop() {
            let id = u16::from_be_bytes([p[4], p[5]]);
            let flags = u16::from_be_bytes([p[6], p[7]]);
            let offset = usize::from(flags & 0x1fff) * 8;
            let entry = self.reassembly.entry(id).or_insert((Vec::new(), 0, 0));
            entry.0.resize(entry.0.len().max(offset + p.len() - 20), 0);
            entry.0[offset..offset + p.len() - 20].copy_from_slice(&p[20..]);
            entry.1 += p.len() - 20;
            if flags & 0x2000 == 0 {
                entry.2 = offset + p.len() - 20;
            }
            if entry.2 > 0 && entry.1 == entry.2 {
                let (datagram, _, _) = self.reassembly.remove(&id).unwrap();
                complete.push(datagram[8..].to_vec());
            }
        }
        ensure!(
            self.reassembly.len() < 512,
            "fragment loss exhausted test reassembly"
        );
        Ok(complete)
    }
}

fn pair() -> Result<[Side; 2]> {
    let session = [83; 16];
    let mut a = bond::handshake(&[19; 32], &session, true)?;
    let mut b = bond::handshake(&[19; 32], &session, false)?;
    let mut wire = [0; 256];
    let mut plain = [0; 256];
    let n = a.write_message(&[], &mut wire)?;
    b.read_message(&wire[..n], &mut plain)?;
    let n = b.write_message(&[], &mut wire)?;
    a.read_message(&wire[..n], &mut plain)?;
    Ok([
        Side {
            scheduler: Scheduler::new(
                vec![("a".into(), false), ("b".into(), false)],
                Policy::Smart,
            )?,
            transport: bond::transport(session, a)?,
            udp: UdpLane::new(&[19; 32], &session, Policy::Smart)?,
            outbound: Vec::new(),
            fragment_id: 0,
            reassembly: Default::default(),
        },
        Side {
            scheduler: Scheduler::new(
                vec![("a".into(), false), ("b".into(), false)],
                Policy::Smart,
            )?,
            transport: bond::transport(session, b)?,
            udp: UdpLane::new(&[19; 32], &session, Policy::Smart)?,
            outbound: Vec::new(),
            fragment_id: 0,
            reassembly: Default::default(),
        },
    ])
}

fn ip_datagram(payload: &[u8], reverse: bool) -> Vec<u8> {
    let mut packet = vec![0; 28 + payload.len()];
    let len = packet.len() as u16;
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&len.to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    let (source, destination) = if reverse {
        ([1, 1, 1, 1], [10, 78, 0, 2])
    } else {
        ([10, 78, 0, 2], [1, 1, 1, 1])
    };
    packet[12..16].copy_from_slice(&source);
    packet[16..20].copy_from_slice(&destination);
    packet[20..22].copy_from_slice(&(if reverse { 9000_u16 } else { 50000_u16 }).to_be_bytes());
    packet[22..24].copy_from_slice(&(if reverse { 50000_u16 } else { 9000_u16 }).to_be_bytes());
    packet[24..26].copy_from_slice(&((payload.len() + 8) as u16).to_be_bytes());
    packet[28..].copy_from_slice(payload);
    packet
}

#[tokio::test]
#[ignore = "requires ffmpeg with SRT and MPEG2; runs an isolated 7-second native video stream"]
async fn repo_srt_fragmented_video_survives_silent_path_loss_and_return() -> Result<()> {
    let ffmpeg = std::env::var("VERZ_FFMPEG").unwrap_or_else(|_| "ffmpeg".into());
    let client_socket = UdpSocket::bind("127.0.0.1:0").await?;
    let server_socket = UdpSocket::bind("127.0.0.1:0").await?;
    // Reserve a loopback port, then hand it to the external SRT listener.
    let reservation = std::net::UdpSocket::bind("127.0.0.1:0")?;
    let listener_port = reservation.local_addr()?.port();
    drop(reservation);
    server_socket
        .connect((std::net::Ipv4Addr::LOCALHOST, listener_port))
        .await?;
    let receive_url = format!(
        "srt://127.0.0.1:{listener_port}?mode=listener&latency=120000&listen_timeout=12000000"
    );
    let send_url = format!(
        "srt://127.0.0.1:{}?mode=caller&latency=120000&pkt_size=1316&connect_timeout=10000",
        client_socket.local_addr()?.port()
    );
    let mut receiver = Command::new(&ffmpeg)
        .args([
            "-nostdin",
            "-hide_banner",
            "-loglevel",
            "error",
            "-threads",
            "1",
            "-analyzeduration",
            "100000",
            "-probesize",
            "32768",
            "-i",
            &receive_url,
            "-frames:v",
            "70",
            "-threads",
            "1",
            "-f",
            "framemd5",
            "pipe:1",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;
    let mut decoded = BufReader::new(receiver.stdout.take().context("receiver stdout")?).lines();
    time::sleep(Duration::from_millis(200)).await;
    let mut sender = Command::new(&ffmpeg)
        .args([
            "-nostdin",
            "-hide_banner",
            "-loglevel",
            "error",
            "-re",
            "-f",
            "lavfi",
            "-i",
            "testsrc2=size=160x96:rate=10",
            "-t",
            "9",
            "-an",
            "-c:v",
            "mpeg2video",
            "-threads",
            "1",
            "-g",
            "10",
            "-b:v",
            "500k",
            "-f",
            "mpegts",
            &send_url,
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;
    let mut sides = pair()?;
    // Establish probe health before allowing the test's SRT handshake.
    for side in &mut sides {
        for at in [10, 20, 30] {
            for id in 0..2 {
                side.scheduler
                    .receive(&Frame::control(Kind::Pong, id, 0, at - 5), at);
            }
        }
    }
    let epoch = Instant::now();
    let mut tick = time::interval(Duration::from_millis(2));
    tick.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
    let mut from_client = [0; 2048];
    let mut from_server = [0; 2048];
    let mut peer: Option<SocketAddr> = None;
    let mut cut = None;
    let mut cut_at = None;
    let mut restored = false;
    let mut last_decoded_at = None;
    let mut max_decode_gap_ms = 0;
    let mut decoded_frames = 0;
    let mut frames_at_cut = 0;
    let mut dropped = 0;
    let mut data_after_cut = 0;
    let result: Result<()> = async {
        loop {
            ensure!(epoch.elapsed() < Duration::from_secs(15), "native SRT test timed out: frames={decoded_frames}, cut={cut:?}, dropped={dropped}");
            tokio::select! {
                result = client_socket.recv_from(&mut from_client) => {
                    let (len, address) = result?;
                    ensure!(peer.is_none_or(|known| known == address), "SRT sender changed its socket identity");
                    peer = Some(address);
                    let packet = ip_datagram(&from_client[..len], false);
                    sides[0].enqueue(packet, epoch.elapsed().as_millis() as u64)?;
                },
                result = server_socket.recv(&mut from_server) => {
                    if let Ok(len) = result {
                        sides[1].enqueue(ip_datagram(&from_server[..len], true), epoch.elapsed().as_millis() as u64)?;
                    }
                },
                line = decoded.next_line() => {
                    match line? {
                        Some(line) if line.starts_with("0,") => {
                            let at = epoch.elapsed().as_millis() as u64;
                            if let Some(last) = last_decoded_at {
                                max_decode_gap_ms = max_decode_gap_ms.max(at - last);
                            }
                            last_decoded_at = Some(at);
                            decoded_frames += 1;
                            if decoded_frames >= 70 { break; }
                        },
                        Some(_) => {},
                        None => anyhow::bail!("video receiver stopped after {decoded_frames} frames"),
                    }
                },
                _ = tick.tick() => {},
            }
            let now = epoch.elapsed().as_millis() as u64;
            if let Some(path) = cut && !restored && now >= 5000 {
                let path = usize::from(path);
                for side in &mut sides {
                    side.scheduler.add_path(if path == 0 { "a" } else { "b" }.into(), false)?;
                }
                restored = true;
            }
            let mut pending = VecDeque::new();
            for (direction, side) in sides.iter_mut().enumerate() {
                pending.extend(side.scheduler.tick(now).into_iter().map(|frame| (direction, frame)));
                let controls=side.udp.tick(now);side.controls(controls,now)?;
                pending.extend(side.outbound.drain(..).map(|frame| (direction,frame)));
            }
            while let Some((direction, frame)) = pending.pop_front() {
                // Cut the link carrying this live media packet, not the link
                // that happened to send the most cumulative handshake bytes.
                if cut.is_none() && now >= 3500 && decoded_frames >= 10
                    && direction == 0 && frame.kind == Kind::Udp && frame.body.len() >= 500
                {
                    cut = Some(frame.path);
                    cut_at = Some(now);
                    frames_at_cut = decoded_frames;
                }
                if cut == Some(frame.path) && !restored {
                    if frame.kind == Kind::Udp { dropped += 1; }
                    continue; // Silent loss in BOTH directions; no fail_path call.
                }
                let wire = sides[direction].transport.seal(IP, &frame.encode())?;
                let destination = 1 - direction;
                let decoded_frame = Frame::decode(&sides[destination].transport.open(&wire)?.1)?;
                let deliveries=if decoded_frame.kind==Kind::Udp {
                    sides[destination].receive_udp(&decoded_frame,now)?
                } else {
                    let (_,replies)=sides[destination].scheduler.receive(&decoded_frame,now);
                    pending.extend(replies.into_iter().map(|reply|(destination,reply)));
                    Vec::new()
                };
                pending.extend(sides[destination].outbound.drain(..).map(|frame|(destination,frame)));
                for packet in deliveries {
                    if cut.is_some() { data_after_cut += 1; }
                    if destination == 1 {
                        server_socket.send(&packet).await?;
                    } else if let Some(address) = peer {
                        client_socket.send_to(&packet, address).await?;
                    }
                }
            }
        }
        ensure!(cut.is_some() && dropped > 0, "test did not interrupt a carrying path");
        ensure!(decoded_frames - frames_at_cut >= 20 && data_after_cut > 0, "video did not continue after path loss");
        ensure!(restored, "test did not exercise path return");
        ensure!(max_decode_gap_ms < 300, "decoded video stalled for {max_decode_gap_ms} ms");
        eprintln!("Path restored during stream; maximum decoded frame gap {max_decode_gap_ms} ms (10 fps source).");
        eprintln!("Native SRT: {decoded_frames} decoded frames; cut path {cut:?} at {cut_at:?} ms after {frames_at_cut} frames; dropped {dropped} outer data frames; {data_after_cut} packets delivered afterward; one sender socket throughout.");
        Ok(())
    }.await;
    // Child processes are test-owned, and only loopback ports were used.
    let _ = sender.kill().await;
    let _ = receiver.kill().await;
    if result.is_err() {
        use tokio::io::AsyncReadExt;
        for stderr in [sender.stderr.take(), receiver.stderr.take()]
            .into_iter()
            .flatten()
        {
            let mut errors = String::new();
            let _ = stderr.take(16_384).read_to_string(&mut errors).await;
            eprintln!("ffmpeg: {errors}");
        }
    }
    result
}
