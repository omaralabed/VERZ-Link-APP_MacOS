//! Real local SRT uses the same datagram entry/exit as the Swift proxy.
//! No user applications, physical interfaces, routes, or cloud state change.
use super::*;
use std::{
    io::{BufRead, BufReader},
    net::UdpSocket,
    process::{Child, Command, Stdio},
    sync::mpsc,
    time::Duration,
};
struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
#[ignore = "requires local ffmpeg; real 7-second encrypted SRT stream"]
fn native_srt_complete_datagrams_across_both_wan_cuts() {
    let ffmpeg = std::env::var("VERZ_FFMPEG").unwrap_or_else(|_| "ffmpeg".into());
    let app = UdpSocket::bind("127.0.0.1:0").unwrap();
    app.set_nonblocking(true).unwrap();
    let reservation = UdpSocket::bind("127.0.0.1:0").unwrap();
    let remote = reservation.local_addr().unwrap().port();
    drop(reservation);
    let receiver_url =
        format!("srt://127.0.0.1:{remote}?mode=listener&latency=120000&listen_timeout=12000000");
    let mut receiver = Process(
        Command::new(&ffmpeg)
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
                &receiver_url,
                "-frames:v",
                "70",
                "-threads",
                "1",
                "-f",
                "framemd5",
                "pipe:1",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    );
    let (frames_tx, frames) = mpsc::channel();
    let output = receiver.0.stdout.take().unwrap();
    let reader = std::thread::spawn(move || {
        for line in BufReader::new(output).lines().map_while(Result::ok) {
            if !line.starts_with('#') && line.contains(',') {
                let _ = frames_tx.send(Instant::now());
            }
        }
    });
    let key = "native-udp-test-0123456789abcdef0123456789abcdef";
    let mut gateway =
        secure::SecureGateway::bind("127.0.0.1:0".parse().unwrap(), key.into(), true).unwrap();
    let gateway_address = gateway.address().unwrap();
    let router = UdpSocket::bind("127.0.0.1:0").unwrap();
    router.set_nonblocking(true).unwrap();
    let mut e = Engine::new(Enrollment {
        gateway: router.local_addr().unwrap(),
        session: 192,
        key: key.into(),
    })
    .unwrap();
    let name = if cfg!(target_os = "macos") {
        "lo0"
    } else {
        "lo"
    };
    e.adapters(
        (1..=2)
            .map(|id| Adapter {
                id,
                name: name.into(),
                address: Ipv4Addr::LOCALHOST,
            })
            .collect(),
    )
    .unwrap();
    unsafe { verz_mode(&mut e, 2) };
    let mut paths = std::collections::HashMap::new();
    let mut route = |cut: u8| {
        let mut buf = [0; 17000];
        for _ in 0..256 {
            let Ok((n, from)) = router.recv_from(&mut buf) else {
                break;
            };
            if n < 30 {
                continue;
            };
            assert_eq!(&buf[..4], b"VZU1");
            let id = buf[21];
            if from == gateway_address {
                if id != cut
                    && let Some(to) = paths.get(&id)
                {
                    router.send_to(&buf[..n], to).unwrap();
                }
            } else {
                paths.insert(id, from);
                if id != cut {
                    router.send_to(&buf[..n], gateway_address).unwrap();
                }
            }
        }
    };
    let ready = Instant::now();
    while ready.elapsed() < Duration::from_millis(300) {
        e.tick();
        route(0);
        gateway.step().unwrap();
        route(0);
        e.tick();
        std::thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(e.links().iter().filter(|p| p.status == 1).count(), 2);
    let send_url = format!(
        "srt://127.0.0.1:{}?mode=caller&latency=120000&pkt_size=1316&connect_timeout=10000",
        app.local_addr().unwrap().port()
    );
    let sender = Process(
        Command::new(&ffmpeg)
            .args([
                "-nostdin",
                "-hide_banner",
                "-loglevel",
                "error",
                "-re",
                "-f",
                "lavfi",
                "-i",
                "testsrc2=size=320x180:rate=10",
                "-t",
                "9",
                "-an",
                "-c:v",
                "libx264",
                "-preset",
                "ultrafast",
                "-tune",
                "zerolatency",
                "-x264-params",
                "nal-hrd=cbr:force-cfr=1",
                "-threads",
                "1",
                "-g",
                "10",
                "-b:v",
                "6M",
                "-minrate",
                "6M",
                "-maxrate",
                "6M",
                "-bufsize",
                "6M",
                "-f",
                "mpegts",
                &send_url,
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    );
    let start = Instant::now();
    let mut source = None;
    let mut decoded = Vec::new();
    let mut buf = [0; 17000];
    while start.elapsed() < Duration::from_secs(12) && decoded.len() < 70 {
        let ms = start.elapsed().as_millis();
        let cut = if (2000..3200).contains(&ms) {
            2
        } else if (4500..5700).contains(&ms) {
            1
        } else {
            0
        };
        for _ in 0..128 {
            let Ok((n, from)) = app.recv_from(&mut buf) else {
                break;
            };
            if let Some(old) = source {
                assert_eq!(old, from);
            } else {
                source = Some(from);
            }
            e.send(31000, [127, 0, 0, 1], remote, &buf[..n]).unwrap();
        }
        e.tick();
        route(cut);
        gateway.step().unwrap();
        route(cut);
        e.tick();
        while let Some(packet) = e.received.pop_front() {
            if let Some(to) = source {
                app.send_to(&packet.payload, to).unwrap();
            }
        }
        decoded.extend(frames.try_iter());
        std::thread::sleep(Duration::from_millis(1));
    }
    drop(sender);
    drop(receiver);
    reader.join().unwrap();
    assert_eq!(decoded.len(), 70, "native video did not complete");
    let max_gap = decoded
        .windows(2)
        .map(|p| p[1].duration_since(p[0]))
        .max()
        .unwrap();
    println!(
        "70 decoded frames, maximum inter-frame gap {} ms, uploaded {} bytes",
        max_gap.as_millis(),
        e.upload
    );
    assert!(
        max_gap < Duration::from_millis(350),
        "video delivery stalled across WAN cut: {max_gap:?}"
    );
}

#[test]
#[ignore = "requires explicitly configured deployed gateway and temporary echo target"]
fn deployed_gateway_echo() {
    let gateway = std::env::var("VERZ_UDP_TEST_GATEWAY")
        .unwrap()
        .parse()
        .unwrap();
    let key = std::fs::read_to_string(std::env::var("VERZ_UDP_TEST_SECRET_FILE").unwrap()).unwrap();
    let target: std::net::SocketAddrV4 = std::env::var("VERZ_UDP_TEST_ECHO")
        .unwrap()
        .parse()
        .unwrap();
    let adapters: Vec<Adapter> =
        serde_json::from_str(&std::env::var("VERZ_UDP_TEST_ADAPTERS").unwrap()).unwrap();
    let mut e = Engine::new(Enrollment {
        gateway,
        key: key.trim().into(),
        session: rand::random::<u32>().max(1),
    })
    .unwrap();
    e.adapters(adapters.clone()).unwrap();
    unsafe { verz_mode(&mut e, 2) };
    let ready = Instant::now();
    while ready.elapsed() < Duration::from_secs(8)
        && e.links().iter().filter(|p| p.status == 1).count() < adapters.len()
    {
        e.tick();
        std::thread::sleep(Duration::from_millis(2));
    }
    assert_eq!(
        e.links().iter().filter(|p| p.status == 1).count(),
        adapters.len(),
        "not all selected paths authenticated: {:?}",
        e.links()
    );
    for sequence in 0u32..100 {
        // Remove/recreate only one engine socket. Never disable an actual Mac adapter.
        if sequence == 25 {
            e.adapters(vec![adapters[0].clone()]).unwrap();
        }
        if sequence == 50 {
            e.adapters(adapters.clone()).unwrap();
        }
        let mut payload = vec![0x5a; 1332];
        payload[..4].copy_from_slice(&sequence.to_be_bytes());
        e.send(1234, target.ip().octets(), target.port(), &payload)
            .unwrap();
        let deadline = Instant::now();
        let mut found = false;
        while deadline.elapsed() < Duration::from_secs(2) {
            e.tick();
            while let Some(reply) = e.received.pop_front() {
                if reply.payload == payload {
                    found = true;
                }
            }
            if found {
                break;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        assert!(found, "deployed echo lost sequence {sequence}");
    }
    println!(
        "Deployed encrypted gateway: 100 complete 1332-byte echoes, {} authenticated paths; secondary socket removal/restoration exercised: {}",
        adapters.len(),
        adapters.len() > 1
    );
}
