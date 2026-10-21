//! Owns one privileged tunnel child for one connected local app. Closing the
//! app's authenticated Unix socket terminates that exact child and removes utun.
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{
    io::{BufRead, BufReader, Read, Write},
    os::{fd::AsRawFd, unix::net::UnixStream},
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::{Arc, Mutex, mpsc},
    thread,
    time::{Duration, Instant},
};

type Events = Arc<Mutex<UnixStream>>;
mod network;
enum Control {
    Stop,
    Connected(String),
    Settings(Value),
    /// A kept stream's socket closed; its index in the bypass list.
    FlowEnded(usize),
}

/// A stream the app found running on a physical link before Connect and the
/// user chose to keep there.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Bypass {
    protocol: String,
    port: u16,
    interface: String,
    remote: Option<std::net::Ipv4Addr>,
    process: String,
}

const MAX_BYPASS: usize = 8;

fn parse_bypass(initial: &Value, interfaces: &[String]) -> Vec<Bypass> {
    let Some(items) = initial.get("bypass").and_then(Value::as_array) else {
        return Vec::new();
    };
    items
        .iter()
        .filter_map(|item| {
            let protocol = item.get("protocol")?.as_str()?;
            if protocol != "udp" && protocol != "tcp" {
                return None;
            }
            let port = u16::try_from(item.get("port")?.as_u64()?).ok().filter(|port| *port > 0)?;
            let interface = item.get("interface")?.as_str()?;
            if !interfaces.iter().any(|name| name == interface) {
                return None;
            }
            let remote = match item.get("remote").and_then(Value::as_str).unwrap_or("") {
                "" => None,
                text => Some(text.parse().ok()?),
            };
            let process: String = item
                .get("process")
                .and_then(Value::as_str)
                .unwrap_or("")
                .chars()
                .filter(|c| c.is_ascii_alphanumeric() || matches!(c, ' ' | '.' | '-' | '_'))
                .take(24)
                .collect();
            Some(Bypass {
                protocol: protocol.to_owned(),
                port,
                interface: interface.to_owned(),
                remote,
                process: if process.trim().is_empty() { "A stream".to_owned() } else { process },
            })
        })
        .take(MAX_BYPASS)
        .collect()
}

/// The far end of a captured packet: "IP 192.168.1.5.63690 > 1.2.3.4.9000: UDP ..."
fn destination_from_capture(output: &str) -> Option<std::net::Ipv4Addr> {
    output.lines().find_map(|line| {
        let (_, rest) = line.split_once(" > ")?;
        let endpoint = rest.split([':', ' ']).next()?;
        let (host, _port) = endpoint.rsplit_once('.')?;
        host.parse().ok()
    })
}

/// Learns where an unconnected socket sends by capturing one of its packets
/// on its link, before the tunnel takes the route.
fn capture_destination(stream: &Bypass) -> Option<std::net::Ipv4Addr> {
    let filter = format!("{} and src port {}", stream.protocol, stream.port);
    let mut child = Command::new("/usr/sbin/tcpdump")
        .args(["-i", &stream.interface, "-c", "1", "-n", "-l", "-q", "-s", "64", &filter])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        if child.try_wait().ok()?.is_some() {
            let output = child.wait_with_output().ok()?;
            return destination_from_capture(&String::from_utf8_lossy(&output.stdout));
        }
        thread::sleep(Duration::from_millis(50));
    }
    let _ = child.kill();
    let _ = child.wait();
    None
}

/// Reports when the kept stream's socket is gone, so its pin can be lifted.
fn watch_flow(stream: Bypass, index: usize, tx: mpsc::Sender<Control>) {
    thread::spawn(move || loop {
        thread::sleep(Duration::from_secs(5));
        let open = Command::new("/usr/sbin/lsof")
            .args(["-nP", &format!("-i{}:{}", stream.protocol.to_uppercase(), stream.port), "-F", "p"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .output()
            .map(|output| output.status.success())
            .unwrap_or(true);
        if !open {
            let _ = tx.send(Control::FlowEnded(index));
            break;
        }
    });
}

/// Pins each kept stream's destination to its link and starts watching it.
fn keep_streams(
    guard: &mut network::NetworkGuard,
    streams: &[Bypass],
    events: &Events,
    tx: &mpsc::Sender<Control>,
) -> Vec<Option<std::net::Ipv4Addr>> {
    streams
        .iter()
        .enumerate()
        .map(|(index, stream)| {
            let Some(destination) = stream.remote.or_else(|| capture_destination(stream)) else {
                event(
                    events,
                    json!({"event":"log", "line":format!("Could not learn where {}'s stream goes; it will reconnect once through VERZ", stream.process)}),
                );
                return None;
            };
            match guard.add_bypass(&destination.to_string(), &stream.interface) {
                Ok(()) => {
                    event(
                        events,
                        json!({"event":"log", "line":format!("{}'s stream to {destination} stays on {} until it restarts", stream.process, stream.interface)}),
                    );
                    watch_flow(stream.clone(), index, tx.clone());
                    Some(destination)
                }
                Err(error) => {
                    event(
                        events,
                        json!({"event":"log", "line":format!("Could not keep {}'s stream on {}: {error}; it will reconnect once through VERZ", stream.process, stream.interface)}),
                    );
                    None
                }
            }
        })
        .collect()
}

fn event(events: &Events, value: Value) {
    if let Ok(mut socket) = events.lock() {
        let _ = writeln!(socket, "{value}");
    }
}

fn stop(child: &mut Child) -> Result<()> {
    if child.try_wait()?.is_some() {
        return Ok(());
    }
    // SAFETY: this PID belongs to our still-unreaped direct child; it cannot
    // be reused before wait. SIGTERM lets the Rust engine close its TUN FD.
    unsafe {
        libc::kill(child.id() as libc::pid_t, libc::SIGTERM);
    }
    let deadline = Instant::now() + Duration::from_secs(4);
    while Instant::now() < deadline {
        if child.try_wait()?.is_some() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(40));
    }
    child.kill()?;
    child.wait()?;
    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    ensure!(
        args.len() == 5,
        "expected: private-run-directory app-uid relay interfaces policy"
    );
    let directory = PathBuf::from(&args[0]);
    let app_uid: libc::uid_t = args[1].parse()?;
    let relay: std::net::SocketAddrV4 = args[2].parse()?;
    let mut interfaces: Vec<String> = args[3].split(',').map(str::to_owned).collect();
    let policy = &args[4];
    ensure!(
        !interfaces.is_empty()
            && interfaces.len() <= 256
            && interfaces.iter().all(|name| valid_interface(name)),
        "invalid interface list"
    );
    ensure!(
        ["smart", "performance", "continuity", "data-saver"].contains(&policy.as_str()),
        "invalid policy"
    );
    let socket =
        UnixStream::connect(directory.join("app.sock")).context("connect app control socket")?;
    let mut peer_uid = 0;
    let mut peer_gid = 0;
    // SAFETY: these pointers refer to valid uid/gid storage and the FD is open.
    let status = unsafe { libc::getpeereid(socket.as_raw_fd(), &mut peer_uid, &mut peer_gid) };
    ensure!(
        status == 0 && peer_uid == app_uid,
        "control socket does not belong to requesting app user"
    );
    socket.set_write_timeout(Some(Duration::from_secs(2)))?;
    let reader = socket.try_clone()?;
    let events: Events = Arc::new(Mutex::new(socket));
    event(&events, json!({"event":"helper_ready"}));
    reader.set_read_timeout(Some(Duration::from_secs(8)))?;
    let mut input = BufReader::new(reader);
    let mut initial_line = Vec::new();
    let count = input
        .by_ref()
        .take(65537)
        .read_until(b'\n', &mut initial_line)?;
    ensure!(
        count > 0 && count <= 65536,
        "app did not provide initial configuration"
    );
    let initial: Value =
        serde_json::from_slice(&initial_line).context("invalid initial configuration")?;
    input.get_mut().set_read_timeout(None)?;
    let mode = initial
        .get("mode")
        .and_then(Value::as_str)
        .unwrap_or("secure");
    ensure!(
        ["direct", "hybrid", "secure"].contains(&mode),
        "invalid connection mode"
    );
    let direct = mode == "direct";
    let hybrid = mode == "hybrid";
    let initial_items = initial
        .get("interfaces")
        .and_then(Value::as_array)
        .context("initial interfaces are missing")?;
    interfaces = initial_items
        .iter()
        .filter_map(|item| item.get("name").and_then(Value::as_str))
        .map(str::to_owned)
        .collect();
    ensure!(
        !interfaces.is_empty()
            && interfaces.len() == initial_items.len()
            && interfaces.iter().all(|name| valid_interface(name)),
        "invalid initial interfaces"
    );
    let bypass = if direct || hybrid { Vec::new() } else { parse_bypass(&initial, &interfaces) };
    let mut kept: Vec<Option<std::net::Ipv4Addr>> = Vec::new();
    // Persistent service: only run the engine beside this signed supervisor,
    // never a user-replaceable executable from the session directory.
    let engine = std::env::current_exe()?
        .parent()
        .context("supervisor executable directory")?
        .join("verz-bond");
    let configured_policy = initial
        .get("policy")
        .and_then(Value::as_str)
        .unwrap_or(policy);
    ensure!(
        ["smart", "performance", "continuity", "data-saver"].contains(&configured_policy),
        "invalid configured policy"
    );
    let mut command = Command::new(engine);
    if direct || hybrid {
        let paths: Vec<String> = initial_items
            .iter()
            .filter_map(|item| {
                let name = item.get("name")?.as_str()?;
                let address = item.get("address")?.as_str()?;
                address.parse::<std::net::Ipv4Addr>().ok()?;
                let metered = item
                    .get("metered")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                Some(format!("{name}={address},{metered}"))
            })
            .collect();
        ensure!(
            paths.len() == initial_items.len(),
            "direct path addresses are invalid"
        );
        if hybrid {
            let domains = initial
                .get("secureDomains")
                .and_then(Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .map(|item| item.as_str().context("secure domain must be text"))
                        .collect::<Result<Vec<_>>>()
                })
                .transpose()?
                .unwrap_or_default();
            ensure!(
                domains.iter().all(|domain| valid_domain(domain)),
                "invalid secure domain"
            );
            let brain = std::net::SocketAddr::new((*relay.ip()).into(), 39003);
            command
                .args(["hybrid", "--relay", &relay.to_string(), "--interface"])
                .args(&interfaces)
                .arg("--secret-file")
                .arg(directory.join("lab-secret"))
                .args(["--listen", "127.0.0.1:0", "--path"])
                .args(paths)
                .args(["--policy", configured_policy, "--brain", &brain.to_string()]);
            for domain in domains {
                command.args(["--secure-domain", domain]);
            }
        } else {
            command
                .args(["direct", "--listen", "127.0.0.1:0", "--path"])
                .args(paths)
                .args(["--policy", configured_policy, "--control-stdin"]);
        }
    } else {
        command
            .args(["client", "--relay", &relay.to_string(), "--interface"])
            .args(&interfaces)
            .arg("--secret-file")
            .arg(directory.join("lab-secret"))
            .args(["--policy", configured_policy, "--control-stdin"]);
    }
    let mut child = command
        .current_dir(&directory)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("start networking engine")?;
    let (stop_tx, stop_rx) = mpsc::channel();
    let input_tx = stop_tx.clone();
    thread::spawn(move || {
        loop {
            let mut line = Vec::new();
            let count = input
                .by_ref()
                .take(65537)
                .read_until(b'\n', &mut line)
                .unwrap_or(0);
            if count == 0 || count > 65536 || line == b"disconnect\n" {
                break;
            }
            let Ok(value) = serde_json::from_slice::<Value>(&line) else {
                break;
            };
            if input_tx.send(Control::Settings(value)).is_err() {
                break;
            }
        }
        let _ = input_tx.send(Control::Stop);
    });
    let stdout = child.stdout.take().context("missing engine output")?;
    let stderr = child.stderr.take().context("missing engine error output")?;
    let out_events = events.clone();
    let ready_tx = stop_tx.clone();
    let output_thread = thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            let connected =
                line.starts_with("TUNNEL CONNECTED:") || line.starts_with("DIRECT CONNECTED:");
            if connected {
                let _ = ready_tx.send(Control::Connected(line));
            } else if let Some(telemetry) = line.strip_prefix("BOND_STATE ") {
                event(&out_events, json!({"event":"telemetry", "line":telemetry}));
            } else if let Some(telemetry) = line.strip_prefix("DIRECT_STATE ") {
                event(
                    &out_events,
                    json!({"event":"direct_telemetry", "line":telemetry}),
                );
            } else if let Some(state) = line.strip_prefix("BRAIN_STATE ") {
                event(&out_events, json!({"event":"brain", "line":state}));
            } else if let Some(record) = line.strip_prefix("FLOW_RECORD ") {
                event(&out_events, json!({"event":"flow", "line":record}));
            } else {
                event(&out_events, json!({"event":"log", "line":line}));
            }
        }
    });
    let err_events = events.clone();
    let error_thread = thread::spawn(move || {
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            event(&err_events, json!({"event":"engine_error", "line":line}));
        }
    });
    let watch_tx = stop_tx.clone();
    drop(stop_tx);
    let mut network: Option<network::NetworkGuard> = None;
    let mut proxy: Option<network::ProxyGuard> = None;
    let mut hybrid_proxy_endpoint: Option<String> = None;
    let mut hybrid_tun: Option<String> = None;
    let mut hybrid_announced = false;
    let code = loop {
        if let Some(status) = child.try_wait()? {
            break status.code().unwrap_or(1);
        }
        match stop_rx.recv_timeout(Duration::from_millis(100)) {
            Ok(Control::Connected(line)) => {
                let endpoint = line
                    .split_whitespace()
                    .nth(2)
                    .context("engine omitted connection endpoint")?;
                let configured: Result<()> = if hybrid {
                    (|| {
                        if line.starts_with("TUNNEL CONNECTED:") {
                            hybrid_tun = Some(endpoint.to_owned());
                        } else if line.starts_with("DIRECT CONNECTED:") {
                            hybrid_proxy_endpoint = Some(endpoint.to_owned());
                        }
                        if network.is_none()
                            && let Some(tun) = hybrid_tun.as_deref()
                            && let Some(endpoint) = hybrid_proxy_endpoint.as_deref()
                        {
                            let started = Instant::now();
                            event(
                                &events,
                                json!({"event":"configuring", "line":"Preparing and verifying direct + encrypted paths; existing DNS unchanged"}),
                            );
                            network = Some(network::NetworkGuard::prepare(
                                tun,
                                &interfaces,
                                &relay.ip().to_string(),
                                true,
                            )?);
                            network::verify_tunnel(tun)?;
                            network::verify_socks(endpoint)?;
                            event(
                                &events,
                                json!({"event":"configuring", "line":format!("Paths verified in {} ms; enabling prepared Hybrid routing", started.elapsed().as_millis())}),
                            );
                            proxy = Some(network::ProxyGuard::configure(endpoint, &interfaces)?);
                            network.as_mut().expect("prepared network").capture()?;
                        }
                        Ok(())
                    })()
                } else if direct {
                    event(
                        &events,
                        json!({"event":"configuring", "line":"Enabling local Direct Smart flow steering"}),
                    );
                    network::ProxyGuard::configure(endpoint, &interfaces)
                        .map(|guard| proxy = Some(guard))
                } else {
                    event(
                        &events,
                        json!({"event":"configuring", "line":"Routing Mac traffic and DNS through VERZ"}),
                    );
                    network::NetworkGuard::prepare(endpoint, &interfaces, &relay.ip().to_string(), false)
                        .and_then(|mut guard| {
                            // Pinned before the tunnel takes the route, so a
                            // kept stream never sends a packet through it.
                            kept = keep_streams(&mut guard, &bypass, &events, &watch_tx);
                            guard.capture()?;
                            Ok(guard)
                        })
                        .map(|guard| network = Some(guard))
                };
                match configured {
                    Ok(())
                        if hybrid && network.is_some() && proxy.is_some() && !hybrid_announced =>
                    {
                        hybrid_announced = true;
                        event(
                            &events,
                            json!({"event":"connected", "line":format!("HYBRID CONNECTED: {}", hybrid_proxy_endpoint.as_deref().unwrap_or(""))}),
                        );
                    }
                    Ok(()) if !hybrid => event(&events, json!({"event":"connected", "line":line})),
                    Ok(()) => {}
                    Err(error) => {
                        event(
                            &events,
                            json!({"event":"engine_error", "line":format!("Network setup failed: {error}")}),
                        );
                        stop(&mut child)?;
                        break 1;
                    }
                }
            }
            Ok(Control::Settings(value)) => {
                let Some(items) = value.get("interfaces").and_then(Value::as_array) else {
                    continue;
                };
                if items.len() > 256 {
                    continue;
                }
                let names: Vec<String> = items
                    .iter()
                    .filter_map(|item| item.get("name").and_then(Value::as_str))
                    .map(str::to_owned)
                    .collect();
                if names.len() != items.len() || !names.iter().all(|name| valid_interface(name)) {
                    continue;
                }
                interfaces = names;
                // The engine must learn about a lost adapter before this
                // process spends time in route/networksetup calls; it retries
                // a not-yet-routed new adapter on its own 500 ms cadence.
                if let Some(input) = child.stdin.as_mut() {
                    let _ = writeln!(input, "{value}");
                }
                if let Some(guard) = network.as_mut() {
                    if let Err(error) = guard.protect_ipv6(&interfaces) {
                        event(
                            &events,
                            json!({"event":"engine_error", "line":format!("IPv6 leak protection: {error}")}),
                        );
                        stop(&mut child)?;
                        break 1;
                    }
                    for interface in &interfaces {
                        if let Err(error) = guard.add_uplink(interface, &relay.ip().to_string()) {
                            event(
                                &events,
                                json!({"event":"log", "line":format!("Uplink {interface} is waiting for a gateway: {error}")}),
                            );
                        }
                    }
                    if let Err(error) = guard.refresh_dns() {
                        event(
                            &events,
                            json!({"event":"engine_error", "line":format!("DNS configuration: {error}")}),
                        );
                    }
                }
                if let Some(guard) = proxy.as_mut()
                    && let Err(error) = guard.sync(&interfaces)
                {
                    event(
                        &events,
                        json!({"event":"engine_error", "line":format!("Direct proxy configuration: {error}")}),
                    );
                }
            }
            Ok(Control::FlowEnded(index)) => {
                let Some(destination) = kept.get_mut(index).and_then(Option::take) else { continue };
                let Some(stream) = bypass.get(index) else { continue };
                if let Some(guard) = network.as_mut() {
                    match guard.remove_bypass(&destination.to_string()) {
                        Ok(()) => event(
                            &events,
                            json!({"event":"log", "line":format!("{}'s stream on {} ended · new streams go through VERZ", stream.process, stream.interface)}),
                        ),
                        Err(error) => event(
                            &events,
                            json!({"event":"log", "line":format!("Could not release the kept route for {}: {error}", stream.process)}),
                        ),
                    }
                }
            }
            Ok(Control::Stop) | Err(mpsc::RecvTimeoutError::Disconnected) => {
                stop(&mut child)?;
                break 0;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
    };
    if let Some(mut guard) = proxy {
        for error in guard.restore() {
            event(&events, json!({"event":"cleanup_error", "line":error}));
        }
    }
    if let Some(mut guard) = network {
        for error in guard.restore() {
            event(&events, json!({"event":"cleanup_error", "line":error}));
        }
    }
    let _ = output_thread.join();
    let _ = error_thread.join();
    event(&events, json!({"event":"exited", "code":code}));
    Ok(())
}

fn valid_interface(name: &str) -> bool {
    !name.is_empty() && name.len() < 16 && name.chars().all(|c| c.is_ascii_alphanumeric())
}

fn valid_domain(domain: &str) -> bool {
    let domain = domain.trim().trim_start_matches('.').trim_end_matches('.');
    !domain.is_empty()
        && domain.len() <= 253
        && domain.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        })
}

#[cfg(test)]
mod kept_stream_tests {
    use super::*;

    #[test]
    fn captured_packet_names_the_far_end() {
        let line = "12:00:00.000000 IP 192.168.108.12.63690 > 93.184.216.34.9000: UDP, length 1316\n";
        assert_eq!(destination_from_capture(line), Some("93.184.216.34".parse().unwrap()));
        let tcp = "IP 192.168.1.5.54459 > 17.57.144.55.1935: tcp 1448\n";
        assert_eq!(destination_from_capture(tcp), Some("17.57.144.55".parse().unwrap()));
        assert_eq!(destination_from_capture("tcpdump: listening on en7\n"), None);
        assert_eq!(destination_from_capture(""), None);
    }

    #[test]
    fn only_valid_kept_streams_on_selected_links_are_accepted() {
        let interfaces = vec!["en7".to_owned(), "en0".to_owned()];
        let initial = json!({"bypass": [
            {"protocol": "udp", "port": 63690, "interface": "en7", "remote": "", "process": "OBS"},
            {"protocol": "tcp", "port": 54459, "interface": "en0", "remote": "17.57.144.55", "process": "Google Chrome H"},
            {"protocol": "icmp", "port": 1, "interface": "en7"},
            {"protocol": "udp", "port": 0, "interface": "en7"},
            {"protocol": "udp", "port": 5000, "interface": "en9"},
            {"protocol": "udp", "port": 5001, "interface": "en7", "remote": "not an address"},
            {"protocol": "udp", "port": 5002, "interface": "en7", "process": "x<script>\u{1F600}"}
        ]});
        let parsed = parse_bypass(&initial, &interfaces);
        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed[0], Bypass { protocol: "udp".into(), port: 63690, interface: "en7".into(), remote: None, process: "OBS".into() });
        assert_eq!(parsed[1].remote, Some("17.57.144.55".parse().unwrap()));
        assert_eq!(parsed[1].process, "Google Chrome H");
        assert_eq!(parsed[2].process, "xscript");
        assert!(parse_bypass(&json!({}), &interfaces).is_empty());
        let many = json!({"bypass": (0..20).map(|i| json!({"protocol": "udp", "port": 1000 + i, "interface": "en7"})).collect::<Vec<_>>()});
        assert_eq!(parse_bypass(&many, &interfaces).len(), MAX_BYPASS);
    }
}
