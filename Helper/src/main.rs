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
        .context("start Rust networking engine")?;
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
    drop(stop_tx);
    let mut network: Option<network::NetworkGuard> = None;
    let mut proxy: Option<network::ProxyGuard> = None;
    let mut hybrid_proxy_endpoint: Option<String> = None;
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
                        if line.starts_with("TUNNEL CONNECTED:") && network.is_none() {
                            event(
                                &events,
                                json!({"event":"configuring", "line":"Keeping Secure Continuity warm for selective relay escalation"}),
                            );
                            network = Some(network::NetworkGuard::configure(
                                endpoint,
                                &interfaces,
                                &relay.ip().to_string(),
                            )?);
                        } else if line.starts_with("DIRECT CONNECTED:") {
                            hybrid_proxy_endpoint = Some(endpoint.to_owned());
                        }
                        if network.is_some()
                            && proxy.is_none()
                            && let Some(endpoint) = hybrid_proxy_endpoint.as_deref()
                        {
                            event(
                                &events,
                                json!({"event":"configuring", "line":"Enabling direct-first flow steering with secure escalation"}),
                            );
                            proxy = Some(network::ProxyGuard::configure(endpoint, &interfaces)?);
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
                    network::NetworkGuard::configure(endpoint, &interfaces, &relay.ip().to_string())
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
                if let Some(guard) = network.as_mut() {
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
                if let Some(input) = child.stdin.as_mut() {
                    let _ = writeln!(input, "{value}");
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
