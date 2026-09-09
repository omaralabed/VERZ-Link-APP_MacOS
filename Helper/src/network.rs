use anyhow::{Context, Result, ensure};
use std::{
    collections::HashMap,
    process::{Command, Stdio},
};

fn run(program: &str, args: &[&str]) -> Result<String> {
    let output = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .output()?;
    ensure!(
        output.status.success(),
        "{program}: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Records only changes made by this session; Drop restores DNS and removes
/// the added routes. The user's original default route is never deleted.
#[derive(Default)]
pub struct NetworkGuard {
    routes: Vec<Vec<String>>,
    dns: Vec<(String, Vec<String>)>,
}

impl NetworkGuard {
    pub fn configure(tun: &str, physical: &[String], relay: &str) -> Result<Self> {
        ensure!(
            tun.starts_with("utun") && tun.chars().all(|c| c.is_ascii_alphanumeric()),
            "invalid tunnel interface"
        );
        let internet_route = run("/sbin/route", &["-n", "get", "1.1.1.1"])?;
        let current = internet_route
            .lines()
            .find_map(|line| line.trim().strip_prefix("interface:").map(str::trim))
            .unwrap_or("");
        ensure!(
            !current.starts_with("utun") && !current.starts_with("tun"),
            "another VPN currently owns internet routing; verified VPN-underlay coexistence is not available in this build"
        );
        let mut guard = Self::default();
        let mut configured = 0;
        for interface in physical {
            if guard.add_uplink(interface, relay).is_ok() {
                configured += 1;
            }
        }
        ensure!(configured > 0, "no selected interface has a usable gateway");
        guard.add_route(&["-net", "0.0.0.0/1", "-interface", tun])?;
        guard.add_route(&["-net", "128.0.0.0/1", "-interface", tun])?;
        guard.add_route(&["-inet6", "-net", "::/1", "-interface", tun])?;
        guard.add_route(&["-inet6", "-net", "8000::/1", "-interface", tun])?;
        guard.refresh_dns()?;
        ensure!(
            !guard.dns.is_empty(),
            "no active network service found for tunnel DNS"
        );
        Ok(guard)
    }

    pub fn add_uplink(&mut self, physical: &str, relay: &str) -> Result<()> {
        let default = run(
            "/sbin/route",
            &["-n", "get", "-ifscope", physical, "default"],
        )?;
        let gateway = default
            .lines()
            .find_map(|line| line.trim().strip_prefix("gateway:").map(str::trim))
            .context("selected interface has no default gateway")?;
        let _: std::net::Ipv4Addr = gateway.parse().context("expected IPv4 gateway")?;
        let desired: Vec<String> = ["-host", relay, gateway, "-ifscope", physical]
            .iter()
            .map(|s| (*s).to_owned())
            .collect();
        if self.routes.contains(&desired) {
            // macOS may remove interface-scoped routes on unplug. A record
            // in our cleanup ledger is not proof that the route still exists.
            let existing =
                run("/sbin/route", &["-n", "get", "-ifscope", physical, relay]).unwrap_or_default();
            let field = |key: &str| {
                existing
                    .lines()
                    .find_map(|line| line.trim().strip_prefix(key).map(str::trim))
                    .unwrap_or("")
            };
            if field("destination:") == relay
                && field("gateway:") == gateway
                && field("interface:") == physical
            {
                return Ok(());
            }
            self.routes.retain(|route| route != &desired);
        }
        if let Some(index) = self.routes.iter().position(|route| {
            route.first().map(String::as_str) == Some("-host")
                && route.last().map(String::as_str) == Some(physical)
        }) {
            let previous = self.routes[index].clone();
            let mut args = vec!["-n", "delete"];
            args.extend(previous.iter().map(String::as_str));
            run("/sbin/route", &args)?;
            self.routes.remove(index);
        }
        self.add_route(&["-host", relay, gateway, "-ifscope", physical])
    }

    pub fn refresh_dns(&mut self) -> Result<()> {
        let services = run("/usr/sbin/networksetup", &["-listallnetworkservices"])?;
        for service in services
            .lines()
            .skip(1)
            .filter(|line| !line.starts_with('*') && !line.is_empty())
        {
            if self.dns.iter().any(|(name, _)| name == service) {
                continue;
            }
            let Ok(info) = run("/usr/sbin/networksetup", &["-getinfo", service]) else {
                continue;
            };
            let active = info.lines().any(|line| {
                line.strip_prefix("IP address: ")
                    .is_some_and(|ip| ip.parse::<std::net::Ipv4Addr>().is_ok())
            });
            if !active {
                continue;
            }
            let previous = run("/usr/sbin/networksetup", &["-getdnsservers", service])?;
            let servers: Vec<String> = previous
                .lines()
                .filter(|line| line.parse::<std::net::IpAddr>().is_ok())
                .map(str::to_owned)
                .collect();
            // Record before mutation so a partially failed setup rolls back.
            self.dns.push((service.to_owned(), servers));
            run(
                "/usr/sbin/networksetup",
                &["-setdnsservers", service, "1.1.1.1", "1.0.0.1"],
            )?;
        }
        Ok(())
    }

    fn add_route(&mut self, args: &[&str]) -> Result<()> {
        let mut add = vec!["-n", "add"];
        add.extend_from_slice(args);
        run("/sbin/route", &add)?;
        self.routes
            .push(args.iter().map(|arg| (*arg).to_owned()).collect());
        Ok(())
    }

    pub fn restore(&mut self) -> Vec<String> {
        let mut failures = Vec::new();
        for (service, mut servers) in self.dns.drain(..).rev() {
            if servers.is_empty() {
                servers.push("Empty".into());
            }
            let mut args = vec!["-setdnsservers", service.as_str()];
            args.extend(servers.iter().map(String::as_str));
            if let Err(error) = run("/usr/sbin/networksetup", &args) {
                failures.push(error.to_string());
            }
        }
        for route in self.routes.drain(..).rev() {
            if let Some(name) = route.last().filter(|name| name.starts_with("utun")) {
                let name = std::ffi::CString::new(name.as_str()).expect("validated interface name");
                // A closed utun and its interface routes are already removed
                // by the kernel; route(8) cannot resolve that name anymore.
                if unsafe { libc::if_nametoindex(name.as_ptr()) } == 0 {
                    continue;
                }
            }
            let mut args = vec!["-n", "delete"];
            args.extend(route.iter().map(String::as_str));
            // Kernel removes routes attached to a closed utun itself.
            if let Err(error) = run("/sbin/route", &args) {
                let message = error.to_string();
                if !message.contains("not in table")
                    && !message.contains("No such process")
                    && !message.contains("Network is unreachable")
                {
                    failures.push(message);
                }
            }
        }
        failures
    }
}

impl Drop for NetworkGuard {
    fn drop(&mut self) {
        for error in self.restore() {
            eprintln!("Network restoration: {error}");
        }
    }
}

#[derive(Clone)]
struct SocksState {
    enabled: bool,
    server: String,
    port: u16,
    authenticated: bool,
}

/// Enables the macOS system SOCKS setting only for selected, active network
/// services. The original per-service settings are restored on every exit.
/// Direct mode changes no route and no DNS setting.
#[derive(Default)]
pub struct ProxyGuard {
    endpoint: Option<(String, u16)>,
    originals: HashMap<String, SocksState>,
    active: Vec<String>,
}

impl ProxyGuard {
    pub fn configure(endpoint: &str, physical: &[String]) -> Result<Self> {
        let address: std::net::SocketAddr =
            endpoint.parse().context("invalid local proxy endpoint")?;
        ensure!(
            address.ip().is_loopback() && address.port() > 0,
            "direct proxy is not loopback-only"
        );
        let mut guard = Self {
            endpoint: Some((address.ip().to_string(), address.port())),
            originals: HashMap::new(),
            active: Vec::new(),
        };
        guard.sync(physical)?;
        ensure!(
            !guard.active.is_empty(),
            "no macOS network service matches the selected adapters"
        );
        Ok(guard)
    }

    pub fn sync(&mut self, physical: &[String]) -> Result<()> {
        let services = service_map()?;
        let desired: Vec<String> = physical
            .iter()
            .filter_map(|name| services.get(name).cloned())
            .collect();
        for service in self.active.clone() {
            if !desired.contains(&service) {
                self.restore_service(&service)?;
                self.active.retain(|name| name != &service);
            }
        }
        let (server, port) = self.endpoint.clone().context("proxy endpoint is missing")?;
        let port = port.to_string();
        for service in desired {
            if self.active.contains(&service) {
                continue;
            }
            let state = read_socks(&service)?;
            ensure!(
                !state.authenticated,
                "{service} already uses an authenticated SOCKS proxy; disconnect it before enabling Direct Smart"
            );
            self.originals.entry(service.clone()).or_insert(state);
            run(
                "/usr/sbin/networksetup",
                &["-setsocksfirewallproxy", &service, &server, &port, "off"],
            )?;
            if let Err(error) = run(
                "/usr/sbin/networksetup",
                &["-setsocksfirewallproxystate", &service, "on"],
            ) {
                let _ = self.restore_service(&service);
                return Err(error);
            }
            self.active.push(service);
        }
        Ok(())
    }

    fn restore_service(&self, service: &str) -> Result<()> {
        let state = self
            .originals
            .get(service)
            .context("original SOCKS state is missing")?;
        run(
            "/usr/sbin/networksetup",
            &[
                "-setsocksfirewallproxy",
                service,
                &state.server,
                &state.port.to_string(),
                "off",
            ],
        )?;
        run(
            "/usr/sbin/networksetup",
            &[
                "-setsocksfirewallproxystate",
                service,
                if state.enabled { "on" } else { "off" },
            ],
        )?;
        Ok(())
    }

    pub fn restore(&mut self) -> Vec<String> {
        let mut failures = Vec::new();
        for service in self.active.drain(..).rev().collect::<Vec<_>>() {
            if let Err(error) = self.restore_service(&service) {
                failures.push(error.to_string());
            }
        }
        failures
    }
}

impl Drop for ProxyGuard {
    fn drop(&mut self) {
        for error in self.restore() {
            eprintln!("SOCKS restoration: {error}");
        }
    }
}

fn read_socks(service: &str) -> Result<SocksState> {
    let output = run(
        "/usr/sbin/networksetup",
        &["-getsocksfirewallproxy", service],
    )?;
    let field = |name: &str| {
        output
            .lines()
            .find_map(|line| line.strip_prefix(name).map(str::trim))
            .unwrap_or("")
    };
    Ok(SocksState {
        enabled: field("Enabled:") == "Yes",
        server: field("Server:").to_owned(),
        port: field("Port:").parse().unwrap_or(0),
        authenticated: field("Authenticated Proxy Enabled:") == "1",
    })
}

fn service_map() -> Result<HashMap<String, String>> {
    let output = run("/usr/sbin/networksetup", &["-listnetworkserviceorder"])?;
    let mut result = HashMap::new();
    let mut service: Option<String> = None;
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('(') && !trimmed.starts_with("(Hardware Port:") {
            service = trimmed
                .split_once(')')
                .map(|(_, name)| name.trim().trim_start_matches('*').to_owned());
        } else if let Some(device) = trimmed
            .strip_prefix("(Hardware Port:")
            .and_then(|_| trimmed.split("Device: ").nth(1))
            .and_then(|value| value.strip_suffix(')'))
            && let Some(name) = service.take()
        {
            result.insert(device.to_owned(), name);
        }
    }
    Ok(result)
}

#[cfg(test)]
mod proxy_tests {
    #[test]
    fn service_order_parser_assumptions_match_networksetup_shape() {
        let line = "(Hardware Port: Wi-Fi, Device: en0)";
        assert_eq!(
            line.split("Device: ")
                .nth(1)
                .and_then(|v| v.strip_suffix(')')),
            Some("en0")
        );
    }
}
