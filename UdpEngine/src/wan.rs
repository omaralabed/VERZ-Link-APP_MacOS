//! Nonblocking, interface-pinned UDP sockets. Never use the default route as a WAN substitute.
use std::{
    collections::BTreeMap,
    ffi::CString,
    io,
    net::{Ipv4Addr, SocketAddr, UdpSocket},
    os::fd::AsRawFd,
};
use verz_link_core::transport::WanWriter;

struct Path {
    socket: UdpSocket,
    carrier: bool,
}
pub struct Sockets {
    paths: BTreeMap<u8, Path>,
}
impl Default for Sockets {
    fn default() -> Self {
        Self::new()
    }
}
impl Sockets {
    pub fn new() -> Self {
        Self {
            paths: BTreeMap::new(),
        }
    }
    pub fn add(
        &mut self,
        id: u8,
        interface: &str,
        source: Ipv4Addr,
        gateway: SocketAddr,
    ) -> io::Result<()> {
        if id == 0 || !gateway.is_ipv4() || source.is_unspecified() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "concrete IPv4 source, gateway and nonzero link ID required",
            ));
        }
        let name = CString::new(interface).map_err(io::Error::other)?;
        // SAFETY: name is NUL-terminated for the duration of the call.
        let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
        if index == 0 {
            return Err(io::Error::last_os_error());
        }
        let socket = UdpSocket::bind((source, 0))?;
        #[cfg(target_os = "macos")]
        // SAFETY: index points to an initialized u32 with the correct option size.
        let rc = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::IPPROTO_IP,
                libc::IP_BOUND_IF,
                (&index as *const u32).cast(),
                std::mem::size_of_val(&index) as libc::socklen_t,
            )
        };
        #[cfg(target_os = "linux")]
        // SAFETY: the interface name buffer is live and includes its terminating NUL.
        let rc = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_BINDTODEVICE,
                name.as_ptr().cast(),
                name.as_bytes_with_nul().len() as libc::socklen_t,
            )
        };
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        compile_error!("WAN socket binding has not been implemented for this platform");
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        socket.connect(gateway)?; // Kernel filters packets from other remote endpoints.
        socket.set_nonblocking(true)?;
        self.paths.insert(
            id,
            Path {
                socket,
                carrier: true,
            },
        );
        Ok(())
    }
    pub fn remove(&mut self, id: u8) {
        self.paths.remove(&id);
    }
    /// Bounded receive work per path prevents a busy WAN starving another one.
    #[cfg(test)]
    pub fn receive(&self, mut accept: impl FnMut(u8, &[u8])) -> io::Result<usize> {
        self.receive_sized(
            verz_link_core::HEADER + verz_link_core::MAX_PAYLOAD + verz_link_core::TAG + 1,
            &mut accept,
        )
    }
    pub fn receive_sized(
        &self,
        size: usize,
        mut accept: impl FnMut(u8, &[u8]),
    ) -> io::Result<usize> {
        let mut buffer = vec![0u8; size];
        let mut count = 0;
        let mut last_error = None;
        for (&id, path) in &self.paths {
            for _ in 0..64 {
                match path.socket.recv(&mut buffer) {
                    Ok(n) => {
                        accept(id, &buffer[..n]);
                        count += 1;
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    // A dead adapter must never prevent draining surviving adapters.
                    Err(e) => {
                        last_error = Some(e);
                        break;
                    }
                }
            }
        }
        if count == 0
            && let Some(error) = last_error
        {
            Err(error)
        } else {
            Ok(count)
        }
    }
}
impl WanWriter for Sockets {
    fn carrier(&self, id: u8) -> bool {
        self.paths.get(&id).is_some_and(|p| p.carrier)
    }
    fn send(&mut self, id: u8, wire: &[u8]) -> io::Result<()> {
        let path = self
            .paths
            .get(&id)
            .filter(|p| p.carrier)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "WAN unavailable"))?;
        let n = path.socket.send(wire)?;
        if n != wire.len() {
            return Err(io::Error::new(io::ErrorKind::WriteZero, "short UDP send"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn actual_udp_uses_bound_interface_and_removal_closes_path() {
        let receiver = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        receiver
            .set_read_timeout(Some(std::time::Duration::from_secs(1)))
            .unwrap();
        let mut paths = Sockets::new();
        let iface = if cfg!(target_os = "macos") {
            "lo0"
        } else {
            "lo"
        };
        paths
            .add(
                1,
                iface,
                Ipv4Addr::LOCALHOST,
                receiver.local_addr().unwrap(),
            )
            .unwrap();
        paths.send(1, b"actual UDP").unwrap();
        let mut b = [0; 64];
        let (n, from) = receiver.recv_from(&mut b).unwrap();
        assert_eq!(&b[..n], b"actual UDP");
        receiver.send_to(b"reply", from).unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
        let mut received = false;
        while !received && std::time::Instant::now() < deadline {
            paths
                .receive(|id, wire| {
                    assert_eq!(id, 1);
                    assert_eq!(wire, b"reply");
                    received = true;
                })
                .unwrap();
            std::thread::yield_now();
        }
        assert!(received);
        paths.remove(1);
        assert!(paths.send(1, b"closed").is_err());
    }
}
