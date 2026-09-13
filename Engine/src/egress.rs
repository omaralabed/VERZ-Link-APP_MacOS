//! Server-only batching of already-encrypted TCP carrier datagrams.
//!
//! UDP_SEGMENT does not change the wire protocol: Linux splits a batch back
//! into the original datagrams before delivery. We batch only a consecutive
//! run already released by the scheduler, never wait for more packets, and
//! never enable offload on the socket globally. UDP/media traffic is excluded.
//! See https://man7.org/linux/man-pages/man7/udp.7.html (UDP_SEGMENT).
use serde::Serialize;
use std::{io, net::SocketAddr};
use tokio::net::UdpSocket;

pub const MAX_BATCH_PACKETS: usize = 32;
const MAX_BATCH_BYTES: usize = 48 * 1024;

pub struct Datagram {
    pub address: SocketAddr,
    pub path: usize,
    pub bytes: Vec<u8>,
    pub tcp_data: bool,
}

pub struct SendFailure {
    pub path: usize,
    pub packets: usize,
    pub error: io::Error,
}

#[derive(Default, Serialize)]
pub struct SendCounters {
    pub sent_datagrams: u64,
    pub sent_bytes: u64,
    pub single_calls: u64,
    pub gso_calls: u64,
    pub gso_batches: u64,
    pub gso_datagrams: u64,
    pub gso_fallbacks: u64,
    pub would_block_datagrams: u64,
    pub failed_datagrams: u64,
}

#[derive(Serialize)]
pub struct Egress {
    pub gso_enabled: bool,
    pub counters: SendCounters,
}

impl Default for Egress {
    fn default() -> Self {
        Self {
            gso_enabled: cfg!(target_os = "linux"),
            counters: SendCounters::default(),
        }
    }
}

impl Egress {
    pub fn send(&mut self, socket: &UdpSocket, packets: &[Datagram]) -> Vec<SendFailure> {
        self.send_with(packets, |batch, gso| {
            if gso {
                send_segmented(socket, batch)
            } else {
                socket.try_send_to(&batch[0].bytes, batch[0].address)
            }
        })
    }

    fn send_with(
        &mut self,
        packets: &[Datagram],
        mut send: impl FnMut(&[Datagram], bool) -> io::Result<usize>,
    ) -> Vec<SendFailure> {
        let mut failures = Vec::new();
        let mut start = 0;
        while start < packets.len() {
            let count = if self.gso_enabled {
                group_len(&packets[start..])
            } else {
                1
            };
            let batch = &packets[start..start + count];
            if count > 1 {
                self.counters.gso_calls += 1;
                let result = send(batch, true);
                if result.as_ref().is_err_and(offload_rejected) {
                    // An unsupported/invalid offload request has not sent any
                    // datagrams. Retry the same ciphertext individually; no
                    // nonce allocation, timing change or application restart.
                    self.counters.gso_fallbacks += 1;
                    self.gso_enabled = false;
                    for packet in batch {
                        self.counters.single_calls += 1;
                        let one = std::slice::from_ref(packet);
                        self.account(one, false, send(one, false), &mut failures);
                    }
                } else {
                    self.account(batch, true, result, &mut failures);
                }
            } else {
                self.counters.single_calls += 1;
                self.account(batch, false, send(batch, false), &mut failures);
            }
            start += count;
        }
        failures
    }

    fn account(
        &mut self,
        packets: &[Datagram],
        gso: bool,
        result: io::Result<usize>,
        failures: &mut Vec<SendFailure>,
    ) {
        let bytes: usize = packets.iter().map(|p| p.bytes.len()).sum();
        let result = result.and_then(|sent| {
            if sent == bytes {
                Ok(())
            } else {
                Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "short datagram batch send",
                ))
            }
        });
        match result {
            Ok(()) => {
                self.counters.sent_datagrams += packets.len() as u64;
                self.counters.sent_bytes += bytes as u64;
                if gso {
                    self.counters.gso_batches += 1;
                    self.counters.gso_datagrams += packets.len() as u64;
                }
            }
            Err(error) => {
                if error.kind() == io::ErrorKind::WouldBlock {
                    self.counters.would_block_datagrams += packets.len() as u64;
                } else {
                    self.counters.failed_datagrams += packets.len() as u64;
                }
                // A run always belongs to one destination AND path. Existing
                // scheduler recovery owns retries, including blocked batches.
                failures.push(SendFailure {
                    path: packets[0].path,
                    packets: packets.len(),
                    error,
                });
            }
        }
    }
}

fn group_len(packets: &[Datagram]) -> usize {
    let first = &packets[0];
    if !first.tcp_data || first.bytes.is_empty() || first.bytes.len() > MAX_BATCH_BYTES / 2 {
        return 1;
    }
    let limit = MAX_BATCH_PACKETS.min(MAX_BATCH_BYTES / first.bytes.len());
    packets
        .iter()
        .take(limit)
        .take_while(|p| {
            p.tcp_data
                && p.path == first.path
                && p.address == first.address
                && p.bytes.len() == first.bytes.len()
        })
        .count()
}

fn offload_rejected(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::Unsupported
        || matches!(
            error.raw_os_error(),
            Some(libc::EINVAL | libc::ENOPROTOOPT | libc::EOPNOTSUPP | libc::EMSGSIZE | libc::EIO)
        )
}

#[cfg(not(target_os = "linux"))]
fn send_segmented(_socket: &UdpSocket, _packets: &[Datagram]) -> io::Result<usize> {
    Err(io::ErrorKind::Unsupported.into())
}

#[cfg(target_os = "linux")]
fn send_segmented(socket: &UdpSocket, packets: &[Datagram]) -> io::Result<usize> {
    use std::{mem, os::fd::AsRawFd, ptr};
    // Checked even in release: malformed batches must never merge or split
    // ciphertext at the wrong byte boundaries.
    if packets.len() < 2 || group_len(packets) != packets.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid GSO group",
        ));
    }
    let mut iov: Vec<libc::iovec> = packets
        .iter()
        .map(|p| libc::iovec {
            iov_base: p.bytes.as_ptr() as *mut libc::c_void,
            iov_len: p.bytes.len(),
        })
        .collect();
    // All storage remains alive and stationary through this synchronous,
    // nonblocking syscall. The OS only reads the payloads and address.
    let mut address: libc::sockaddr_storage = unsafe { mem::zeroed() };
    let address_len = match packets[0].address {
        SocketAddr::V4(ip) => {
            let value = libc::sockaddr_in {
                sin_family: libc::AF_INET as _,
                sin_port: ip.port().to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(ip.ip().octets()),
                },
                sin_zero: [0; 8],
            };
            unsafe {
                ptr::write((&mut address as *mut libc::sockaddr_storage).cast(), value);
            }
            mem::size_of::<libc::sockaddr_in>()
        }
        SocketAddr::V6(ip) => {
            let value = libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as _,
                sin6_port: ip.port().to_be(),
                sin6_flowinfo: ip.flowinfo().to_be(),
                sin6_scope_id: ip.scope_id(),
                sin6_addr: libc::in6_addr {
                    s6_addr: ip.ip().octets(),
                },
            };
            unsafe {
                ptr::write((&mut address as *mut libc::sockaddr_storage).cast(), value);
            }
            mem::size_of::<libc::sockaddr_in6>()
        }
    };
    // cmsghdr alignment is native word alignment, not byte alignment.
    let mut control = [0usize; 8];
    let space = unsafe { libc::CMSG_SPACE(mem::size_of::<u16>() as _) } as usize;
    assert!(space <= mem::size_of_val(&control));
    let mut message: libc::msghdr = unsafe { mem::zeroed() };
    message.msg_name = (&mut address as *mut libc::sockaddr_storage).cast();
    message.msg_namelen = address_len as _;
    message.msg_iov = iov.as_mut_ptr();
    message.msg_iovlen = iov.len();
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = space;
    unsafe {
        let header = libc::CMSG_FIRSTHDR(&message);
        assert!(!header.is_null());
        (*header).cmsg_level = libc::IPPROTO_UDP;
        (*header).cmsg_type = libc::UDP_SEGMENT;
        (*header).cmsg_len = libc::CMSG_LEN(mem::size_of::<u16>() as _) as usize;
        ptr::write_unaligned(
            libc::CMSG_DATA(header).cast::<u16>(),
            packets[0].bytes.len() as u16,
        );
    }
    socket.try_io(tokio::io::Interest::WRITABLE, || {
        let sent = unsafe {
            libc::sendmsg(
                socket.as_raw_fd(),
                &message,
                libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
            )
        };
        if sent < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(sent as usize)
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn packet(id: u8, size: usize) -> Datagram {
        Datagram {
            address: "127.0.0.1:18000".parse().unwrap(),
            path: 0,
            bytes: vec![id; size],
            tcp_data: true,
        }
    }
    fn enabled() -> Egress {
        Egress {
            gso_enabled: true,
            counters: SendCounters::default(),
        }
    }

    #[test]
    fn preserves_every_byte_and_order_with_bounded_groups() {
        let packets: Vec<_> = (0..100).map(|n| packet(n, 1343)).collect();
        let mut sender = enabled();
        let mut ids = Vec::new();
        let errors = sender.send_with(&packets, |batch, gso| {
            assert!(gso);
            assert!(batch.len() <= MAX_BATCH_PACKETS);
            assert!(batch.iter().map(|p| p.bytes.len()).sum::<usize>() <= MAX_BATCH_BYTES);
            for p in batch {
                assert!(p.bytes.iter().all(|b| *b == p.bytes[0]));
                ids.push(p.bytes[0]);
            }
            Ok(batch.iter().map(|p| p.bytes.len()).sum())
        });
        assert!(errors.is_empty());
        assert_eq!(ids, (0..100).collect::<Vec<u8>>());
        assert_eq!(sender.counters.sent_bytes, 134300);
        assert_eq!(sender.counters.gso_batches, 4);
        assert_eq!(sender.counters.gso_datagrams, 100);
    }

    #[test]
    fn boundaries_do_not_cross_paths_destinations_sizes_or_media() {
        let mut packets: Vec<_> = (0..8).map(|n| packet(n, 1200)).collect();
        packets[2].path = 1;
        packets[3].address = "127.0.0.1:18001".parse().unwrap();
        packets[4].bytes.push(4);
        packets[5].tcp_data = false;
        let mut groups = Vec::new();
        enabled().send_with(&packets, |batch, gso| {
            groups.push((batch.iter().map(|p| p.bytes[0]).collect::<Vec<_>>(), gso));
            Ok(batch.iter().map(|p| p.bytes.len()).sum())
        });
        assert_eq!(
            groups,
            vec![
                (vec![0, 1], true),
                (vec![2], false),
                (vec![3], false),
                (vec![4], false),
                (vec![5], false),
                (vec![6, 7], true)
            ]
        );
    }

    #[test]
    fn unsupported_offload_falls_back_once_without_duplicates_or_nonce_changes() {
        let packets: Vec<_> = (0..70).map(|n| packet(n, 1300)).collect();
        let mut sender = enabled();
        let mut seen = Vec::new();
        let errors = sender.send_with(&packets, |batch, gso| {
            if gso {
                return Err(io::ErrorKind::Unsupported.into());
            }
            seen.push(batch[0].bytes.clone());
            Ok(batch[0].bytes.len())
        });
        assert!(errors.is_empty());
        assert_eq!(
            seen,
            packets.iter().map(|p| p.bytes.clone()).collect::<Vec<_>>()
        );
        assert!(!sender.gso_enabled);
        assert_eq!(sender.counters.gso_calls, 1);
        assert_eq!(sender.counters.gso_fallbacks, 1);
        assert_eq!(sender.counters.single_calls, 70);
    }

    #[test]
    fn blocked_and_short_sends_are_not_reported_as_delivery_or_retried() {
        for kind in [io::ErrorKind::WouldBlock, io::ErrorKind::NetworkUnreachable] {
            let packets: Vec<_> = (0..4).map(|n| packet(n, 1300)).collect();
            let mut sender = enabled();
            let errors = sender.send_with(&packets, |_, _| Err(kind.into()));
            assert_eq!(errors.len(), 1);
            assert_eq!(errors[0].packets, 4);
            assert_eq!(errors[0].error.kind(), kind);
            assert_eq!(sender.counters.sent_datagrams, 0);
            assert!(sender.gso_enabled);
            assert_eq!(sender.counters.single_calls, 0);
        }
        let mut sender = enabled();
        assert_eq!(
            sender.send_with(&[packet(0, 1200), packet(1, 1200)], |_, _| Ok(1200))[0]
                .error
                .kind(),
            io::ErrorKind::WriteZero
        );
        assert_eq!(sender.counters.sent_datagrams, 0);
        assert_eq!(sender.counters.gso_calls, 1);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn linux_gso_preserves_datagrams_and_destination_over_real_sockets() {
        use std::time::Duration;
        for bind in ["127.0.0.1:0", "[::1]:0"] {
            let receiver = UdpSocket::bind(bind).await.unwrap();
            let other = UdpSocket::bind(bind).await.unwrap();
            let socket = UdpSocket::bind(bind).await.unwrap();
            socket.writable().await.unwrap();
            let mut packets: Vec<_> = (0..32).map(|n| packet(n, 1343)).collect();
            for p in &mut packets {
                p.address = receiver.local_addr().unwrap();
            }
            let mut sender = enabled();
            assert!(sender.send(&socket, &packets).is_empty());
            assert_eq!(
                sender.counters.gso_batches, 1,
                "test requires actual kernel GSO, not fallback"
            );
            let mut buf = [0; 2048];
            for expected in &packets {
                let (size, address) =
                    tokio::time::timeout(Duration::from_secs(1), receiver.recv_from(&mut buf))
                        .await
                        .unwrap()
                        .unwrap();
                assert_eq!(address, socket.local_addr().unwrap());
                assert_eq!(&buf[..size], expected.bytes.as_slice());
            }
            assert!(
                tokio::time::timeout(Duration::from_millis(10), other.recv_from(&mut buf))
                    .await
                    .is_err()
            );
        }
    }
}
