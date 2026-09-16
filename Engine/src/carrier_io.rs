//! Bounded carrier-socket receive batching for the Linux TCP relay.
//!
//! `recvmmsg(2)` changes only how already-separated UDP datagrams cross the
//! userspace boundary. It does not coalesce wire packets, wait for a full
//! batch, or alter packet order. The non-Linux and disabled paths retain one
//! ordinary Tokio `recv_from` per call.

use serde::Serialize;
use std::{io, net::SocketAddr};
use tokio::net::UdpSocket;

pub const MAX_RECEIVE_BATCH: usize = 64;

#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct ReceiveSnapshot {
    pub calls: u64,
    pub datagrams: u64,
    pub max_batch: usize,
    pub batching_enabled: bool,
}

#[cfg(target_os = "linux")]
pub struct ReceiveBatch {
    buffers: Vec<Box<[u8]>>,
    addresses: Box<[libc::sockaddr_storage]>,
    iovecs: Box<[libc::iovec]>,
    messages: Box<[libc::mmsghdr]>,
    single: Option<(usize, SocketAddr)>,
    counters: ReceiveSnapshot,
}

#[cfg(target_os = "linux")]
impl ReceiveBatch {
    pub fn new(datagram_bytes: usize, batching_enabled: bool) -> Self {
        assert!(datagram_bytes > 0);
        let buffers = (0..MAX_RECEIVE_BATCH)
            .map(|_| vec![0; datagram_bytes].into_boxed_slice())
            .collect();
        let addresses = (0..MAX_RECEIVE_BATCH)
            .map(|_| unsafe { std::mem::zeroed() })
            .collect::<Vec<libc::sockaddr_storage>>()
            .into_boxed_slice();
        let iovecs = (0..MAX_RECEIVE_BATCH)
            .map(|_| unsafe { std::mem::zeroed() })
            .collect::<Vec<libc::iovec>>()
            .into_boxed_slice();
        let messages = (0..MAX_RECEIVE_BATCH)
            .map(|_| unsafe { std::mem::zeroed() })
            .collect::<Vec<libc::mmsghdr>>()
            .into_boxed_slice();
        let mut batch = Self {
            buffers,
            addresses,
            iovecs,
            messages,
            single: None,
            counters: ReceiveSnapshot {
                batching_enabled,
                ..Default::default()
            },
        };
        batch.prepare();
        batch
    }

    fn prepare(&mut self) {
        self.single = None;
        for index in 0..MAX_RECEIVE_BATCH {
            self.iovecs[index].iov_base = self.buffers[index].as_mut_ptr().cast();
            self.iovecs[index].iov_len = self.buffers[index].len();
            self.messages[index].msg_len = 0;
            let header = &mut self.messages[index].msg_hdr;
            header.msg_name = (&mut self.addresses[index] as *mut libc::sockaddr_storage).cast();
            header.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as _;
            header.msg_iov = &mut self.iovecs[index];
            header.msg_iovlen = 1;
            header.msg_control = std::ptr::null_mut();
            header.msg_controllen = 0;
            header.msg_flags = 0;
        }
    }

    pub async fn recv(&mut self, socket: &UdpSocket) -> io::Result<usize> {
        self.prepare();
        let count = if !self.counters.batching_enabled {
            let (length, address) = socket.recv_from(&mut self.buffers[0]).await?;
            self.single = Some((length, address));
            1
        } else {
            use std::os::fd::AsRawFd;
            let fd = socket.as_raw_fd();
            socket
                .async_io(tokio::io::Interest::READABLE, || {
                    let received = unsafe {
                        libc::recvmmsg(
                            fd,
                            self.messages.as_mut_ptr(),
                            MAX_RECEIVE_BATCH as _,
                            libc::MSG_DONTWAIT | libc::MSG_TRUNC,
                            std::ptr::null_mut(),
                        )
                    };
                    if received < 0 {
                        Err(io::Error::last_os_error())
                    } else {
                        Ok(received as usize)
                    }
                })
                .await?
        };
        self.counters.calls += 1;
        self.counters.datagrams += count as u64;
        self.counters.max_batch = self.counters.max_batch.max(count);
        Ok(count)
    }

    pub fn datagram(&self, index: usize) -> Option<(&[u8], SocketAddr)> {
        if let Some((length, address)) = self.single {
            return (index == 0 && length <= self.buffers[0].len())
                .then(|| (&self.buffers[0][..length], address));
        }
        let message = self.messages.get(index)?;
        let length = message.msg_len as usize;
        if length > self.buffers[index].len() {
            return None;
        }
        let address = socket_address(&self.addresses[index], message.msg_hdr.msg_namelen)?;
        Some((&self.buffers[index][..length], address))
    }

    pub fn snapshot(&self) -> ReceiveSnapshot {
        self.counters
    }
}

#[cfg(target_os = "linux")]
fn socket_address(storage: &libc::sockaddr_storage, length: libc::socklen_t) -> Option<SocketAddr> {
    match storage.ss_family as libc::c_int {
        libc::AF_INET if length as usize >= std::mem::size_of::<libc::sockaddr_in>() => {
            let address =
                unsafe { &*(storage as *const libc::sockaddr_storage).cast::<libc::sockaddr_in>() };
            Some(SocketAddr::new(
                std::net::Ipv4Addr::from(address.sin_addr.s_addr.to_ne_bytes()).into(),
                u16::from_be(address.sin_port),
            ))
        }
        libc::AF_INET6 if length as usize >= std::mem::size_of::<libc::sockaddr_in6>() => {
            let address = unsafe {
                &*(storage as *const libc::sockaddr_storage).cast::<libc::sockaddr_in6>()
            };
            Some(SocketAddr::new(
                std::net::Ipv6Addr::from(address.sin6_addr.s6_addr).into(),
                u16::from_be(address.sin6_port),
            ))
        }
        _ => None,
    }
}

#[cfg(not(target_os = "linux"))]
pub struct ReceiveBatch {
    buffer: Vec<u8>,
    received: Option<(usize, SocketAddr)>,
    counters: ReceiveSnapshot,
}

#[cfg(not(target_os = "linux"))]
impl ReceiveBatch {
    pub fn new(datagram_bytes: usize, _batching_enabled: bool) -> Self {
        Self {
            buffer: vec![0; datagram_bytes],
            received: None,
            counters: ReceiveSnapshot::default(),
        }
    }

    pub async fn recv(&mut self, socket: &UdpSocket) -> io::Result<usize> {
        self.received = Some(socket.recv_from(&mut self.buffer).await?);
        self.counters.calls += 1;
        self.counters.datagrams += 1;
        self.counters.max_batch = 1;
        Ok(1)
    }

    pub fn datagram(&self, index: usize) -> Option<(&[u8], SocketAddr)> {
        let (length, address) = self.received?;
        (index == 0).then(|| (&self.buffer[..length], address))
    }

    pub fn snapshot(&self) -> ReceiveSnapshot {
        self.counters
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn receives_ordered_datagrams_without_waiting_for_a_full_batch() {
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        for value in 0..16u8 {
            sender
                .send_to(&[value; 8], receiver.local_addr().unwrap())
                .await
                .unwrap();
        }
        let mut batch = ReceiveBatch::new(64, true);
        let count = batch.recv(&receiver).await.unwrap();
        assert!((1..=16).contains(&count));
        for index in 0..count {
            assert_eq!(batch.datagram(index).unwrap().0, &[index as u8; 8]);
        }
        assert_eq!(batch.snapshot().datagrams, count as u64);
    }

    #[tokio::test]
    async fn disabled_batching_uses_one_datagram_per_call() {
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        sender
            .send_to(b"one", receiver.local_addr().unwrap())
            .await
            .unwrap();
        sender
            .send_to(b"two", receiver.local_addr().unwrap())
            .await
            .unwrap();
        let mut batch = ReceiveBatch::new(64, false);
        assert_eq!(batch.recv(&receiver).await.unwrap(), 1);
        assert_eq!(batch.datagram(0).unwrap().0, b"one");
        assert_eq!(batch.recv(&receiver).await.unwrap(), 1);
        assert_eq!(batch.datagram(0).unwrap().0, b"two");
        assert!(!batch.snapshot().batching_enabled);
    }
}
