//! Read-only TCP delivery feedback. Never change OS congestion control or
//! count socket-buffer acceptance as network delivery.
use std::os::fd::RawFd;

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Snapshot {
    pub acknowledged: u64,
    pub queued: u64,
    pub retransmitted: u64,
    pub rtt_us: u64,
}

#[cfg(target_os = "macos")]
pub(crate) fn snapshot(fd: RawFd, written: u64) -> Option<Snapshot> {
    // SDK netinet/tcp.h ABI. libc 0.2.189 incorrectly expands the single
    // 32-bit TFO bitfield into fifteen u32s, shifting every byte counter.
    // https://github.com/apple-oss-distributions/xnu/blob/main/bsd/netinet/tcp.h
    #[repr(C)]
    #[derive(Default)]
    struct ConnectionInfo {
        state: u8,
        snd_scale: u8,
        rcv_scale: u8,
        pad: u8,
        options: u32,
        flags: u32,
        rto: u32,
        maxseg: u32,
        ssthresh: u32,
        cwnd: u32,
        snd_wnd: u32,
        snd_sbbytes: u32,
        rcv_wnd: u32,
        rttcur: u32,
        srtt: u32,
        rttvar: u32,
        tfo_bits: u32,
        txpackets: u64,
        txbytes: u64,
        retransmitted: u64,
        rxpackets: u64,
        rxbytes: u64,
        out_of_order: u64,
        retransmitted_packets: u64,
    }
    const _: () = assert!(std::mem::offset_of!(ConnectionInfo, txpackets) == 56);
    const _: () = assert!(std::mem::size_of::<ConnectionInfo>() == 112);
    let mut info = ConnectionInfo::default();
    let mut size = std::mem::size_of_val(&info) as libc::socklen_t;
    // SAFETY: the live borrowed fd is never retained, and the output buffer
    // and length match the SDK structure, including its packed bitfield.
    let result = unsafe {
        libc::getsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_CONNECTION_INFO,
            (&mut info as *mut ConnectionInfo).cast(),
            &mut size,
        )
    };
    if result != 0 || size < 80 || !matches!(info.state, 4..=10) {
        // A reset can discard the send buffer. Never interpret that as ACKs.
        return None;
    }
    Some(Snapshot {
        // Darwin explicitly includes both unsent and in-flight data here.
        // This is a lower bound; a reset/early close may leave bytes uncounted.
        acknowledged: written.saturating_sub(u64::from(info.snd_sbbytes)),
        queued: u64::from(info.snd_sbbytes),
        retransmitted: info.retransmitted,
        rtt_us: u64::from(info.rttcur.max(info.srtt)) * 1_000,
    })
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
pub(crate) fn snapshot(fd: RawFd, written: u64) -> Option<Snapshot> {
    // SAFETY: tcp_info is a plain C output structure, zero is valid for it.
    let mut info: libc::tcp_info = unsafe { std::mem::zeroed() };
    let mut size = std::mem::size_of_val(&info) as libc::socklen_t;
    // SAFETY: valid output buffer; getsockopt reports the fields available on
    // this kernel. Refuse short/old layouts rather than inventing feedback.
    let result = unsafe {
        libc::getsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_INFO,
            (&mut info as *mut libc::tcp_info).cast(),
            &mut size,
        )
    };
    if result != 0 || size < 224 {
        return None;
    }
    let acknowledged = info.tcpi_bytes_acked.saturating_sub(1).min(written); // SYN
    Some(Snapshot {
        acknowledged,
        queued: written.saturating_sub(acknowledged),
        retransmitted: info.tcpi_bytes_retrans,
        rtt_us: u64::from(info.tcpi_rtt),
    })
}

#[cfg(not(any(target_os = "macos", all(target_os = "linux", target_env = "gnu"))))]
pub(crate) fn snapshot(_fd: RawFd, _written: u64) -> Option<Snapshot> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
    };

    #[tokio::test]
    async fn native_counters_observe_delivery_and_never_exceed_written() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut sender = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (mut receiver, _) = listener.accept().await.unwrap();
        assert_eq!(snapshot(sender.as_raw_fd(), 0).unwrap().acknowledged, 0);
        sender.write_all(&[42; 8192]).await.unwrap();
        receiver.read_exact(&mut [0; 8192]).await.unwrap();
        for _ in 0..50 {
            let sample = snapshot(sender.as_raw_fd(), 8192).unwrap();
            assert!(sample.acknowledged <= 8192);
            assert_eq!(sample.acknowledged + sample.queued, 8192);
            if sample.acknowledged == 8192 {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!("loopback data was not acknowledged");
    }
}
