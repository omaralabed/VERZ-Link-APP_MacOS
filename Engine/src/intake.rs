//! Bounded server-side TUN intake, independent of encryption/scheduler work.
//!
//! This is download intake (Linux -> relay), not the writer used for uploads.
//! A full userspace queue backpressures the reader; it never silently drops a
//! packet. Kernel-ring drops remain possible and are reported separately.

use serde::Serialize;
use std::{
    future::Future,
    io,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicU64, AtomicUsize, Ordering::Relaxed},
    },
    time::Instant,
};
use tokio::{sync::mpsc, task::JoinHandle};
use tun_rs::AsyncDevice;

pub const INTAKE_PACKETS: usize = 1024;
pub const INTAKE_BATCH: usize = 64;
pub const KERNEL_RING_PACKETS: u32 = 2048;

pub struct IntakePacket {
    pub bytes: Vec<u8>,
    admitted: Instant,
}

#[derive(Default)]
struct Counters {
    packets: AtomicU64,
    bytes: AtomicU64,
    oversize_drops: AtomicU64,
    queue_waits: AtomicU64,
    peak_packets: AtomicUsize,
}

#[derive(Serialize)]
pub struct IntakeSnapshot {
    pub packets: u64,
    pub bytes: u64,
    pub oversize_drops: u64,
    pub queue_waits: u64,
    pub queued_packets: usize,
    pub peak_queued_packets: usize,
    pub capacity_packets: usize,
    pub max_queue_delay_us: u64,
}

pub struct TunIntake {
    receiver: mpsc::Receiver<IntakePacket>,
    counters: Arc<Counters>,
    max_queue_delay_us: u64,
    pub task: JoinHandle<io::Result<()>>,
}

trait PacketSource: Send + Sync + 'static {
    fn recv(&self, buffer: &mut [u8]) -> impl Future<Output = io::Result<usize>> + Send;
}

impl PacketSource for AsyncDevice {
    async fn recv(&self, buffer: &mut [u8]) -> io::Result<usize> {
        AsyncDevice::recv(self, buffer).await
    }
}

impl TunIntake {
    pub fn new(tun: Arc<AsyncDevice>, mtu: usize) -> Self {
        Self::from_source(tun, mtu)
    }

    fn from_source<S: PacketSource>(source: Arc<S>, mtu: usize) -> Self {
        let (sender, receiver) = mpsc::channel(INTAKE_PACKETS);
        let counters = Arc::new(Counters::default());
        let task = tokio::spawn(read_packets(source, mtu, sender, counters.clone()));
        Self {
            receiver,
            counters,
            max_queue_delay_us: 0,
            task,
        }
    }

    /// Cancel safe: packets are removed only when recv_many returns Ready.
    /// Never waits for a full batch, so sparse traffic has no batching timer.
    pub async fn recv_batch(&mut self, packets: &mut Vec<IntakePacket>) -> usize {
        let count = self.receiver.recv_many(packets, INTAKE_BATCH).await;
        for packet in &packets[packets.len() - count..] {
            self.max_queue_delay_us = self
                .max_queue_delay_us
                .max(packet.admitted.elapsed().as_micros().min(u64::MAX as u128) as u64);
        }
        count
    }

    pub fn snapshot(&self) -> IntakeSnapshot {
        IntakeSnapshot {
            packets: self.counters.packets.load(Relaxed),
            bytes: self.counters.bytes.load(Relaxed),
            oversize_drops: self.counters.oversize_drops.load(Relaxed),
            queue_waits: self.counters.queue_waits.load(Relaxed),
            queued_packets: self.receiver.len(),
            peak_queued_packets: self.counters.peak_packets.load(Relaxed),
            capacity_packets: INTAKE_PACKETS,
            max_queue_delay_us: self.max_queue_delay_us,
        }
    }
}

impl Drop for TunIntake {
    fn drop(&mut self) {
        // Covers normal shutdown, startup failure and server-loop errors.
        // No blocking thread or detached reader survives its owner.
        self.task.abort();
    }
}

async fn read_packets<S: PacketSource>(
    source: Arc<S>,
    mtu: usize,
    sender: mpsc::Sender<IntakePacket>,
    counters: Arc<Counters>,
) -> io::Result<()> {
    // One scratch buffer, not one maximum-IP allocation per queued packet.
    // Read the whole IP packet so an oversized packet cannot be truncated
    // into a seemingly valid, corrupted datagram.
    let mut buffer = vec![0u8; 65536];
    let mut turn_packets = 0;
    loop {
        let permit = match sender.try_reserve() {
            Ok(permit) => permit,
            Err(mpsc::error::TrySendError::Closed(_)) => return Ok(()),
            Err(mpsc::error::TrySendError::Full(_)) => {
                counters.queue_waits.fetch_add(1, Relaxed);
                match sender.reserve().await {
                    Ok(permit) => permit,
                    Err(_) => return Ok(()),
                }
            }
        };
        let length = match source.recv(&mut buffer).await {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            result => result?,
        };
        if length == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "TUN intake ended",
            ));
        }
        if length > mtu {
            counters.oversize_drops.fetch_add(1, Relaxed);
        } else {
            let packet = IntakePacket {
                bytes: buffer[..length].to_vec(),
                admitted: Instant::now(),
            };
            counters.packets.fetch_add(1, Relaxed);
            counters.bytes.fetch_add(length as u64, Relaxed);
            counters
                .peak_packets
                .fetch_max(INTAKE_PACKETS - sender.capacity(), Relaxed);
            permit.send(packet);
        }
        turn_packets += 1;
        if turn_packets == INTAKE_BATCH {
            // Bound this task's uninterrupted work even on a one-vCPU relay.
            // Scheduling, ACKs, uploads and timers still get CPU time.
            tokio::task::yield_now().await;
            turn_packets = 0;
        }
    }
}

#[derive(Default, Serialize)]
pub struct KernelTxSnapshot {
    pub tx_dropped: Option<u64>,
    pub tx_dropped_since_start: Option<u64>,
    pub tx_dropped_since_report: Option<u64>,
    pub tx_queue_packets: Option<u64>,
}

pub struct KernelTxMonitor {
    root: PathBuf,
    baseline: Option<u64>,
    previous: Option<u64>,
}

impl KernelTxMonitor {
    pub fn new(interface: &str) -> io::Result<Self> {
        // A kernel interface name, never a path supplied for arbitrary reads.
        if interface.is_empty()
            || interface.len() >= 16
            || !interface
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid TUN interface name",
            ));
        }
        let root = PathBuf::from("/sys/class/net").join(interface);
        let baseline = read_counter(root.join("statistics/tx_dropped"));
        Ok(Self {
            root,
            baseline,
            previous: baseline,
        })
    }

    pub fn snapshot(&mut self) -> KernelTxSnapshot {
        let current = read_counter(self.root.join("statistics/tx_dropped"));
        let mut sample = self.observe(current);
        sample.tx_queue_packets = read_counter(self.root.join("tx_queue_len"));
        sample
    }

    fn observe(&mut self, current: Option<u64>) -> KernelTxSnapshot {
        let since_report = current
            .zip(self.previous)
            .and_then(|(c, p)| c.checked_sub(p));
        // Interface replacement/counter reset must not wrap or report a false
        // zero-loss interval. A missing sysfs statistic is null, not zero.
        if let Some(current) = current {
            if self.baseline.is_none_or(|b| current < b)
                || self.previous.is_some_and(|p| current < p)
            {
                self.baseline = Some(current);
            }
        }
        self.previous = current;
        KernelTxSnapshot {
            tx_dropped: current,
            tx_dropped_since_start: current
                .zip(self.baseline)
                .and_then(|(c, b)| c.checked_sub(b)),
            tx_dropped_since_report: since_report,
            tx_queue_packets: None,
        }
    }
}

fn read_counter(path: PathBuf) -> Option<u64> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::{sync::Mutex, time::timeout};

    struct FakeSource(Mutex<mpsc::Receiver<io::Result<Vec<u8>>>>);
    impl PacketSource for FakeSource {
        async fn recv(&self, buffer: &mut [u8]) -> io::Result<usize> {
            let packet = self
                .0
                .lock()
                .await
                .recv()
                .await
                .ok_or(io::ErrorKind::UnexpectedEof)??;
            buffer[..packet.len()].copy_from_slice(&packet);
            Ok(packet.len())
        }
    }

    fn fake() -> (mpsc::Sender<io::Result<Vec<u8>>>, TunIntake) {
        let (sender, receiver) = mpsc::channel(4096);
        (
            sender,
            TunIntake::from_source(Arc::new(FakeSource(Mutex::new(receiver))), 1280),
        )
    }

    async fn wait_until(mut condition: impl FnMut() -> bool) {
        timeout(Duration::from_secs(3), async {
            while !condition() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("condition did not become true");
    }

    #[tokio::test]
    async fn burst_drains_over_old_ring_size_and_backpressures_at_exact_bound() {
        let (sender, mut intake) = fake();
        for n in 0..2500u32 {
            sender.send(Ok(n.to_be_bytes().to_vec())).await.unwrap();
        }
        wait_until(|| intake.snapshot().queued_packets == INTAKE_PACKETS).await;
        assert_eq!(intake.snapshot().packets, INTAKE_PACKETS as u64);
        assert_eq!(intake.snapshot().peak_queued_packets, INTAKE_PACKETS);
        wait_until(|| intake.snapshot().queue_waits > 0).await;
        let mut expected = 0u32;
        let mut batch = Vec::new();
        while expected < 2500 {
            let count = timeout(Duration::from_secs(3), intake.recv_batch(&mut batch))
                .await
                .unwrap();
            assert!((1..=INTAKE_BATCH).contains(&count));
            for packet in batch.drain(..) {
                assert_eq!(packet.bytes, expected.to_be_bytes());
                expected += 1;
            }
        }
        assert_eq!(intake.snapshot().packets, 2500);
        assert_eq!(intake.snapshot().bytes, 10000);
        assert_eq!(intake.snapshot().oversize_drops, 0);
        assert!(intake.snapshot().max_queue_delay_us > 0);
    }

    #[tokio::test]
    async fn sparse_traffic_does_not_wait_for_full_batch_and_oversize_is_counted() {
        let (sender, mut intake) = fake();
        sender.send(Ok(vec![1; 1281])).await.unwrap();
        sender.send(Ok(vec![2; 1280])).await.unwrap();
        let mut batch = Vec::new();
        assert_eq!(
            timeout(Duration::from_secs(1), intake.recv_batch(&mut batch))
                .await
                .unwrap(),
            1
        );
        assert_eq!(batch[0].bytes, vec![2; 1280]);
        assert_eq!(intake.snapshot().oversize_drops, 1);
        assert_eq!(intake.snapshot().packets, 1);
    }

    #[tokio::test]
    async fn read_errors_reach_owner_and_drop_cancels_reader_even_when_full() {
        let (sender, mut intake) = fake();
        sender
            .send(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "test read error",
            )))
            .await
            .unwrap();
        let error = timeout(Duration::from_secs(1), &mut intake.task)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
        let (sender, intake) = fake();
        for _ in 0..1500 {
            sender.send(Ok(vec![1])).await.unwrap();
        }
        wait_until(|| intake.snapshot().queue_waits > 0).await;
        drop(intake);
        timeout(Duration::from_secs(1), sender.closed())
            .await
            .unwrap();
        let (sender, intake) = fake();
        drop(intake);
        timeout(Duration::from_secs(1), sender.closed())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn cancelling_pending_batch_does_not_consume_later_packet() {
        let (sender, mut intake) = fake();
        let mut batch = Vec::new();
        assert!(
            timeout(Duration::from_millis(10), intake.recv_batch(&mut batch))
                .await
                .is_err()
        );
        sender.send(Ok(vec![9])).await.unwrap();
        assert_eq!(intake.recv_batch(&mut batch).await, 1);
        assert_eq!(batch[0].bytes, vec![9]);
    }

    #[test]
    fn kernel_counters_distinguish_drops_reset_and_unavailable() {
        let mut monitor = KernelTxMonitor {
            root: PathBuf::new(),
            baseline: Some(100),
            previous: Some(100),
        };
        let s = monitor.observe(Some(110));
        assert_eq!(s.tx_dropped_since_start, Some(10));
        assert_eq!(s.tx_dropped_since_report, Some(10));
        assert_eq!(monitor.observe(Some(112)).tx_dropped_since_report, Some(2));
        assert_eq!(monitor.observe(None).tx_dropped_since_report, None);
        assert_eq!(monitor.observe(Some(115)).tx_dropped_since_report, None);
        let reset = monitor.observe(Some(1));
        assert_eq!(reset.tx_dropped_since_report, None);
        assert_eq!(reset.tx_dropped_since_start, Some(0));
        assert_eq!(monitor.observe(Some(3)).tx_dropped_since_report, Some(2));
        assert!(KernelTxMonitor::new("../../etc").is_err());
        assert!(KernelTxMonitor::new("").is_err());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "root required; run only in isolated network namespace"]
    async fn linux_real_tun_burst_has_no_loss_or_reordering() {
        let tun = Arc::new(
            tun_rs::DeviceBuilder::new()
                .name("vtintest0")
                .ipv4("198.18.255.1", 30, None)
                .mtu(1280)
                .build_async()
                .unwrap(),
        );
        tun.set_tx_queue_len(KERNEL_RING_PACKETS).unwrap();
        assert_eq!(tun.tx_queue_len().unwrap(), KERNEL_RING_PACKETS);
        let mut monitor = KernelTxMonitor::new("vtintest0").unwrap();
        let mut intake = TunIntake::new(tun, 1280);
        let source = std::net::UdpSocket::bind("198.18.255.1:0").unwrap();
        // A burst larger than the former 500-packet ring, while the scheduler
        // consumes nothing. Both intake and kernel buffers remain bounded.
        for n in 0..1500u32 {
            let mut payload = [0u8; 1100];
            payload[..4].copy_from_slice(&n.to_be_bytes());
            source.send_to(&payload, "198.18.255.2:18000").unwrap();
        }
        let mut expected = 0u32;
        let mut batch = Vec::new();
        timeout(Duration::from_secs(5), async {
            while expected < 1500 {
                intake.recv_batch(&mut batch).await;
                for packet in batch.drain(..) {
                    // Linux may also emit IPv6 router solicitation on the new
                    // interface. Only the generated IPv4 UDP stream is under
                    // test; production validates IPv4 after intake as before.
                    if packet.bytes[0] >> 4 != 4 {
                        continue;
                    }
                    assert_eq!(packet.bytes[9], 17);
                    assert_eq!(&packet.bytes[16..20], &[198, 18, 255, 2]);
                    assert_eq!(packet.bytes.len(), 1128);
                    assert_eq!(&packet.bytes[28..32], &expected.to_be_bytes());
                    expected += 1;
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(monitor.snapshot().tx_dropped_since_start, Some(0));
        assert_eq!(intake.snapshot().oversize_drops, 0);
    }
}
