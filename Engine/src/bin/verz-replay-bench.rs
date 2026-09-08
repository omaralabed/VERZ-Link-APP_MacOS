//! CPU microbenchmark, not a network throughput or failover acceptance test.
use std::{hint::black_box, time::Instant};
use verz_link_lab::ReplayWindow;

fn main() {
    let packets = 100_000_u64;
    let mut transport = ReplayWindow::new(8192);
    let mut delivery = ReplayWindow::new(16384);
    for counter in 0..16384 {
        assert!(transport.mark(counter));
        assert!(delivery.mark(counter));
    }
    let start = Instant::now();
    for counter in 16384..16384 + packets {
        assert!(black_box(&mut transport).mark(black_box(counter)));
        assert!(black_box(&mut delivery).mark(black_box(counter)));
    }
    let seconds = start.elapsed().as_secs_f64();
    println!(
        "Two full replay windows: {packets} packets in {seconds:.6}s; {:.0} packets/s; {:.1} ns/packet",
        packets as f64 / seconds,
        seconds * 1e9 / packets as f64
    );
    println!(
        "Replay-only CPU ceiling at 1200 bytes: {:.1} Mbps (excludes encryption, sockets, scheduling and TCP)",
        packets as f64 * 1200.0 * 8.0 / seconds / 1e6
    );
}
