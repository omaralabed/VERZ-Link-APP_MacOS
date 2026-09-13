use std::{
    io,
    net::SocketAddr,
    time::{Duration, Instant},
};
use verz_udp_proxy::secure::SecureGateway;
fn main() -> io::Result<()> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 3 {
        return Err(io::Error::other(
            "usage: verz-udp-gateway IPv4:port secret-file",
        ));
    }
    let address: SocketAddr = args[1].parse().map_err(io::Error::other)?;
    let key = std::fs::read_to_string(&args[2])?;
    let mut server = SecureGateway::bind(address, key.trim().to_owned(), false)?;
    println!(
        "Encrypted isolated UDP gateway ready: {}",
        server.address()?
    );
    let mut report = Instant::now();
    loop {
        server.step()?;
        if report.elapsed() >= Duration::from_secs(5) {
            println!("{}", server.counters());
            report = Instant::now();
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}
