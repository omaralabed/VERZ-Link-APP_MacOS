//! Integration check: two concurrent authenticated clients exchange real ICMP
//! echo requests with the relay's Linux IP stack, each using its own lease.
use anyhow::{Result, ensure};
use clap::Parser;
use std::{net::SocketAddr, path::PathBuf, time::Duration};
use tokio::{net::UdpSocket, time};
use verz_link_lab::{bind_interface_socket, load_secret, tunnel::*};

#[derive(Parser)]
struct Args {
    #[arg(long)]
    secret_file: PathBuf,
    #[arg(long, default_value = "69.164.213.57:39001")]
    relay: SocketAddr,
    #[arg(long, default_value = "en0")]
    interface: String,
}

async fn connect(args: &Args) -> Result<(UdpSocket, Transport, [u8; 4])> {
    let socket = bind_interface_socket(&args.interface, args.relay)?;
    let session = rand::random();
    let mut noise = handshake(&load_secret(&args.secret_file)?, &session, true)?;
    let mut wire = [0; MAX_WIRE + 1];
    let len = noise.write_message(&[], &mut wire)?;
    let hello = Header {
        kind: HELLO,
        session,
        counter: 0,
    }
    .wrap(&wire[..len]);
    for _ in 0..20 {
        socket.send(&hello).await?;
        if let Ok(Ok(len)) = time::timeout(Duration::from_millis(500), socket.recv(&mut wire)).await
        {
            let header = Header::parse(&wire[..len])?;
            ensure!(
                header.kind == WELCOME && header.session == session,
                "wrong welcome"
            );
            let mut assigned = [0; 64];
            let size = noise.read_message(&wire[HEADER..len], &mut assigned)?;
            ensure!(size == 4, "missing authenticated lease");
            return Ok((
                socket,
                Transport::new(session, noise)?,
                assigned[..4].try_into()?,
            ));
        }
    }
    anyhow::bail!("handshake timeout")
}

fn checksum(bytes: &[u8]) -> u16 {
    let mut sum: u32 = bytes
        .chunks(2)
        .map(|b| u32::from(b[0]) * 256 + u32::from(*b.get(1).unwrap_or(&0)))
        .sum();
    while sum >> 16 != 0 {
        sum = (sum & 65535) + (sum >> 16);
    }
    !(sum as u16)
}

async fn ping(client: &mut (UdpSocket, Transport, [u8; 4]), sequence: u16) -> Result<()> {
    let mut ip = [0; 36];
    ip[0] = 0x45;
    ip[3] = 36;
    ip[8] = 64;
    ip[9] = 1;
    ip[12..16].copy_from_slice(&client.2);
    ip[16..20].copy_from_slice(&SERVER_IP);
    let sum = checksum(&ip[..20]);
    ip[10..12].copy_from_slice(&sum.to_be_bytes());
    ip[20] = 8;
    ip[24] = 0x56;
    ip[25] = client.2[3];
    ip[26..28].copy_from_slice(&sequence.to_be_bytes());
    ip[28..36].copy_from_slice(b"VERZTEST");
    let sum = checksum(&ip[20..]);
    ip[22..24].copy_from_slice(&sum.to_be_bytes());
    client.0.send(&client.1.seal(IP, &ip)?).await?;
    let mut wire = [0; MAX_WIRE + 1];
    let len = time::timeout(Duration::from_secs(4), client.0.recv(&mut wire)).await??;
    let (kind, response) = client.1.open(&wire[..len])?;
    ensure!(kind == IP, "expected real IP response");
    validate_ipv4(&response, Some(SERVER_IP), Some(client.2))?;
    ensure!(
        response.len() == 36 && response[20] == 0 && response[24..] == ip[24..],
        "wrong ICMP echo response or cross-client routing"
    );
    Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let args = Args::parse();
    let mut first = connect(&args).await?;
    let mut second = connect(&args).await?;
    ensure!(first.2 != second.2, "duplicate client assignment");
    for sequence in 0..10 {
        let (a, b) = tokio::join!(ping(&mut first, sequence), ping(&mut second, sequence));
        a?;
        b?;
    }
    for client in [&mut first, &mut second] {
        client.0.send(&client.1.seal(CLOSE, &[])?).await?;
    }
    println!(
        "PASS: two simultaneous sessions, unique leases {} and {}, 20 real ICMP replies; no cross-client delivery",
        std::net::Ipv4Addr::from(first.2),
        std::net::Ipv4Addr::from(second.2)
    );
    Ok(())
}
