//! Ordinary HTTP/TCP test endpoint bound only to the server's private TUN IP.
use anyhow::{Result, ensure};
use clap::Parser;
use sha2::{Digest, Sha256};
use std::{net::SocketAddr, path::PathBuf, sync::Arc};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::{Duration, timeout},
};

#[derive(Parser)]
struct Args {
    #[arg(long, default_value = "10.77.0.1:8080")]
    listen: SocketAddr,
    #[arg(long)]
    file: PathBuf,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let args = Args::parse();
    let file = Arc::new(std::fs::read(args.file)?);
    ensure!(file.len() <= 16 * 1024 * 1024, "test file too large");
    let hash = Arc::new(format!(
        "{}\n",
        hex::encode(Sha256::digest(file.as_slice()))
    ));
    let listener = TcpListener::bind(args.listen).await?;
    let slots = Arc::new(tokio::sync::Semaphore::new(8));
    println!(
        "REAL TCP test endpoint {} / {} bytes / SHA256 {}",
        args.listen,
        file.len(),
        hash.trim()
    );
    loop {
        let (socket, _) = listener.accept().await?;
        let Ok(permit) = slots.clone().try_acquire_owned() else {
            continue;
        };
        let file = file.clone();
        let hash = hash.clone();
        tokio::spawn(async move {
            let _permit = permit;
            match timeout(Duration::from_secs(90), serve(socket, file, hash)).await {
                Ok(Ok(())) => {}
                other => eprintln!("HTTP test connection: {other:?}"),
            }
        });
    }
}

async fn serve(mut socket: TcpStream, file: Arc<Vec<u8>>, hash: Arc<String>) -> Result<()> {
    let mut header = Vec::new();
    while !header.ends_with(b"\r\n\r\n") {
        ensure!(header.len() < 8192, "HTTP header too large");
        header.push(socket.read_u8().await?);
    }
    let text = std::str::from_utf8(&header)?;
    let request = text.lines().next().unwrap_or("");
    if request.starts_with("GET /health ") {
        respond(&mut socket, b"VERZ real TCP over encrypted IP tunnel\n").await?;
    } else if request.starts_with("GET /download ") {
        respond(&mut socket, &file).await?;
    } else if request.starts_with("GET /sha256 ") {
        respond(&mut socket, hash.as_bytes()).await?;
    } else if request.starts_with("POST /upload ") {
        let length = text
            .lines()
            .filter_map(|line| line.split_once(':'))
            .find(|(key, _)| key.eq_ignore_ascii_case("content-length"))
            .map(|(_, value)| value.trim().parse::<usize>())
            .transpose()?
            .unwrap_or(0);
        ensure!(length <= 16 * 1024 * 1024, "upload too large");
        if text
            .lines()
            .any(|line| line.eq_ignore_ascii_case("expect: 100-continue"))
        {
            socket.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").await?;
        }
        let mut content = vec![0; length];
        socket.read_exact(&mut content).await?;
        let hash = format!("{}\n", hex::encode(Sha256::digest(&content)));
        println!(
            "HTTP upload verified: {length} bytes / SHA256 {}",
            hash.trim()
        );
        respond(&mut socket, hash.as_bytes()).await?;
    } else {
        socket
            .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await?;
    }
    socket.shutdown().await?;
    Ok(())
}

async fn respond(socket: &mut TcpStream, body: &[u8]) -> Result<()> {
    let header = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/octet-stream\r\nConnection: close\r\n\r\n",
        body.len()
    );
    socket.write_all(header.as_bytes()).await?;
    socket.write_all(body).await?;
    Ok(())
}
