//! Per-interface TLS/TCP carrier fallback.
//!
//! TLS is an outer compatibility layer for networks that suppress UDP. The
//! existing Noise session still authenticates and encrypts every VERZ packet;
//! consequently the short-lived self-signed outer certificate is deliberately
//! not an identity credential. A TLS interceptor can only cause the Noise
//! handshake to fail, never read or forge tunnel traffic.

use anyhow::{Context, Result, ensure};
use rcgen::{CertifiedKey, generate_simple_self_signed};
use std::{
    fmt,
    net::{SocketAddr, SocketAddrV4},
    os::fd::AsRawFd,
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpSocket, TcpStream, UdpSocket},
    sync::Semaphore,
    task::JoinHandle,
    time,
};
use tokio_rustls::{
    TlsAcceptor, TlsConnector,
    client::TlsStream as ClientTlsStream,
    rustls::{
        self, ClientConfig, DigitallySignedStruct, ServerConfig, SignatureScheme,
        client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime},
    },
};

use crate::bind_ipv4_interface_fd;

pub const ALPN: &[u8] = b"verz-link-carrier/1";
pub const MAX_FRAME: usize = 65_535;
const WRITE_BATCH_FRAMES: usize = 64;
const WRITE_BATCH_BYTES: usize = 256 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(6);
const TLS_TIMEOUT: Duration = Duration::from_secs(6);

/// The outer certificate is intentionally anonymous. Authentication remains
/// the responsibility of the existing Noise PSK immediately inside TLS.
struct NoiseAuthenticatedTls;

impl fmt::Debug for NoiseAuthenticatedTls {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("NoiseAuthenticatedTls")
    }
}

impl ServerCertVerifier for NoiseAuthenticatedTls {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

pub fn client_config() -> Arc<ClientConfig> {
    let mut config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoiseAuthenticatedTls))
        .with_no_client_auth();
    config.alpn_protocols = vec![ALPN.to_vec()];
    Arc::new(config)
}

pub fn server_config() -> Result<Arc<ServerConfig>> {
    let CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(vec!["verz-relay.invalid".to_string()])?;
    let certificate = cert.der().clone();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(signing_key.serialize_der()));
    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![certificate], key)?;
    config.alpn_protocols = vec![ALPN.to_vec()];
    Ok(Arc::new(config))
}

/// Connect one TCP socket through a specific physical interface, then wrap it
/// in ordinary TLS 1.2/1.3. No route or system setting is changed.
pub async fn connect(
    interface: &str,
    relay: SocketAddr,
    config: Arc<ClientConfig>,
) -> Result<ClientTlsStream<TcpStream>> {
    ensure!(
        relay.is_ipv4(),
        "corporate fallback currently requires IPv4"
    );
    let socket = TcpSocket::new_v4()?;
    bind_ipv4_interface_fd(socket.as_raw_fd(), interface)?;
    socket.bind(SocketAddrV4::new(std::net::Ipv4Addr::UNSPECIFIED, 0).into())?;
    let stream = time::timeout(CONNECT_TIMEOUT, socket.connect(relay))
        .await
        .context("corporate fallback TCP connection timed out")??;
    stream.set_nodelay(true)?;
    let name = ServerName::try_from("verz-relay.invalid")?.to_owned();
    let tls = time::timeout(
        TLS_TIMEOUT,
        TlsConnector::from(config).connect(name, stream),
    )
    .await
    .context("corporate fallback TLS handshake timed out")??;
    ensure!(
        tls.get_ref().1.alpn_protocol() == Some(ALPN),
        "corporate fallback ALPN was not negotiated"
    );
    Ok(tls)
}

pub async fn write_frame<W: AsyncWrite + Unpin>(writer: &mut W, packet: &[u8]) -> Result<()> {
    ensure!(
        !packet.is_empty() && packet.len() <= MAX_FRAME,
        "invalid corporate fallback frame length"
    );
    let mut frame = Vec::with_capacity(packet.len() + 2);
    append_frame(&mut frame, packet)?;
    writer.write_all(&frame).await?;
    Ok(())
}

/// Append one datagram to a bounded TLS write batch while preserving exact
/// datagram boundaries. The caller flushes after the group, avoiding a TLS
/// record and two async writes for every 1,280-byte tunnel packet.
pub fn append_frame(batch: &mut Vec<u8>, packet: &[u8]) -> Result<()> {
    ensure!(
        !packet.is_empty() && packet.len() <= MAX_FRAME,
        "invalid corporate fallback frame length"
    );
    batch.extend_from_slice(&(packet.len() as u16).to_be_bytes());
    batch.extend_from_slice(packet);
    Ok(())
}

pub fn batch_has_room(batch: &[u8], frames: usize) -> bool {
    frames < WRITE_BATCH_FRAMES && batch.len() < WRITE_BATCH_BYTES
}

pub async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Option<Vec<u8>>> {
    let mut size = [0_u8; 2];
    match reader.read_exact(&mut size).await {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error.into()),
    }
    let size = usize::from(u16::from_be_bytes(size));
    ensure!(
        (1..=MAX_FRAME).contains(&size),
        "invalid corporate fallback frame"
    );
    let mut packet = vec![0_u8; size];
    reader.read_exact(&mut packet).await?;
    Ok(Some(packet))
}

async fn proxy_connection(
    stream: TcpStream,
    acceptor: TlsAcceptor,
    udp_relay: SocketAddr,
) -> Result<()> {
    stream.set_nodelay(true)?;
    let tls = time::timeout(TLS_TIMEOUT, acceptor.accept(stream))
        .await
        .context("corporate fallback TLS accept timed out")??;
    ensure!(
        tls.get_ref().1.alpn_protocol() == Some(ALPN),
        "corporate fallback client omitted ALPN"
    );
    let udp = UdpSocket::bind("0.0.0.0:0").await?;
    crate::configure_udp_buffers(&udp)?;
    let udp = Arc::new(udp);
    udp.connect(udp_relay).await?;
    let (mut reader, mut writer) = tokio::io::split(tls);
    let uplink = udp.clone();
    let read_tls = async move {
        while let Some(frame) = read_frame(&mut reader).await? {
            ensure!(
                uplink.send(&frame).await? == frame.len(),
                "short fallback UDP write"
            );
        }
        Ok::<(), anyhow::Error>(())
    };
    let write_tls = async move {
        let mut datagram = vec![0_u8; MAX_FRAME];
        let mut batch = Vec::with_capacity(WRITE_BATCH_BYTES);
        loop {
            let received = udp.recv(&mut datagram).await?;
            batch.clear();
            append_frame(&mut batch, &datagram[..received])?;
            let mut frames = 1;
            while batch_has_room(&batch, frames) {
                match udp.try_recv(&mut datagram) {
                    Ok(received) => {
                        append_frame(&mut batch, &datagram[..received])?;
                        frames += 1;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(error) => return Err::<(), anyhow::Error>(error.into()),
                }
            }
            writer.write_all(&batch).await?;
            writer.flush().await?;
        }
    };
    tokio::try_join!(read_tls, write_tls)?;
    Ok(())
}

/// Run the outer TLS listener. Every accepted stream gets its own connected
/// loopback UDP socket, preserving independent NAT-like path identities for
/// the unchanged multipath server.
pub async fn serve(
    listener: TcpListener,
    udp_relay: SocketAddr,
    max_connections: usize,
) -> Result<()> {
    ensure!(
        max_connections > 0,
        "corporate fallback connection limit is zero"
    );
    let acceptor = TlsAcceptor::from(server_config()?);
    let permits = Arc::new(Semaphore::new(max_connections));
    loop {
        let (stream, _) = listener.accept().await?;
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            // Refuse excess unauthenticated sockets before allocating their
            // TLS and UDP state. Existing fallback sessions remain untouched.
            continue;
        };
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            let _permit = permit;
            // Remote handshake failures are untrusted input. Drop them without
            // per-connection journal output so a scan cannot create log I/O.
            let _ = proxy_connection(stream, acceptor, udp_relay).await;
        });
    }
}

pub fn spawn(
    listener: TcpListener,
    udp_relay: SocketAddr,
    max_connections: usize,
) -> JoinHandle<Result<()>> {
    tokio::spawn(serve(listener, udp_relay, max_connections))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn tls_proxy_preserves_datagram_boundaries() -> Result<()> {
        let udp = UdpSocket::bind("127.0.0.1:0").await?;
        let udp_address = udp.local_addr()?;
        let echo = tokio::spawn(async move {
            let mut packet = [0_u8; 2048];
            for _ in 0..3 {
                let (size, peer) = udp.recv_from(&mut packet).await.unwrap();
                udp.send_to(&packet[..size], peer).await.unwrap();
            }
        });
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let proxy = spawn(listener, udp_address, 8);
        let interface = if cfg!(target_os = "macos") {
            "lo0"
        } else {
            "lo"
        };
        let mut tls = connect(interface, address, client_config()).await?;
        for packet in [b"one".as_slice(), b"two-two", &[7_u8; 1024]] {
            write_frame(&mut tls, packet).await?;
            assert_eq!(read_frame(&mut tls).await?.as_deref(), Some(packet));
        }
        echo.await?;
        proxy.abort();
        Ok(())
    }

    #[tokio::test]
    async fn tls_proxy_moves_a_batched_packet_window_without_serial_round_trips() -> Result<()> {
        const PACKETS: usize = 4096;
        const PAYLOAD: usize = 1200;
        let udp = UdpSocket::bind("127.0.0.1:0").await?;
        crate::configure_udp_buffers(&udp)?;
        let udp_address = udp.local_addr()?;
        let echo = tokio::spawn(async move {
            let mut packet = [0_u8; 2048];
            for _ in 0..PACKETS {
                let (size, peer) = udp.recv_from(&mut packet).await.unwrap();
                udp.send_to(&packet[..size], peer).await.unwrap();
            }
        });
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let proxy = spawn(listener, udp_address, 8);
        let interface = if cfg!(target_os = "macos") {
            "lo0"
        } else {
            "lo"
        };
        let tls = connect(interface, address, client_config()).await?;
        let (mut reader, mut writer) = tokio::io::split(tls);
        let transfer = async move {
            let upload = async move {
                let packet = vec![7_u8; PAYLOAD];
                let mut batch = Vec::with_capacity(WRITE_BATCH_BYTES);
                for window in 0..PACKETS.div_ceil(WRITE_BATCH_FRAMES) {
                    batch.clear();
                    let count = WRITE_BATCH_FRAMES.min(PACKETS - window * WRITE_BATCH_FRAMES);
                    for _ in 0..count {
                        append_frame(&mut batch, &packet)?;
                    }
                    writer.write_all(&batch).await?;
                    writer.flush().await?;
                }
                Ok::<(), anyhow::Error>(())
            };
            let download = async move {
                for _ in 0..PACKETS {
                    let packet = read_frame(&mut reader).await?.context("early TLS EOF")?;
                    ensure!(packet.len() == PAYLOAD && packet.iter().all(|byte| *byte == 7));
                }
                Ok::<(), anyhow::Error>(())
            };
            tokio::try_join!(upload, download)?;
            Ok::<(), anyhow::Error>(())
        };
        time::timeout(Duration::from_secs(5), transfer)
            .await
            .context("batched corporate proxy stalled")??;
        echo.await?;
        proxy.abort();
        Ok(())
    }

    #[tokio::test]
    async fn framing_rejects_zero_length() {
        let mut bytes = &b"\0\0"[..];
        assert!(read_frame(&mut bytes).await.is_err());
    }
}
