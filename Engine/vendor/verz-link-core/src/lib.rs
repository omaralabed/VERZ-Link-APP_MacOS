//! Rust port of the copied Boundlink v2 envelope. No VERZ v1 engine code.
use hmac::{Hmac, Mac};
use sha2::Sha256;
pub mod recovery;
pub mod scheduler;
pub mod transport;
pub mod wan;

pub const HEADER: usize = 38;
pub const MAX_PAYLOAD: usize = 16384;
pub const TAG: usize = 16;
pub const FEC: u8 = 1;
pub const PRIMARY: u8 = 2;
pub const TUN: u8 = 4;
pub const ACK: u8 = 8;
pub const NACK: u8 = 16;
pub const RESEND: u8 = 32;
pub const DOWNLINK: u8 = 64;
pub const HEARTBEAT: u8 = 128;

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Packet {
    pub flags: u8,
    pub class: u16,
    pub session: u32,
    pub sequence: u32,
    pub timestamp_us: i64,
    pub link: u8,
    pub protocol: u8,
    pub destination: [u8; 4],
    pub destination_port: u16,
    pub local_port: u16,
    pub payload: Vec<u8>,
}

impl Packet {
    /// An empty key is supported for legacy fixture compatibility only.
    /// Production configuration must reject empty/weak keys.
    pub fn encode(&self, key: &[u8]) -> Result<Vec<u8>, &'static str> {
        if self.payload.len() > MAX_PAYLOAD {
            return Err("payload too large");
        }
        let mut out = Vec::with_capacity(HEADER + self.payload.len() + TAG);
        out.extend_from_slice(b"BDLK");
        out.extend_from_slice(&[2, self.flags]);
        out.extend_from_slice(&self.class.to_be_bytes());
        out.extend_from_slice(&self.session.to_be_bytes());
        out.extend_from_slice(&self.sequence.to_be_bytes());
        out.extend_from_slice(&self.timestamp_us.to_be_bytes());
        out.extend_from_slice(&[self.link, self.protocol]);
        out.extend_from_slice(&self.destination);
        out.extend_from_slice(&self.destination_port.to_be_bytes());
        out.extend_from_slice(&self.local_port.to_be_bytes());
        out.extend_from_slice(&(self.payload.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.payload);
        if !key.is_empty() {
            let mut mac = Hmac::<Sha256>::new_from_slice(key).map_err(|_| "key")?;
            mac.update(&out);
            out.extend_from_slice(&mac.finalize().into_bytes()[..TAG]);
        }
        Ok(out)
    }

    pub fn decode(wire: &[u8], key: &[u8]) -> Result<Self, &'static str> {
        if wire.len() < HEADER || &wire[..4] != b"BDLK" || wire[4] != 2 {
            return Err("invalid header");
        }
        let n = u32::from_be_bytes(wire[34..38].try_into().unwrap()) as usize;
        let body = HEADER + n;
        let tag = if key.is_empty() { 0 } else { TAG };
        if n > MAX_PAYLOAD || wire.len() != body + tag {
            return Err("invalid length");
        }
        if tag != 0 {
            let mut mac = Hmac::<Sha256>::new_from_slice(key).map_err(|_| "key")?;
            mac.update(&wire[..body]);
            mac.verify_truncated_left(&wire[body..])
                .map_err(|_| "authentication failed")?;
        }
        Ok(Self {
            flags: wire[5],
            class: u16::from_be_bytes(wire[6..8].try_into().unwrap()),
            session: u32::from_be_bytes(wire[8..12].try_into().unwrap()),
            sequence: u32::from_be_bytes(wire[12..16].try_into().unwrap()),
            timestamp_us: i64::from_be_bytes(wire[16..24].try_into().unwrap()),
            link: wire[24],
            protocol: wire[25],
            destination: wire[26..30].try_into().unwrap(),
            destination_port: u16::from_be_bytes(wire[30..32].try_into().unwrap()),
            local_port: u16::from_be_bytes(wire[32..34].try_into().unwrap()),
            payload: wire[HEADER..body].to_vec(),
        })
    }

    pub fn is_data(&self) -> bool {
        self.flags & (ACK | NACK | DOWNLINK | HEARTBEAT) == 0
    }
    pub fn normalized_class(&self) -> u16 {
        if self.class == 1 { 4 } else { self.class }
    }
}

pub fn encode_nack(sequences: &[u32]) -> Result<Vec<u8>, &'static str> {
    if sequences.is_empty() || sequences.len() > 32 {
        return Err("invalid NACK count");
    }
    let mut wire = Vec::with_capacity(2 + 4 * sequences.len());
    wire.extend_from_slice(&(sequences.len() as u16).to_be_bytes());
    for seq in sequences {
        wire.extend_from_slice(&seq.to_be_bytes());
    }
    Ok(wire)
}

pub fn decode_nack(wire: &[u8]) -> Result<Vec<u32>, &'static str> {
    if wire.len() < 2 {
        return Err("short NACK");
    }
    let count = u16::from_be_bytes(wire[..2].try_into().unwrap()) as usize;
    if count == 0 || count > 32 || wire.len() < 2 + count * 4 {
        return Err("invalid NACK");
    }
    // Go reference accepts trailing bytes; preserve that behavior in the port.
    Ok(wire[2..2 + count * 4]
        .chunks_exact(4)
        .map(|b| u32::from_be_bytes(b.try_into().unwrap()))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> Packet {
        Packet {
            flags: PRIMARY,
            class: 4,
            session: 42,
            sequence: 1001,
            timestamp_us: 1700000000123456,
            link: 1,
            protocol: 2,
            destination: [203, 0, 113, 10],
            destination_port: 4200,
            local_port: 5000,
            payload: b"hello-stream".to_vec(),
        }
    }
    #[test]
    fn round_trip() {
        for key in [b"".as_slice(), b"fixture-key"] {
            let p = fixture();
            assert_eq!(Packet::decode(&p.encode(key).unwrap(), key).unwrap(), p);
        }
    }
    #[test]
    fn all_truncations_fail() {
        let w = fixture().encode(b"fixture-key").unwrap();
        for n in 0..w.len() {
            assert!(Packet::decode(&w[..n], b"fixture-key").is_err());
        }
    }
    #[test]
    fn every_tampered_byte_fails() {
        let w = fixture().encode(b"fixture-key").unwrap();
        for i in 0..w.len() {
            let mut b = w.clone();
            b[i] ^= 1;
            assert!(Packet::decode(&b, b"fixture-key").is_err());
        }
        assert!(Packet::decode(&w, b"wrong-key").is_err());
    }
    #[test]
    fn payload_bounds_and_trailing_data() {
        let mut p = fixture();
        p.payload = vec![0; MAX_PAYLOAD];
        assert!(p.encode(b"k").is_ok());
        p.payload.push(0);
        assert!(p.encode(b"k").is_err());
        let mut w = fixture().encode(b"").unwrap();
        w.push(0);
        assert!(Packet::decode(&w, b"").is_err());
    }
    #[test]
    fn control_and_legacy_class() {
        for flag in [ACK, NACK, DOWNLINK, HEARTBEAT] {
            assert!(
                !Packet {
                    flags: flag,
                    ..Default::default()
                }
                .is_data()
            );
        }
        assert_eq!(
            Packet {
                class: 1,
                ..Default::default()
            }
            .normalized_class(),
            4
        );
    }
    #[test]
    fn nack_bounds_and_wrap() {
        let seq = [u32::MAX, 0, 1];
        assert_eq!(decode_nack(&encode_nack(&seq).unwrap()).unwrap(), seq);
        assert!(encode_nack(&[]).is_err());
        assert!(encode_nack(&[1; 33]).is_err());
        assert!(decode_nack(&[0, 2, 0]).is_err());
    }
}
