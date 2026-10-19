//! Coded mode (class 6) on the gateway: originals and repair packets in, the
//! application's datagrams out in order, per-link reports back.
//!
//! Wire format, all inside the usual authenticated packet:
//! - Original: class 6, no `FEC` flag, `sequence` = coded sequence,
//!   `timestamp_us` = the client's per-link send stamp (echoed back), payload
//!   = the datagram, or one piece of it with the `MORE` flag on every piece
//!   but the last.
//! - Repair: class 6 with the `FEC` flag; payload = [`RepairHeader`] then one
//!   coded block. Destination fields are unused.
//! - Probe: class 6 with `FEC` and `MORE`, empty payload: nothing to decode,
//!   only a send stamp to echo, so an idle link's rhythm stays observable.
//! - Report (gateway → client): class 6 with the `ACK` flag, sent on the link
//!   it describes; payload = [`Report`].
//!
//! Every original is coded as a fixed-size block: a prefix carrying what
//! egress needs (length, more-pieces flag, protocol, destination), then the
//! bytes, zero padded. A rebuilt original is therefore complete on its own.

use std::collections::HashMap;
use verz_bonding_core::coding::RepairHeader;
use verz_bonding_core::receiver::{CodedReceiver, Delivery, ReceiverConfig, Report};
use verz_link_core::{ACK, FEC, MAX_PAYLOAD, Packet, RESEND};

pub const CODED_CLASS: u16 = 6;
/// Coded block size. Repairs are then as long as the longest packets today.
pub const BLOCK: usize = 1_200;
const PREFIX: usize = 10;
/// Longest datagram, or piece of one, that fits a block.
pub const MAX_PIECE: usize = BLOCK - PREFIX;
/// Flag on an original that is not the last piece of its datagram.
pub const MORE: u8 = RESEND;
const DEADLINE_US: u64 = 200_000;
/// A sequence this far behind with a newer timestamp means the client restarted.
const RESET_GAP: u32 = 1_024;

/// The block for an original packet, or `None` if it does not fit one.
pub fn pack(p: &Packet) -> Option<Vec<u8>> {
    if p.payload.len() > MAX_PIECE {
        return None;
    }
    let mut block = vec![0_u8; BLOCK];
    block[..2].copy_from_slice(&(p.payload.len() as u16).to_be_bytes());
    block[2] = u8::from(p.flags & MORE != 0);
    block[3] = p.protocol;
    block[4..8].copy_from_slice(&p.destination);
    block[8..10].copy_from_slice(&p.destination_port.to_be_bytes());
    block[PREFIX..PREFIX + p.payload.len()].copy_from_slice(&p.payload);
    Some(block)
}

pub struct Unpacked {
    pub more: bool,
    pub protocol: u8,
    pub destination: [u8; 4],
    pub destination_port: u16,
    pub data: Vec<u8>,
}

pub fn unpack(block: &[u8]) -> Option<Unpacked> {
    if block.len() != BLOCK {
        return None;
    }
    let len = usize::from(u16::from_be_bytes([block[0], block[1]]));
    if len > MAX_PIECE {
        return None;
    }
    Some(Unpacked {
        more: block[2] != 0,
        protocol: block[3],
        destination: block[4..8].try_into().ok()?,
        destination_port: u16::from_be_bytes([block[8], block[9]]),
        data: block[PREFIX..PREFIX + len].to_vec(),
    })
}

#[derive(Default)]
pub struct CodedStats {
    pub rebuilt: u64,
    pub abandoned: u64,
    pub repairs: u64,
}

pub struct CodedStream {
    session: u32,
    port: u16,
    receiver: CodedReceiver,
    latest_sent: u64,
    /// Pieces of a datagram still being put together.
    pieces: Vec<u8>,
    rebuilt_seen: u64,
    abandoned_seen: u64,
    pub last: u64,
}

impl CodedStream {
    pub fn new(session: u32, port: u16, now: u64) -> Self {
        Self {
            session,
            port,
            receiver: CodedReceiver::new(ReceiverConfig {
                deadline_us: DEADLINE_US,
                payload_len: BLOCK,
                ..Default::default()
            }),
            latest_sent: 0,
            pieces: Vec::new(),
            rebuilt_seen: 0,
            abandoned_seen: 0,
            last: now,
        }
    }

    pub fn memory_bytes(&self) -> usize {
        self.receiver.memory_bytes() + self.pieces.len()
    }

    pub fn debug(&self) -> serde_json::Value {
        let (next, highest, rows, unknowns) = self.receiver.debug();
        serde_json::json!({"port": self.port, "next": next, "highest": highest, "equations": rows, "unknowns": unknowns})
    }

    /// Take in an original or a repair. Returns false if it was malformed.
    pub fn ingest(&mut self, p: &Packet, now: u64, stats: &mut CodedStats) -> bool {
        let sent_us = p.timestamp_us.max(0) as u64;
        self.last = now;
        if p.flags & FEC != 0 {
            if p.flags & MORE != 0 {
                self.receiver.on_probe(now, p.link, sent_us);
                return true;
            }
            let Some(header) = RepairHeader::from_bytes(&p.payload) else {
                return false;
            };
            let block = &p.payload[RepairHeader::WIRE..];
            if block.len() != BLOCK {
                return false;
            }
            stats.repairs += 1;
            self.receiver.on_repair(now, p.link, header, sent_us, block);
        } else {
            if p.sequence.saturating_add(RESET_GAP) < self.receiver.next_seq()
                && sent_us > self.latest_sent + 1_000_000
            {
                *self = Self::new(self.session, self.port, now);
            }
            self.latest_sent = self.latest_sent.max(sent_us);
            let Some(block) = pack(p) else {
                return false;
            };
            self.receiver.on_source(now, p.link, p.sequence, sent_us, &block);
        }
        true
    }

    /// Datagrams ready for egress, in order, and reports to send down each link.
    pub fn poll(&mut self, now: u64, stats: &mut CodedStats) -> (Vec<Packet>, Vec<Packet>) {
        let reports = self.receiver.poll(now);
        let mut egress = Vec::new();
        for delivery in self.receiver.drain() {
            match delivery {
                Delivery::Released(seq) => {
                    let Some(unpacked) = self.receiver.payload(seq).and_then(unpack) else {
                        self.pieces.clear();
                        continue;
                    };
                    if self.pieces.len() + unpacked.data.len() > MAX_PAYLOAD {
                        self.pieces.clear();
                        continue;
                    }
                    self.pieces.extend_from_slice(&unpacked.data);
                    if unpacked.more {
                        continue;
                    }
                    egress.push(Packet {
                        class: CODED_CLASS,
                        session: self.session,
                        sequence: seq,
                        timestamp_us: now as i64,
                        protocol: unpacked.protocol,
                        destination: unpacked.destination,
                        destination_port: unpacked.destination_port,
                        local_port: self.port,
                        payload: std::mem::take(&mut self.pieces),
                        ..Default::default()
                    });
                }
                Delivery::Abandoned(_) => self.pieces.clear(),
            }
        }
        stats.rebuilt += self.receiver.rebuilt - self.rebuilt_seen;
        stats.abandoned += self.receiver.abandoned - self.abandoned_seen;
        self.rebuilt_seen = self.receiver.rebuilt;
        self.abandoned_seen = self.receiver.abandoned;
        let reports = reports
            .into_iter()
            .map(|(link, report)| Packet {
                flags: ACK,
                class: CODED_CLASS,
                session: self.session,
                sequence: report.decoded_through.unwrap_or(u32::MAX),
                timestamp_us: now as i64,
                link,
                local_port: self.port,
                payload: report.encode(),
                ..Default::default()
            })
            .collect();
        (egress, reports)
    }
}

/// Streams by (session, local port), with the memory they hold.
pub type CodedStreams = HashMap<(u32, u16), CodedStream>;

/// The report inside a class-6 `ACK` packet, for the client.
pub fn report_of(p: &Packet) -> Option<Report> {
    (p.flags == ACK && p.class == CODED_CLASS).then(|| Report::decode(&p.payload)).flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_block_round_trips_everything_egress_needs() {
        let p = Packet {
            flags: MORE,
            protocol: 17,
            destination: [93, 184, 216, 34],
            destination_port: 9_000,
            payload: (0..MAX_PIECE).map(|i| i as u8).collect(),
            ..Default::default()
        };
        let block = pack(&p).unwrap();
        assert_eq!(block.len(), BLOCK);
        let u = unpack(&block).unwrap();
        assert!(u.more);
        assert_eq!((u.protocol, u.destination, u.destination_port), (17, [93, 184, 216, 34], 9_000));
        assert_eq!(u.data, p.payload);
        let too_long = Packet { payload: vec![0; MAX_PIECE + 1], ..Default::default() };
        assert!(pack(&too_long).is_none());
    }
}
