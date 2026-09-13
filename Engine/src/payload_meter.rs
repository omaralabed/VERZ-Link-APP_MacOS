//! Passive payload accounting. Never feeds routing, recovery or congestion control.
//! TCP credit requires a cumulative TCP ACK covering payload we actually observed.
//! Wire copies, retransmitted sequence ranges, IP/TCP headers and SYN/FIN get no credit.
use serde::Serialize;
use std::collections::HashMap;

const MAX_FLOWS: usize = 4096;
const MAX_RANGES: usize = 64;
const IDLE_MS: u64 = 600_000;

#[derive(Clone, Copy)]
pub enum Direction {
    Upload = 0,
    Download = 1,
}

#[derive(Default, Serialize)]
pub struct PayloadMeter {
    pub upload_bytes: u64,
    pub download_bytes: u64,
    pub unmeasured_packets: u64,
    #[serde(skip)]
    flows: HashMap<[u8; 12], Flow>,
}

#[derive(Default)]
struct Flow {
    streams: [Stream; 2],
    opening_syn: u32,
    last_seen: u64,
}

#[derive(Default)]
struct Stream {
    reference: Option<i64>,
    ack: Option<i64>,
    ranges: Vec<(i64, i64)>,
}

impl Stream {
    fn unwrap(&self, seq: u32) -> i64 {
        self.reference.map_or(i64::from(seq), |reference| {
            reference + i64::from(seq.wrapping_sub(reference as u32) as i32)
        })
    }

    fn observe(&mut self, seq: u32, bytes: usize, syn: bool, fin: bool) -> bool {
        let start = self.unwrap(seq) + i64::from(syn);
        let end = start + bytes as i64;
        self.reference = Some(self.reference.unwrap_or(end).max(end + i64::from(fin)));
        let start = start.max(self.ack.unwrap_or(start));
        if start >= end {
            return true;
        }
        // Bounded sorted interval union; retransmissions and partial overlaps count once.
        let mut merged = (start, end);
        let begin = self.ranges.partition_point(|r| r.1 < start);
        let mut finish = begin;
        while finish < self.ranges.len() && self.ranges[finish].0 <= merged.1 {
            merged.0 = merged.0.min(self.ranges[finish].0);
            merged.1 = merged.1.max(self.ranges[finish].1);
            finish += 1;
        }
        if begin == finish && self.ranges.len() >= MAX_RANGES {
            return false;
        }
        self.ranges.splice(begin..finish, [merged]);
        true
    }

    fn acknowledge(&mut self, seq: u32) -> u64 {
        let Some(reference) = self.reference else {
            return 0;
        };
        let ack = self.unwrap(seq);
        // A forged/stale ACK must not manufacture delivery of unsent bytes.
        if ack > reference || self.ack.is_some_and(|old| ack <= old) {
            return 0;
        }
        self.ack = Some(ack);
        let mut bytes = 0;
        for range in &mut self.ranges {
            if range.0 >= ack {
                break;
            }
            let end = range.1.min(ack);
            bytes += (end - range.0) as u64;
            range.0 = end;
        }
        self.ranges.retain(|(start, end)| start < end);
        bytes
    }
}

fn ipv4_transport(ip: &[u8], protocol: u8) -> Option<&[u8]> {
    if ip.len() < 20 || ip[0] >> 4 != 4 || ip[9] != protocol {
        return None;
    }
    let header = usize::from(ip[0] & 15) * 4;
    let total = usize::from(u16::from_be_bytes([ip[2], ip[3]]));
    if header < 20
        || total < header
        || total > ip.len()
        || u16::from_be_bytes([ip[6], ip[7]]) & 0x3fff != 0
    {
        return None;
    }
    Some(&ip[header..total])
}

pub fn udp_payload_len(ip: &[u8]) -> Option<u64> {
    let udp = ipv4_transport(ip, 17)?;
    if udp.len() < 8 {
        return None;
    }
    let length = usize::from(u16::from_be_bytes([udp[4], udp[5]]));
    (length >= 8 && length <= udp.len()).then_some(length.saturating_sub(8) as u64)
}

impl PayloadMeter {
    pub fn expire(&mut self, now: u64) {
        self.flows
            .retain(|_, flow| now.saturating_sub(flow.last_seen) < IDLE_MS);
    }

    pub fn observe(&mut self, ip: &[u8], direction: Direction, now: u64) {
        if ip.get(9) != Some(&6) {
            return;
        }
        let Some(tcp) = ipv4_transport(ip, 6).filter(|tcp| tcp.len() >= 20) else {
            self.unmeasured_packets += 1;
            return;
        };
        let header = usize::from(tcp[12] >> 4) * 4;
        if header < 20 || header > tcp.len() {
            self.unmeasured_packets += 1;
            return;
        }
        let d = direction as usize;
        let mut key = [0; 12];
        let (local, remote, ports) = if d == 0 {
            (&ip[12..16], &ip[16..20], [tcp[0], tcp[1], tcp[2], tcp[3]])
        } else {
            (&ip[16..20], &ip[12..16], [tcp[2], tcp[3], tcp[0], tcp[1]])
        };
        key[..4].copy_from_slice(local);
        key[4..8].copy_from_slice(remote);
        key[8..].copy_from_slice(&ports);
        let seq = u32::from_be_bytes(tcp[4..8].try_into().unwrap());
        let ack = u32::from_be_bytes(tcp[8..12].try_into().unwrap());
        let flags = tcp[13];
        let syn = flags & 2 != 0;
        let opening = syn && flags & 16 == 0;
        if opening && self.flows.get(&key).is_none_or(|f| f.opening_syn != seq) {
            if self.flows.len() >= MAX_FLOWS && !self.flows.contains_key(&key) {
                self.unmeasured_packets += 1;
                return;
            }
            self.flows.insert(
                key,
                Flow {
                    opening_syn: seq,
                    last_seen: now,
                    ..Default::default()
                },
            );
        }
        let Some(flow) = self.flows.get_mut(&key) else {
            // Do not invent a baseline for a connection opened before observation.
            if tcp.len() > header {
                self.unmeasured_packets += 1;
            }
            return;
        };
        flow.last_seen = now;
        if flags & 16 != 0 {
            let bytes = flow.streams[1 - d].acknowledge(ack);
            if d == 0 {
                self.download_bytes += bytes;
            } else {
                self.upload_bytes += bytes;
            }
        }
        if !flow.streams[d].observe(seq, tcp.len() - header, syn, flags & 1 != 0) {
            self.unmeasured_packets += 1;
        }
        if flags & 4 != 0 {
            self.flows.remove(&key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn packet(d: Direction, seq: u32, ack: u32, flags: u8, len: usize) -> Vec<u8> {
        let mut p = vec![0; 40 + len];
        p[0] = 0x45;
        p[9] = 6;
        p[2..4].copy_from_slice(&((40 + len) as u16).to_be_bytes());
        if matches!(d, Direction::Upload) {
            p[12..20].copy_from_slice(&[10, 0, 0, 2, 1, 1, 1, 1]);
            p[20..24].copy_from_slice(&[4, 0, 1, 187]);
        } else {
            p[12..20].copy_from_slice(&[1, 1, 1, 1, 10, 0, 0, 2]);
            p[20..24].copy_from_slice(&[1, 187, 4, 0]);
        }
        p[24..28].copy_from_slice(&seq.to_be_bytes());
        p[28..32].copy_from_slice(&ack.to_be_bytes());
        p[32] = 0x50;
        p[33] = flags;
        p
    }
    fn observe(m: &mut PayloadMeter, d: Direction, seq: u32, ack: u32, flags: u8, len: usize) {
        m.observe(&packet(d, seq, ack, flags, len), d, 0);
    }
    fn opened(seq: u32) -> PayloadMeter {
        let mut m = PayloadMeter::default();
        observe(&mut m, Direction::Upload, seq, 0, 2, 0);
        observe(&mut m, Direction::Download, 500, seq.wrapping_add(1), 18, 0);
        m
    }
    #[test]
    fn payload_requires_tcp_ack_and_excludes_retries_headers_and_fin() {
        let mut m = opened(100);
        observe(&mut m, Direction::Upload, 101, 501, 16, 1000);
        observe(&mut m, Direction::Upload, 101, 501, 16, 1000);
        assert_eq!(m.upload_bytes, 0);
        observe(&mut m, Direction::Download, 501, 601, 16, 0);
        assert_eq!(m.upload_bytes, 500);
        observe(&mut m, Direction::Upload, 501, 501, 16, 600);
        observe(&mut m, Direction::Download, 501, 1101, 16, 0);
        observe(&mut m, Direction::Download, 501, 1101, 16, 0);
        observe(&mut m, Direction::Upload, 1101, 501, 17, 0);
        observe(&mut m, Direction::Download, 501, 1102, 16, 0);
        assert_eq!(m.upload_bytes, 1000);
        assert_eq!(m.download_bytes, 0);
    }
    #[test]
    fn downloads_wait_for_mac_ack_and_do_not_count_missing_bytes() {
        let mut m = opened(100);
        observe(&mut m, Direction::Download, 1501, 101, 16, 500);
        observe(&mut m, Direction::Download, 501, 101, 16, 500);
        assert_eq!(m.download_bytes, 0);
        observe(&mut m, Direction::Upload, 101, 2001, 16, 0);
        assert_eq!(m.download_bytes, 1000);
    }
    #[test]
    fn sequence_wrap_and_late_duplicates() {
        let mut m = opened(u32::MAX - 10);
        observe(&mut m, Direction::Upload, u32::MAX - 9, 501, 16, 30);
        observe(&mut m, Direction::Download, 501, 20, 16, 0);
        observe(&mut m, Direction::Upload, u32::MAX - 9, 501, 16, 30);
        observe(&mut m, Direction::Download, 501, 20, 16, 0);
        assert_eq!(m.upload_bytes, 30);
    }
    #[test]
    fn invalid_future_ack_does_not_credit_pending_data() {
        let mut m = opened(100);
        observe(&mut m, Direction::Upload, 101, 501, 16, 20);
        observe(&mut m, Direction::Download, 501, 10_000, 16, 0);
        assert_eq!(m.upload_bytes, 0);
    }
    #[test]
    fn unobserved_and_expired_connections_are_marked_partial() {
        let mut m = PayloadMeter::default();
        observe(&mut m, Direction::Upload, 101, 501, 16, 20);
        assert_eq!(m.unmeasured_packets, 1);
        m = opened(100);
        m.expire(IDLE_MS);
        observe(&mut m, Direction::Upload, 101, 501, 16, 20);
        assert_eq!(m.upload_bytes, 0);
        assert_eq!(m.unmeasured_packets, 1);
    }
    #[test]
    fn tuple_reuse_starts_a_new_sequence_epoch() {
        let mut m = opened(100);
        observe(&mut m, Direction::Upload, 101, 501, 16, 20);
        observe(&mut m, Direction::Download, 501, 121, 16, 0);
        observe(&mut m, Direction::Upload, 900, 0, 2, 0);
        observe(&mut m, Direction::Upload, 901, 0, 16, 30);
        observe(&mut m, Direction::Download, 501, 931, 16, 0);
        assert_eq!(m.upload_bytes, 50);
    }
    #[test]
    fn bounded_ranges_report_coverage_loss_instead_of_guessing() {
        let mut m = opened(100);
        for i in 0..MAX_RANGES + 2 {
            observe(&mut m, Direction::Upload, 101 + (i * 4) as u32, 501, 16, 1);
        }
        assert_eq!(m.unmeasured_packets, 2);
        assert_eq!(
            m.flows.values().next().unwrap().streams[0].ranges.len(),
            MAX_RANGES
        );
    }
    #[test]
    fn malformed_tcp_and_fragmented_udp_do_not_invent_payload() {
        let mut m = opened(100);
        let mut p = packet(Direction::Upload, 101, 501, 16, 20);
        p[32] = 0xf0;
        m.observe(&p, Direction::Upload, 0);
        assert_eq!(m.unmeasured_packets, 1);
        p[9] = 17;
        p[24..26].copy_from_slice(&40u16.to_be_bytes());
        assert_eq!(udp_payload_len(&p), Some(32));
        p[6] = 0x20;
        assert_eq!(udp_payload_len(&p), None);
    }
}
