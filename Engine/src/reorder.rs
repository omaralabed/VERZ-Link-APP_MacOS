//! Bounded, per-TCP-flow resequencing for unequal-delay links. ACK-only TCP,
//! UDP and unrelated flows never wait behind a missing bulk segment.
use std::collections::HashMap;

const MAX_FLOWS: usize = 1024;
// At 300 Mbps a 40 ms arrival gap spans roughly 1,250 full-size packets.
// The former 64-packet per-flow cap forced TCP reordering at ordinary speeds.
const MAX_PER_FLOW: usize = 4096;
const MAX_BUFFERED: usize = 8192;
// Cover the scheduler's 70 ms minimum repair timer plus a short alternate RTT.
// Releasing a gap at 50 ms triggered inner TCP loss recovery before the outer
// repair could arrive. ACK-only TCP and UDP still bypass this hold entirely.
const HOLD_MS: u64 = 80;

#[derive(Default)]
pub struct TcpReorder {
    flows: HashMap<[u8; 12], Flow>,
    buffered: usize,
}
struct Flow {
    next: u32,
    touched: u64,
    pending: Vec<(u32, u32, u64, Vec<u8>)>,
}

fn segment(ip: &[u8]) -> Option<([u8; 12], u32, u32)> {
    if ip.len() < 40 || ip[9] != 6 || ip[6] & 0x3f != 0 || ip[7] != 0 {
        return None;
    }
    let header = usize::from(ip[0] & 15) * 4;
    if header < 20 || ip.len() < header + 20 {
        return None;
    }
    let tcp_header = usize::from(ip[header + 12] >> 4) * 4;
    if tcp_header < 20 || ip.len() < header + tcp_header {
        return None;
    }
    let length = (ip.len() - header - tcp_header) as u32
        + u32::from(ip[header + 13] & 2 != 0)
        + u32::from(ip[header + 13] & 1 != 0);
    if length == 0 {
        return None;
    }
    let mut key = [0; 12];
    key[..8].copy_from_slice(&ip[12..20]);
    key[8..].copy_from_slice(&ip[header..header + 4]);
    Some((
        key,
        u32::from_be_bytes(ip[header + 4..header + 8].try_into().ok()?),
        length,
    ))
}

fn advance(flow: &mut Flow, seq: u32, length: u32) {
    let end = seq.wrapping_add(length);
    if end.wrapping_sub(flow.next) as i32 > 0 {
        flow.next = end;
    }
}
fn flush_contiguous(flow: &mut Flow, output: &mut Vec<Vec<u8>>) {
    while let Some(index) = flow
        .pending
        .iter()
        .position(|(seq, _, _, _)| seq.wrapping_sub(flow.next) as i32 <= 0)
    {
        let (seq, length, _, ip) = flow.pending.swap_remove(index);
        advance(flow, seq, length);
        output.push(ip);
    }
}

impl TcpReorder {
    pub fn push(&mut self, ip: Vec<u8>, now: u64) -> Vec<Vec<u8>> {
        let Some((key, seq, length)) = segment(&ip) else {
            return vec![ip];
        };
        if !self.flows.contains_key(&key) {
            // Do not evict another flow's buffered packets to admit this one.
            if self.flows.len() >= MAX_FLOWS {
                self.flows.retain(|_, flow| {
                    !flow.pending.is_empty() || now.saturating_sub(flow.touched) < 60_000
                });
                if self.flows.len() >= MAX_FLOWS {
                    return vec![ip];
                }
            }
            self.flows.insert(
                key,
                Flow {
                    next: seq.wrapping_add(length),
                    touched: now,
                    pending: Vec::new(),
                },
            );
            return vec![ip];
        }
        let flow = self.flows.get_mut(&key).expect("known flow");
        flow.touched = now;
        let before = flow.pending.len();
        let mut output = Vec::new();
        if seq.wrapping_sub(flow.next) as i32 > 0
            && flow.pending.len() < MAX_PER_FLOW
            && self.buffered < MAX_BUFFERED
        {
            flow.pending.push((seq, length, now, ip));
        } else {
            advance(flow, seq, length);
            output.push(ip);
            flush_contiguous(flow, &mut output);
        }
        self.buffered = self.buffered + flow.pending.len() - before;
        output
    }

    pub fn drain_due(&mut self, now: u64) -> Vec<Vec<u8>> {
        let mut output = Vec::new();
        for flow in self.flows.values_mut() {
            if !flow
                .pending
                .iter()
                .any(|(_, _, arrived, _)| now.saturating_sub(*arrived) >= HOLD_MS)
            {
                continue;
            }
            let before = flow.pending.len();
            // Skip a persistent gap after a strict bound; let TCP repair it.
            let index = flow
                .pending
                .iter()
                .enumerate()
                .min_by_key(|(_, (seq, _, _, _))| seq.wrapping_sub(flow.next))
                .map(|(i, _)| i)
                .unwrap();
            let (seq, length, _, ip) = flow.pending.swap_remove(index);
            advance(flow, seq, length);
            output.push(ip);
            flush_contiguous(flow, &mut output);
            self.buffered -= before - flow.pending.len();
        }
        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn tcp(seq: u32) -> Vec<u8> {
        let mut ip = vec![0; 140];
        ip[0] = 0x45;
        ip[9] = 6;
        ip[32] = 0x50;
        ip[24..28].copy_from_slice(&seq.to_be_bytes());
        ip
    }
    #[test]
    fn forty_ms_difference_is_reordered_without_blocking_udp() {
        let mut q = TcpReorder::default();
        assert_eq!(q.push(tcp(0), 0).len(), 1);
        assert!(q.push(tcp(200), 1).is_empty());
        let mut udp = vec![0; 40];
        udp[9] = 17;
        assert_eq!(q.push(udp, 2).len(), 1);
        assert_eq!(q.push(tcp(100), 41), vec![tcp(100), tcp(200)]);
        assert_eq!(q.buffered, 0);
    }
    #[test]
    fn missing_packet_has_bounded_hold_and_wrap_is_correct() {
        let mut q = TcpReorder::default();
        q.push(tcp(u32::MAX - 99), 0);
        assert!(q.push(tcp(100), 1).is_empty());
        assert!(q.drain_due(80).is_empty());
        assert_eq!(q.drain_due(81), vec![tcp(100)]);
        assert_eq!(q.buffered, 0);
    }

    #[test]
    fn fast_path_burst_waits_for_slower_path_without_forcing_tcp_reordering() {
        let mut q = TcpReorder::default();
        q.push(tcp(0), 0);
        for index in 2..1500 {
            assert!(q.push(tcp(index * 100), 1).is_empty());
        }
        let packets = q.push(tcp(100), 41);
        assert_eq!(packets.len(), 1499);
        for (index, packet) in packets.iter().enumerate() {
            assert_eq!(
                u32::from_be_bytes(packet[24..28].try_into().unwrap()),
                (index as u32 + 1) * 100
            );
        }
        assert_eq!(q.buffered, 0);
    }
}
