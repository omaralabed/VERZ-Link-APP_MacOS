//! Sliding-window repair packets.
//!
//! Original packets are always sent unchanged (systematic), so a clean path
//! adds no delay. A repair packet is a random linear combination, over
//! GF(256), of a contiguous range of recent originals. The header carries only
//! the range and a seed; both ends derive identical coefficients from it.
//!
//! Any missing original inside a range can be rebuilt once the receiver holds
//! as many independent repairs as it has missing originals there. The decoder
//! works incrementally: originals and repairs may arrive in any order.

use crate::gf256;
use std::collections::BTreeMap;

/// Released originals kept for eliminating them from late repairs: many
/// when only coefficients are tracked, fewer when every one holds a payload.
const RETAIN_COUNTED: u32 = 4096;
const RETAIN_WITH_PAYLOAD: u32 = 256;
/// Equations held at once; beyond this the oldest is dropped.
const MAX_ROWS: usize = 512;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RepairHeader {
    pub first: u32,
    pub count: u16,
    pub seed: u32,
}

impl RepairHeader {
    pub const WIRE: usize = 10;

    pub fn last(&self) -> u32 {
        self.first + u32::from(self.count) - 1
    }

    pub fn to_bytes(&self) -> [u8; Self::WIRE] {
        let mut out = [0; Self::WIRE];
        out[..4].copy_from_slice(&self.first.to_be_bytes());
        out[4..6].copy_from_slice(&self.count.to_be_bytes());
        out[6..].copy_from_slice(&self.seed.to_be_bytes());
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < Self::WIRE {
            return None;
        }
        let header = Self {
            first: u32::from_be_bytes(bytes[..4].try_into().ok()?),
            count: u16::from_be_bytes(bytes[4..6].try_into().ok()?),
            seed: u32::from_be_bytes(bytes[6..10].try_into().ok()?),
        };
        (header.count > 0 && header.first.checked_add(u32::from(header.count)).is_some()).then_some(header)
    }
}

/// Nonzero coefficient for one original inside one repair.
pub fn coefficient(seed: u32, seq: u32) -> u8 {
    let mut z = (u64::from(seed) << 32 | u64::from(seq)).wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^= z >> 31;
    (z % 255) as u8 + 1
}

/// Build a repair payload from originals of equal length.
pub fn encode<'a>(header: RepairHeader, original: impl Fn(u32) -> &'a [u8], len: usize) -> Vec<u8> {
    let mut out = vec![0_u8; len];
    for seq in header.first..=header.last() {
        gf256::mul_add(&mut out, original(seq), coefficient(header.seed, seq));
    }
    out
}

/// One reduced equation: sorted unknown columns with coefficients, and the
/// combined payload. The first column is the pivot and has coefficient 1.
#[derive(Clone, Debug)]
struct Row {
    cols: Vec<(u32, u8)>,
    rhs: Vec<u8>,
}

/// Incremental Gaussian elimination over a sliding window.
///
/// With `payload_len == 0` only coefficients are tracked: decodability is
/// exact, but no bytes are rebuilt. The simulator uses that mode; tests and
/// benchmarks use real payloads to prove the bytes come back identical.
pub struct Decoder {
    payload_len: usize,
    known: BTreeMap<u32, Vec<u8>>,
    rows: BTreeMap<u32, Row>,
    floor: u32,
    retain: u32,
}

impl Decoder {
    pub fn new(payload_len: usize) -> Self {
        Self {
            payload_len,
            known: BTreeMap::new(),
            rows: BTreeMap::new(),
            floor: 0,
            retain: if payload_len == 0 { RETAIN_COUNTED } else { RETAIN_WITH_PAYLOAD },
        }
    }

    /// Bytes held for payloads and equations.
    pub fn memory_bytes(&self) -> usize {
        (self.known.len() + self.rows.len()) * self.payload_len
    }

    pub fn is_known(&self, seq: u32) -> bool {
        self.known.contains_key(&seq)
    }

    pub fn payload(&self, seq: u32) -> Option<&[u8]> {
        self.known.get(&seq).map(Vec::as_slice)
    }

    pub fn pending_equations(&self) -> usize {
        self.rows.len()
    }

    /// Originals currently held, released or not.
    pub fn known_count(&self) -> usize {
        self.known.len()
    }

    /// Unknown sequences the pending equations refer to, lowest first.
    pub fn unknowns(&self) -> Vec<u32> {
        let mut all: Vec<u32> = self.rows.values().flat_map(|r| r.cols.iter().map(|&(s, _)| s)).collect();
        all.sort_unstable();
        all.dedup();
        all
    }

    /// An original arrived. Returns originals rebuilt as a consequence.
    pub fn add_source(&mut self, seq: u32, payload: &[u8]) -> Vec<u32> {
        if seq < self.floor || self.known.contains_key(&seq) {
            return Vec::new();
        }
        let value = self.value(payload);
        let mut solved = Vec::new();
        self.learn(seq, value, &mut solved);
        solved
    }

    /// A repair arrived. Returns originals rebuilt by it.
    pub fn add_repair(&mut self, header: RepairHeader, payload: &[u8]) -> Vec<u32> {
        if header.last() < self.floor {
            return Vec::new();
        }
        let mut row = Row {
            cols: Vec::with_capacity(usize::from(header.count)),
            rhs: self.value(payload),
        };
        for seq in header.first..=header.last() {
            let c = coefficient(header.seed, seq);
            if let Some(value) = self.known.get(&seq) {
                if self.payload_len > 0 {
                    gf256::mul_add(&mut row.rhs, value, c);
                }
            } else if seq < self.floor {
                // An abandoned original is part of this combination. Its value
                // will never be known, so the repair cannot be used safely.
                return Vec::new();
            } else {
                row.cols.push((seq, c));
            }
        }
        let mut solved = Vec::new();
        if let Some(pivot) = self.insert(row) {
            self.settle(vec![pivot], &mut solved);
        }
        solved
    }

    /// Everything below `floor` has been released or abandoned. Equations for
    /// abandoned originals are dropped; known originals are retained a while
    /// longer so repairs built from a slightly stale window stay usable.
    pub fn forget_below(&mut self, floor: u32) {
        if floor <= self.floor {
            return;
        }
        self.floor = floor;
        self.rows = self.rows.split_off(&floor);
        self.known = self.known.split_off(&floor.saturating_sub(self.retain));
    }

    fn value(&self, payload: &[u8]) -> Vec<u8> {
        if self.payload_len == 0 {
            Vec::new()
        } else {
            let mut v = payload.to_vec();
            v.resize(self.payload_len, 0);
            v
        }
    }

    /// Reduce a row against existing pivots and store it. Returns its pivot,
    /// or `None` if it carried no new information.
    fn insert(&mut self, mut row: Row) -> Option<u32> {
        loop {
            let &(pivot, c) = row.cols.first()?;
            match self.rows.get(&pivot) {
                Some(base) => row = combine(&row, base, c),
                None => {
                    let factor = gf256::inv(c);
                    for col in &mut row.cols {
                        col.1 = gf256::mul(col.1, factor);
                    }
                    gf256::scale(&mut row.rhs, factor);
                    if self.rows.len() >= MAX_ROWS {
                        self.rows.pop_first();
                    }
                    self.rows.insert(pivot, row);
                    return Some(pivot);
                }
            }
        }
    }

    /// Solve every row that has been reduced to a single unknown, cascading.
    fn settle(&mut self, mut work: Vec<u32>, solved: &mut Vec<u32>) {
        while let Some(pivot) = work.pop() {
            let single = self.rows.get(&pivot).is_some_and(|row| row.cols.len() == 1);
            if !single {
                continue;
            }
            let row = self.rows.remove(&pivot).expect("row present");
            solved.push(pivot);
            self.learn_into(pivot, row.rhs, &mut work);
        }
    }

    fn learn(&mut self, seq: u32, value: Vec<u8>, solved: &mut Vec<u32>) {
        let mut work = Vec::new();
        self.learn_into(seq, value, &mut work);
        self.settle(work, solved);
    }

    /// Record a known original and eliminate it from every stored row.
    fn learn_into(&mut self, seq: u32, value: Vec<u8>, work: &mut Vec<u32>) {
        // A row pivoted on this original loses its pivot and is re-reduced.
        if let Some(mut row) = self.rows.remove(&seq) {
            let (_, c) = row.cols.remove(0);
            if self.payload_len > 0 {
                gf256::mul_add(&mut row.rhs, &value, c);
            }
            if let Some(pivot) = self.insert(row) {
                work.push(pivot);
            }
        }
        // Rows pivoted below this original may contain it as a later column.
        let below: Vec<u32> = self.rows.range(..seq).map(|(&p, _)| p).collect();
        for pivot in below {
            let row = self.rows.get_mut(&pivot).expect("row present");
            if let Ok(i) = row.cols.binary_search_by_key(&seq, |&(s, _)| s) {
                let (_, c) = row.cols.remove(i);
                if self.payload_len > 0 {
                    gf256::mul_add(&mut row.rhs, &value, c);
                }
                if row.cols.len() == 1 {
                    work.push(pivot);
                }
            }
        }
        self.known.insert(seq, value);
    }
}

/// `row - c * base`, where `base` has a unit pivot equal to row's first column.
fn combine(row: &Row, base: &Row, c: u8) -> Row {
    let mut cols = Vec::with_capacity(row.cols.len() + base.cols.len());
    let (mut i, mut j) = (0, 0);
    while i < row.cols.len() || j < base.cols.len() {
        let a = row.cols.get(i);
        let b = base.cols.get(j);
        match (a, b) {
            (Some(&(sa, ca)), Some(&(sb, cb))) if sa == sb => {
                let v = ca ^ gf256::mul(c, cb);
                if v != 0 {
                    cols.push((sa, v));
                }
                i += 1;
                j += 1;
            }
            (Some(&(sa, ca)), Some(&(sb, _))) if sa < sb => {
                cols.push((sa, ca));
                i += 1;
            }
            (Some(&(sa, ca)), None) => {
                cols.push((sa, ca));
                i += 1;
            }
            (_, Some(&(sb, cb))) => {
                cols.push((sb, gf256::mul(c, cb)));
                j += 1;
            }
            (None, None) => unreachable!(),
        }
    }
    let mut rhs = row.rhs.clone();
    if !rhs.is_empty() {
        gf256::mul_add(&mut rhs, &base.rhs, c);
    }
    Row { cols, rhs }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn originals(n: u32, len: usize) -> Vec<Vec<u8>> {
        (0..n)
            .map(|seq| (0..len).map(|i| (seq as usize * 31 + i * 7) as u8 ^ 0x5a).collect())
            .collect()
    }

    #[test]
    fn rebuilds_exact_bytes_for_as_many_losses_as_repairs() {
        let data = originals(32, 1200);
        let mut decoder = Decoder::new(1200);
        let lost = [3_u32, 9, 10, 27];
        for seq in 0..32 {
            if !lost.contains(&seq) {
                decoder.add_source(seq, &data[seq as usize]);
            }
        }
        let mut rebuilt = Vec::new();
        for seed in 0..4 {
            let header = RepairHeader { first: 0, count: 32, seed };
            let payload = encode(header, |s| &data[s as usize], 1200);
            rebuilt.extend(decoder.add_repair(header, &payload));
        }
        rebuilt.sort_unstable();
        assert_eq!(rebuilt, lost);
        for seq in lost {
            assert_eq!(decoder.payload(seq).unwrap(), data[seq as usize].as_slice());
        }
    }

    #[test]
    fn repair_headers_survive_the_wire_and_reject_nonsense() {
        let header = RepairHeader { first: 70_000, count: 96, seed: 0xDEAD_BEEF };
        assert_eq!(RepairHeader::from_bytes(&header.to_bytes()), Some(header));
        assert_eq!(RepairHeader::from_bytes(&header.to_bytes()[..9]), None);
        let empty = RepairHeader { first: 1, count: 0, seed: 1 };
        assert_eq!(RepairHeader::from_bytes(&empty.to_bytes()), None);
    }

    #[test]
    fn repairs_may_arrive_before_the_originals_they_cover() {
        let data = originals(16, 64);
        let mut decoder = Decoder::new(64);
        let header = RepairHeader { first: 0, count: 16, seed: 7 };
        let payload = encode(header, |s| &data[s as usize], 64);
        assert!(decoder.add_repair(header, &payload).is_empty());
        let mut rebuilt = Vec::new();
        for seq in (0..16).filter(|&s| s != 5) {
            rebuilt.extend(decoder.add_source(seq, &data[seq as usize]));
        }
        assert_eq!(rebuilt, vec![5]);
        assert_eq!(decoder.payload(5).unwrap(), data[5].as_slice());
    }

    #[test]
    fn too_few_repairs_rebuild_nothing_and_coefficient_mode_agrees() {
        let data = originals(20, 32);
        let mut with_bytes = Decoder::new(32);
        let mut counted = Decoder::new(0);
        for seq in (0..20).filter(|s| ![2, 4, 6].contains(s)) {
            with_bytes.add_source(seq, &data[seq as usize]);
            counted.add_source(seq, &[]);
        }
        for seed in 0..2 {
            let header = RepairHeader { first: 0, count: 20, seed };
            let payload = encode(header, |s| &data[s as usize], 32);
            assert!(with_bytes.add_repair(header, &payload).is_empty());
            assert!(counted.add_repair(header, &[]).is_empty());
        }
        let header = RepairHeader { first: 0, count: 20, seed: 9 };
        let payload = encode(header, |s| &data[s as usize], 32);
        let mut a = with_bytes.add_repair(header, &payload);
        let mut b = counted.add_repair(header, &[]);
        a.sort_unstable();
        b.sort_unstable();
        assert_eq!(a, vec![2, 4, 6]);
        assert_eq!(a, b);
    }
}
