//! Real links, replayed: recordings made by `verz-link-record` stand in for
//! the fake link model. Every simulated packet gets the fate of the recorded
//! packet sent closest to the same moment: lost, or delivered after the
//! recorded round trip. Links recorded by separate processes are aligned on
//! the wall clock.
//!
//! The recording was made under the recorder's own load, so queueing from a
//! heavier simulated stream is not reproduced; keep the recording rate close
//! to the stream rate per link.

use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::sync::Arc;

/// A run of lost packets this long counts as an outage, for the detection
/// time column.
const OUTAGE_US: u64 = 150_000;

pub struct Trace {
    pub interface: String,
    pub started_unix_us: u64,
    pub mbps: f64,
    /// (send time, round trip) per packet in send order; `None` if never acknowledged.
    pub packets: Vec<(u64, Option<u64>)>,
    /// (time, carrier) changes, first entry at time 0.
    pub carrier: Vec<(u64, bool)>,
}

impl Trace {
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let mut lines = text.lines();
        let header = lines.next().and_then(|l| l.strip_prefix("# ")).ok_or("missing metadata line")?;
        let meta: serde_json::Value = serde_json::from_str(header).map_err(|e| format!("metadata: {e}"))?;
        let field = |name: &str| meta.get(name).ok_or(format!("metadata lacks {name}"));
        let interface = field("interface")?.as_str().ok_or("interface")?.to_owned();
        let started_unix_us = field("started_unix_us")?.as_u64().ok_or("started_unix_us")?;
        let mbps = field("mbps")?.as_f64().ok_or("mbps")?;
        let mut sends: BTreeMap<u64, (u64, bool)> = BTreeMap::new();
        let mut acks: HashMap<u64, u64> = HashMap::new();
        let mut carrier = Vec::new();
        for (n, line) in lines.enumerate() {
            let mut parts = line.split(',');
            let kind = parts.next().unwrap_or("");
            let a: u64 = parts.next().and_then(|v| v.parse().ok()).ok_or(format!("line {}: malformed", n + 2))?;
            let b: u64 = parts.next().and_then(|v| v.parse().ok()).ok_or(format!("line {}: malformed", n + 2))?;
            match kind {
                "s" => {
                    sends.insert(a, (b, true));
                }
                "f" => {
                    sends.insert(a, (b, false));
                }
                "a" => {
                    acks.insert(a, b);
                }
                "c" => carrier.push((a, b != 0)),
                // The recorder reopened its socket; nothing to replay.
                "r" => {}
                _ => return Err(format!("line {}: unknown record {kind}", n + 2)),
            }
        }
        if carrier.first().is_none_or(|&(t, _)| t != 0) {
            carrier.insert(0, (0, true));
        }
        let packets = sends
            .into_iter()
            .map(|(seq, (sent, ok))| {
                let rtt = if ok { acks.get(&seq).map(|&at| at.saturating_sub(sent)) } else { None };
                (sent, rtt)
            })
            .collect::<Vec<_>>();
        if packets.len() < 100 {
            return Err(format!("{}: only {} packets", path.display(), packets.len()));
        }
        Ok(Self { interface, started_unix_us, mbps, packets, carrier })
    }

    fn end_us(&self) -> u64 {
        self.packets.last().map_or(0, |p| p.0)
    }
}

/// One link of a recording, aligned to the simulator's clock.
#[derive(Clone)]
pub struct Replay {
    trace: Arc<Trace>,
    /// Added to simulator time to get the trace's own clock.
    offset_us: u64,
    /// Runs of loss long enough to count as outages, in simulator time.
    outages: Vec<(u64, u64)>,
}

impl std::fmt::Debug for Replay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Replay({}, {} packets)", self.trace.interface, self.trace.packets.len())
    }
}

impl Replay {
    /// Aligns several traces so that simulator time 0 is the moment the last
    /// recorder started. Returns the links and the common length.
    pub fn align(traces: Vec<Trace>) -> (Vec<Replay>, u64) {
        let origin = traces.iter().map(|t| t.started_unix_us).max().unwrap_or(0);
        let length = traces
            .iter()
            .map(|t| (t.started_unix_us + t.end_us()).saturating_sub(origin))
            .min()
            .unwrap_or(0);
        let replays = traces
            .into_iter()
            .map(|t| {
                let offset_us = origin - t.started_unix_us;
                let outages = find_outages(&t.packets)
                    .into_iter()
                    .filter_map(|(a, b)| (b > offset_us).then(|| (a.saturating_sub(offset_us), b - offset_us)))
                    .collect();
                Replay { trace: Arc::new(t), offset_us, outages }
            })
            .collect();
        (replays, length)
    }

    pub fn interface(&self) -> &str {
        &self.trace.interface
    }

    pub fn mbps(&self) -> f64 {
        self.trace.mbps
    }

    /// Index of the recorded packet sent closest to this moment.
    fn nearest(&self, now: u64) -> usize {
        let local = now + self.offset_us;
        let p = &self.trace.packets;
        let i = p.partition_point(|&(sent, _)| sent < local);
        if i == 0 {
            0
        } else if i == p.len() {
            p.len() - 1
        } else if local - p[i - 1].0 <= p[i].0 - local {
            i - 1
        } else {
            i
        }
    }

    /// Fate of a packet sent up now: its round trip, or `None` if lost.
    pub fn up(&self, now: u64) -> Option<u64> {
        self.trace.packets[self.nearest(now)].1
    }

    /// Delay to assume for feedback sent down now: the nearest acknowledged
    /// packet's round trip. Loss is charged to the uplink only.
    pub fn down_rtt(&self, now: u64) -> u64 {
        let p = &self.trace.packets;
        let i = self.nearest(now);
        let before = p[..=i].iter().rev().find_map(|&(_, rtt)| rtt);
        let after = p[i..].iter().find_map(|&(_, rtt)| rtt);
        before.or(after).unwrap_or(100_000)
    }

    pub fn carrier_at(&self, now: u64) -> bool {
        let local = now + self.offset_us;
        let c = &self.trace.carrier;
        let i = c.partition_point(|&(t, _)| t <= local);
        i > 0 && c[i - 1].1 || i == 0 && c.first().is_some_and(|&(_, up)| up)
    }

    pub fn down_at(&self, now: u64) -> bool {
        self.outages.iter().any(|&(a, b)| now >= a && now < b)
    }

    pub fn outages(&self) -> Vec<(u64, u64)> {
        self.outages.clone()
    }
}

/// Runs of consecutive losses spanning at least `OUTAGE_US`, as
/// (first lost send, next delivered send) in the trace's own clock.
fn find_outages(packets: &[(u64, Option<u64>)]) -> Vec<(u64, u64)> {
    let mut outages = Vec::new();
    let mut run_start: Option<u64> = None;
    for &(sent, rtt) in packets {
        match (rtt, run_start) {
            (None, None) => run_start = Some(sent),
            (Some(_), Some(start)) => {
                if sent - start >= OUTAGE_US {
                    outages.push((start, sent));
                }
                run_start = None;
            }
            _ => {}
        }
    }
    if let (Some(start), Some(&(last, _))) = (run_start, packets.last())
        && last - start >= OUTAGE_US
    {
        outages.push((start, last + 1));
    }
    outages
}

#[cfg(test)]
mod tests {
    use super::*;

    fn trace(started: u64, packets: Vec<(u64, Option<u64>)>) -> Trace {
        Trace { interface: "t".into(), started_unix_us: started, mbps: 1.0, packets, carrier: vec![(0, true)] }
    }

    #[test]
    fn links_started_at_different_times_are_aligned_on_the_wall_clock() {
        let a = trace(1_000_000, (0..100).map(|i| (i * 10_000, Some(20_000))).collect());
        let b = trace(1_300_000, (0..100).map(|i| (i * 10_000, Some(30_000))).collect());
        let (replays, length) = Replay::align(vec![a, b]);
        // b started 300 ms later; a's packet at its own 300 ms is simulator time 0.
        assert_eq!(replays[0].offset_us, 300_000);
        assert_eq!(replays[1].offset_us, 0);
        assert_eq!(length, 990_000 - 300_000);
        assert_eq!(replays[0].up(0), Some(20_000));
    }

    #[test]
    fn a_long_run_of_losses_is_an_outage_and_short_ones_are_not() {
        let mut packets: Vec<(u64, Option<u64>)> = (0..300).map(|i| (i * 10_000, Some(20_000))).collect();
        for p in &mut packets[100..120] {
            p.1 = None; // 200 ms
        }
        packets[200].1 = None; // one packet
        let (replays, _) = Replay::align(vec![trace(0, packets)]);
        assert_eq!(replays[0].outages(), vec![(1_000_000, 1_200_000)]);
        assert!(replays[0].down_at(1_100_000));
        assert!(!replays[0].down_at(2_000_000));
        assert_eq!(replays[0].up(2_000_000), None);
        assert_eq!(replays[0].up(2_010_000), Some(20_000));
    }
}
