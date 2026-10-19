//! VERZ bonding simulator.
//!
//! Replays identical link failures against the methods shipped today and the
//! experimental coded method, and reports what the destination application
//! would have seen. Everything runs on this machine: fake links, a fake
//! server and simulated time.
//!
//! ```text
//! cargo run --release -- [--scenario NAME]... [--seeds N] [--seconds N]
//!                        [--mbps F] [--deadline-ms N] [--verbose] [--timeline] [--list]
//! cargo run --release -- --record FILE [--record FILE]... [--separate-upstreams]
//! ```
//!
//! `--record` replays recordings of real links made by `verz-link-record`
//! (see `record-links.sh`) in place of the fake links.

mod link;
mod methods;
mod net;
mod replay;
mod rng;
mod scenario;

// The shipped schedulers, compiled from the engine's own source files so the
// baselines are the real code rather than imitations.
#[path = "../../../UdpEngine/src/bonded.rs"]
#[allow(dead_code)]
mod bonded;
#[path = "../../../UdpEngine/src/reassembly.rs"]
#[allow(dead_code)]
mod reassembly;

use link::{LinkSim, LinkSpec};
use methods::coded::Coded;
use methods::shipped::{Mode, Shipped};
use methods::{Log, Method, PAYLOAD};
use net::{Event, Net};
use scenario::Scenario;
use std::sync::Mutex;

const METHODS: [(&str, &str); 4] = [
    ("Split", "Bonded Speed today"),
    ("Copy", "Continuity today"),
    ("New", "coded, protects by risk"),
    ("New-always", "coded, protects every single failure"),
];

const TRAFFIC_START_US: u64 = 1_000_000;
/// Links and estimators settle before anything is counted.
const WARMUP_US: u64 = 5_000_000;
/// Traffic stops this long before the end so in-flight packets can land.
const TAIL_US: u64 = 5_000_000;

struct Options {
    scenarios: Vec<String>,
    /// Recordings of real links to replay instead of scenarios.
    records: Vec<String>,
    /// Recorded links do not share one public address.
    separate_upstreams: bool,
    seeds: u64,
    seconds: u64,
    mbps: f64,
    deadline_ms: u64,
    verbose: bool,
    /// Print per-second misses (and internal state) for one seed.
    timeline: bool,
}

#[derive(Clone, Default)]
struct Stats {
    runs: u64,
    originals: u64,
    late: u64,
    lost: u64,
    worst_gap_us: u64,
    original_bytes: u64,
    protection_bytes: u64,
    probe_bytes: u64,
    feedback_bytes: u64,
    metered_bytes: u64,
    detect_us: Vec<u64>,
    delays_us: Vec<u64>,
}

impl Stats {
    fn merge(&mut self, other: Stats) {
        self.runs += other.runs;
        self.originals += other.originals;
        self.late += other.late;
        self.lost += other.lost;
        self.worst_gap_us = self.worst_gap_us.max(other.worst_gap_us);
        self.original_bytes += other.original_bytes;
        self.protection_bytes += other.protection_bytes;
        self.probe_bytes += other.probe_bytes;
        self.feedback_bytes += other.feedback_bytes;
        self.metered_bytes += other.metered_bytes;
        self.detect_us.extend(other.detect_us);
        self.delays_us.extend(other.delays_us);
    }

    fn missed_per_run(&self) -> f64 {
        (self.late + self.lost) as f64 / self.runs.max(1) as f64
    }

    fn extra_percent(&self) -> f64 {
        100.0 * (self.protection_bytes + self.probe_bytes) as f64 / self.original_bytes.max(1) as f64
    }
}

fn run<M: Method>(mut method: M, label: &str, scenario: &Scenario, seed: u64, o: &Options) -> Stats {
    let end = o.seconds * 1_000_000;
    let stop = end - TAIL_US;
    let links = scenario
        .links
        .iter()
        .enumerate()
        .map(|(i, (spec, impairments))| {
            LinkSim::new(spec.clone(), impairments.clone(), seed.wrapping_mul(1_000).wrapping_add(i as u64))
        })
        .collect();
    let mut net: Net<M::Up, M::Down> = Net::new(links, WARMUP_US, stop);
    let mut log = Log::default();
    let interval = (PAYLOAD as f64 * 8.0 / o.mbps).round() as u64;
    let mut next_source = TRAFFIC_START_US;
    let mut next_tick = 0;
    let mut seq = 0_u32;
    let mut traces = Vec::new();
    loop {
        let now = net.next_at().unwrap_or(u64::MAX).min(next_source).min(next_tick);
        if now >= end {
            break;
        }
        if now == next_source {
            log.sent(seq, now);
            method.source(now, seq, &mut net, &mut log);
            seq += 1;
            next_source = if now + interval < stop { now + interval } else { u64::MAX };
        } else if now == next_tick {
            method.tick(now, &mut net, &mut log);
            if o.timeline && now % 500_000 == 0 {
                traces.push((now, method.trace(now)));
            }
            next_tick += 1_000;
        } else if let Some((at, event)) = net.pop() {
            match event {
                Event::Up { link, msg } => method.at_server(at, link, msg, &mut net, &mut log),
                Event::Down { link, msg } => method.at_client(at, link, msg, &mut net),
            }
        }
    }
    let stats = measure(&net, &log, o, stop);
    if o.verbose {
        eprintln!(
            "{} {label} seed {seed}: late={} lost={} probes={:.1}% protection={:.1}% {}",
            scenario.name,
            stats.late,
            stats.lost,
            100.0 * stats.probe_bytes as f64 / stats.original_bytes.max(1) as f64,
            100.0 * stats.protection_bytes as f64 / stats.original_bytes.max(1) as f64,
            method.notes()
        );
    }
    if o.timeline {
        print_timeline(label, &log, &traces, o, stop);
        print_stories(&method, &log, o);
    }
    stats
}

/// The first few misses in full, so a failure can be followed packet by packet.
fn print_stories<M: Method>(method: &M, log: &Log, o: &Options) {
    let deadline = o.deadline_ms * 1_000;
    let mut shown = 0;
    let mut out = String::new();
    for (seq, &sent) in log.sent_at.iter().enumerate() {
        if sent < WARMUP_US || log.released_at[seq].is_some_and(|at| at - sent <= deadline) {
            continue;
        }
        let story = method.story(seq as u32);
        if story.is_empty() && log.sent_on[seq].is_none() {
            continue;
        }
        let link = log.sent_on[seq].map_or("?".to_owned(), |l| format!("L{l}"));
        let arrived = log.arrived_at[seq].map_or("never arrived".to_owned(), |at| format!("arrived at {:.3}s", at as f64 / 1e6));
        let released = log.released_at[seq].map_or("not released".to_owned(), |at| format!("released at {:.3}s", at as f64 / 1e6));
        out += &format!("   seq {seq} on {link}, sent {:.3}s, {arrived}, {released}\n", sent as f64 / 1e6);
        for line in story.iter().take(12) {
            out += &format!("      {line}\n");
        }
        if story.len() > 12 {
            out += &format!("      ... {} more\n", story.len() - 12);
        }
        if shown == 0 {
            let lines = method.between(sent.saturating_sub(20_000), sent + deadline);
            out += &format!("   around the first miss ({} events):\n", lines.len());
            for line in lines.iter().take(400) {
                out += &format!("      {line}\n");
            }
        }
        shown += 1;
        if shown == 6 {
            break;
        }
    }
    print!("{out}");
}

fn print_timeline(label: &str, log: &Log, traces: &[(u64, String)], o: &Options, stop: u64) {
    let deadline = o.deadline_ms * 1_000;
    let mut missed = vec![0_u32; (stop / 500_000) as usize + 1];
    for (seq, &sent) in log.sent_at.iter().enumerate() {
        if !log.released_at[seq].is_some_and(|at| at - sent <= deadline) {
            missed[(sent / 500_000) as usize] += 1;
        }
    }
    let mut out = format!("--- {label}\n");
    for (at, trace) in traces.iter().filter(|(at, _)| *at < stop) {
        let i = (at / 500_000) as usize;
        out += &format!("{:>5.1}s missed {:>4}  {trace}\n", *at as f64 / 1e6, missed[i]);
    }
    // Why each miss happened, per link the original was sent on.
    let mut per_link: std::collections::BTreeMap<u8, [u32; 3]> = Default::default();
    let mut late_by = Vec::new();
    for (seq, &sent) in log.sent_at.iter().enumerate() {
        if sent < WARMUP_US || log.released_at[seq].is_some_and(|at| at - sent <= deadline) {
            continue;
        }
        let Some(link) = log.sent_on[seq] else {
            continue;
        };
        let counts = per_link.entry(link).or_default();
        match log.arrived_at[seq] {
            None => counts[0] += 1,
            Some(at) if at - sent > deadline => {
                counts[1] += 1;
                late_by.push(at - sent - deadline);
            }
            Some(_) => counts[2] += 1,
        }
    }
    for (link, [dropped, late, held]) in per_link {
        out += &format!("   L{link}: {dropped} dropped by the link, {late} arrived late, {held} arrived in time but were released late\n");
    }
    if let Some(p50) = percentile(&mut late_by, 0.5) {
        out += &format!("   late arrivals missed the deadline by {} (median)\n", ms(p50));
    }
    print!("{out}");
}

fn measure<U, D>(net: &Net<U, D>, log: &Log, o: &Options, stop: u64) -> Stats {
    let deadline = o.deadline_ms * 1_000;
    let mut s = Stats { runs: 1, ..Default::default() };
    let mut gap_from: Option<u64> = None;
    for (seq, &sent) in log.sent_at.iter().enumerate() {
        if sent < WARMUP_US {
            continue;
        }
        s.originals += 1;
        let on_time = match log.released_at[seq] {
            Some(at) if at - sent <= deadline => {
                s.delays_us.push(at - sent);
                true
            }
            Some(_) => {
                s.late += 1;
                false
            }
            None => {
                s.lost += 1;
                false
            }
        };
        if on_time {
            if let Some(from) = gap_from.take() {
                s.worst_gap_us = s.worst_gap_us.max(sent - from);
            }
        } else {
            gap_from.get_or_insert(sent);
        }
    }
    if let Some(from) = gap_from {
        s.worst_gap_us = s.worst_gap_us.max(stop - from);
    }
    for (i, link) in net.links.iter().enumerate() {
        let [original, protection, probe] = net.up_bytes[i];
        s.original_bytes += original;
        s.protection_bytes += protection;
        s.probe_bytes += probe;
        s.feedback_bytes += net.down_bytes[i];
        if link.spec.metered {
            s.metered_bytes += original + protection + probe + net.down_bytes[i];
        }
        // How long the method kept placing originals on a link after it failed.
        for (start, end) in link.outages() {
            if start < WARMUP_US || start >= stop {
                continue;
            }
            let last = net.originals[i].iter().rev().find(|&&t| t >= start && t < end);
            s.detect_us.push(last.map_or(0, |t| t - start));
        }
    }
    s
}

fn run_method(method: usize, scenario: &Scenario, seed: u64, o: &Options) -> Stats {
    let specs: Vec<LinkSpec> = scenario.links.iter().map(|(spec, _)| spec.clone()).collect();
    let deadline = o.deadline_ms * 1_000;
    let label = METHODS[method].0;
    match method {
        0 => run(Shipped::new(Mode::Split, specs.len()), label, scenario, seed, o),
        1 => run(Shipped::new(Mode::Copy, specs.len()), label, scenario, seed, o),
        2 => run(Coded::new(&specs, deadline, false), label, scenario, seed, o),
        3 => run(Coded::new(&specs, deadline, true), label, scenario, seed, o),
        _ => unreachable!(),
    }
}

fn percentile(values: &mut [u64], p: f64) -> Option<u64> {
    if values.is_empty() {
        return None;
    }
    values.sort_unstable();
    let i = ((values.len() - 1) as f64 * p).round() as usize;
    Some(values[i])
}

fn ms(us: u64) -> String {
    format!("{} ms", (us as f64 / 1_000.0).round())
}

fn print_scenario(scenario: &Scenario, results: &mut [Stats]) {
    let held_out = if scenario.held_out { " (held out)" } else { "" };
    println!("\n== {}{held_out} [{}]: {}", scenario.name, scenario.profile, scenario.summary);
    let links: Vec<String> = scenario.links.iter().map(|(l, _)| format!("{} ({})", l.name, l.kind)).collect();
    println!("   links: {}", links.join(", "));
    println!(
        "   {:<11} {:>9} {:>11} {:>9} {:>11} {:>12} {:>11}",
        "Method", "Missed", "Worst gap", "p99 delay", "Extra data", "Metered/run", "Detect"
    );
    for (i, s) in results.iter_mut().enumerate() {
        let detect = if s.detect_us.is_empty() {
            "-".to_owned()
        } else {
            ms(s.detect_us.iter().sum::<u64>() / s.detect_us.len() as u64)
        };
        let p99 = percentile(&mut s.delays_us, 0.99).map_or("-".to_owned(), ms);
        println!(
            "   {:<11} {:>9.1} {:>11} {:>9} {:>10.1}% {:>9.1} MB {:>11}",
            METHODS[i].0,
            s.missed_per_run(),
            ms(s.worst_gap_us),
            p99,
            s.extra_percent(),
            s.metered_bytes as f64 / s.runs.max(1) as f64 / 1e6,
            detect,
        );
    }
}

fn parse() -> Result<Option<Options>, String> {
    let mut o = Options {
        scenarios: Vec::new(),
        records: Vec::new(),
        separate_upstreams: false,
        seeds: 3,
        seconds: 0,
        mbps: 8.0,
        deadline_ms: 200,
        verbose: false,
        timeline: false,
    };
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let mut value = |name: &str| args.next().ok_or(format!("{name} needs a value"));
        match arg.as_str() {
            "--scenario" => o.scenarios.push(value("--scenario")?),
            "--record" => o.records.push(value("--record")?),
            "--separate-upstreams" => o.separate_upstreams = true,
            "--seeds" => o.seeds = value("--seeds")?.parse().map_err(|e| format!("--seeds: {e}"))?,
            "--seconds" => o.seconds = value("--seconds")?.parse().map_err(|e| format!("--seconds: {e}"))?,
            "--mbps" => o.mbps = value("--mbps")?.parse().map_err(|e| format!("--mbps: {e}"))?,
            "--deadline-ms" => {
                o.deadline_ms = value("--deadline-ms")?.parse().map_err(|e| format!("--deadline-ms: {e}"))?;
            }
            "--verbose" | "-v" => o.verbose = true,
            "--timeline" => o.timeline = true,
            "--list" => {
                for s in scenario::all() {
                    let held_out = if s.held_out { " (held out)" } else { "" };
                    println!("{:<24} {:<7} {}{held_out}", s.name, s.profile, s.summary);
                }
                return Ok(None);
            }
            "-h" | "--help" => {
                println!(
                    "usage: verz-sim [--scenario NAME]... [--record FILE]... [--separate-upstreams] [--seeds N] [--seconds N] [--mbps F] [--deadline-ms N] [--verbose] [--timeline] [--list]"
                );
                return Ok(None);
            }
            other => return Err(format!("unknown argument {other}")),
        }
    }
    if o.timeline || !o.records.is_empty() {
        // A recording replays identically every time.
        o.seeds = 1;
    }
    if o.seconds == 0 {
        o.seconds = 60;
        // A recording is replayed in full unless told otherwise.
        if !o.records.is_empty() {
            o.seconds = u64::MAX;
        }
    }
    if o.seconds * 1_000_000 <= WARMUP_US + TAIL_US {
        return Err("--seconds must exceed 10".into());
    }
    Ok(Some(o))
}

fn main() {
    let o = match parse() {
        Ok(Some(o)) => o,
        Ok(None) => return,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(2);
        }
    };
    let mut o = o;
    let scenarios: Vec<Scenario> = if o.records.is_empty() {
        scenario::all()
            .into_iter()
            .filter(|s| o.scenarios.is_empty() || o.scenarios.iter().any(|name| s.name.contains(name.as_str())))
            .collect()
    } else {
        let mut traces = Vec::new();
        for path in &o.records {
            match replay::Trace::load(std::path::Path::new(path)) {
                Ok(trace) => traces.push(trace),
                Err(e) => {
                    eprintln!("{e}");
                    std::process::exit(2);
                }
            }
        }
        let (replays, length_us) = replay::Replay::align(traces);
        let (scenario, length_s) = scenario::recorded(replays, length_us, !o.separate_upstreams);
        if length_s * 1_000_000 <= WARMUP_US + TAIL_US {
            eprintln!("the recordings overlap for only {length_s} s; at least 11 s are needed");
            std::process::exit(2);
        }
        o.seconds = o.seconds.min(length_s);
        vec![scenario]
    };
    if scenarios.is_empty() {
        eprintln!("no scenario matches; see --list");
        std::process::exit(2);
    }
    println!(
        "Stream: {} Mbps of {}-byte packets, each due within {} ms. {} s per run, {} seeds, counted from {} s.",
        o.mbps,
        PAYLOAD,
        o.deadline_ms,
        o.seconds,
        o.seeds,
        WARMUP_US / 1_000_000
    );
    for (name, about) in METHODS {
        println!("  {name:<11} {about}");
    }

    let jobs: Vec<(usize, usize, u64)> = (0..scenarios.len())
        .flat_map(|s| (0..METHODS.len()).flat_map(move |m| (0..o.seeds).map(move |seed| (s, m, seed + 1))))
        .collect();
    let results = Mutex::new(vec![vec![Stats::default(); METHODS.len()]; scenarios.len()]);
    let next = Mutex::new(0_usize);
    let workers = std::thread::available_parallelism().map_or(4, |n| n.get());
    std::thread::scope(|scope| {
        for _ in 0..workers {
            scope.spawn(|| loop {
                let job = {
                    let mut next = next.lock().unwrap();
                    let job = jobs.get(*next).copied();
                    *next += 1;
                    job
                };
                let Some((s, m, seed)) = job else {
                    break;
                };
                let stats = run_method(m, &scenarios[s], seed, &o);
                results.lock().unwrap()[s][m].merge(stats);
            });
        }
    });

    let mut results = results.into_inner().unwrap();
    for (scenario, row) in scenarios.iter().zip(results.iter_mut()) {
        print_scenario(scenario, row);
    }
    // Held-out scenarios are summarised apart: the coded method was tuned on
    // the others, so only these show whether it generalises.
    for (title, held_out) in [("Tuned scenarios", false), ("Held-out scenarios", true)] {
        let rows: Vec<&Vec<Stats>> =
            scenarios.iter().zip(&results).filter(|(s, _)| s.held_out == held_out).map(|(_, r)| r).collect();
        if rows.is_empty() {
            continue;
        }
        println!("\n== {title} ({}), averaged per scenario", rows.len());
        println!("   {:<11} {:>14} {:>11} {:>11}", "Method", "Missed/run", "Worst gap", "Extra data");
        for (i, (name, _)) in METHODS.iter().enumerate() {
            let n = rows.len() as f64;
            let missed = rows.iter().map(|r| r[i].missed_per_run()).sum::<f64>() / n;
            let extra = rows.iter().map(|r| r[i].extra_percent()).sum::<f64>() / n;
            let worst = rows.iter().map(|r| r[i].worst_gap_us).max().unwrap_or(0);
            println!("   {name:<11} {missed:>14.1} {:>11} {extra:>10.1}%", ms(worst));
        }
    }
}
