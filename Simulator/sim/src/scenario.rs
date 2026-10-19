//! Device profiles and the failures they face.
//!
//! Link numbers are typical, not measured: replace them with recordings of
//! real links before drawing product conclusions.

use crate::link::{BurstLoss, Impairment, LinkSpec};
use crate::replay::Replay;

pub struct Scenario {
    pub name: &'static str,
    pub profile: &'static str,
    pub summary: &'static str,
    /// Added after the coded method was tuned, and never tuned against:
    /// the honest check that it was not fitted to the other scenarios.
    pub held_out: bool,
    pub links: Vec<(LinkSpec, Vec<Impairment>)>,
}

const fn s(seconds: f64) -> u64 {
    (seconds * 1e6) as u64
}

fn link(name: &str, kind: &'static str, upstream: u32) -> LinkSpec {
    let mut spec = LinkSpec {
        name: name.into(),
        kind,
        owd_ms: 10.0,
        jitter_ms: 1.0,
        up_mbps: 50.0,
        queue_ms: 60.0,
        loss: BurstLoss::NONE,
        wandering: false,
        metered: false,
        upstream,
        replay: None,
    };
    match kind {
        "fiber" => {
            spec.owd_ms = 8.0;
            spec.jitter_ms = 0.5;
            spec.up_mbps = 100.0;
            spec.queue_ms = 50.0;
            spec.loss = BurstLoss { good_to_bad: 0.000_5, bad_to_good: 0.3, loss_good: 0.0, loss_bad: 0.3 };
        }
        "dsl" => {
            spec.owd_ms = 14.0;
            spec.jitter_ms = 1.5;
            spec.up_mbps = 12.0;
            spec.queue_ms = 80.0;
            spec.loss = BurstLoss { good_to_bad: 0.001, bad_to_good: 0.3, loss_good: 0.0, loss_bad: 0.3 };
        }
        "wifi" => {
            spec.owd_ms = 10.0;
            spec.jitter_ms = 3.0;
            spec.up_mbps = 40.0;
            spec.queue_ms = 60.0;
            spec.loss = BurstLoss { good_to_bad: 0.003, bad_to_good: 0.25, loss_good: 0.001, loss_bad: 0.25 };
        }
        "cellular" => {
            spec.owd_ms = 30.0;
            spec.jitter_ms = 10.0;
            spec.up_mbps = 20.0;
            spec.queue_ms = 250.0;
            spec.loss = BurstLoss { good_to_bad: 0.004, bad_to_good: 0.15, loss_good: 0.002, loss_bad: 0.2 };
            spec.wandering = true;
            spec.metered = true;
        }
        "satellite" => {
            spec.owd_ms = 28.0;
            spec.jitter_ms = 8.0;
            spec.up_mbps = 20.0;
            spec.queue_ms = 120.0;
            spec.loss = BurstLoss { good_to_bad: 0.002, bad_to_good: 0.2, loss_good: 0.001, loss_bad: 0.2 };
            spec.wandering = true;
        }
        _ => unreachable!("unknown link kind {kind}"),
    }
    spec
}

fn silent(start: f64, end: f64) -> Impairment {
    Impairment::Outage { start: s(start), end: s(end), visible: false }
}

fn visible(start: f64, end: f64) -> Impairment {
    Impairment::Outage { start: s(start), end: s(end), visible: true }
}

pub fn all() -> Vec<Scenario> {
    vec![
        Scenario {
            name: "laptop-steady",
            profile: "laptop",
            held_out: false,
            summary: "Wi-Fi + fiber LAN + DSL LAN, three ISPs, no failure (normal-day cost)",
            links: vec![
                (link("Wi-Fi", "wifi", 1), vec![]),
                (link("LAN fiber", "fiber", 2), vec![]),
                (link("LAN DSL", "dsl", 3), vec![]),
            ],
        },
        Scenario {
            name: "laptop-cable-pull",
            profile: "laptop",
            held_out: false,
            summary: "fiber LAN cable pulled at 20 s for 15 s (the OS sees it)",
            links: vec![
                (link("Wi-Fi", "wifi", 1), vec![]),
                (link("LAN fiber", "fiber", 2), vec![visible(20.0, 35.0)]),
                (link("LAN DSL", "dsl", 3), vec![]),
            ],
        },
        Scenario {
            name: "laptop-isp-outage",
            profile: "laptop",
            held_out: false,
            summary: "fiber ISP fails silently at 20 s for 10 s (cable still plugged in)",
            links: vec![
                (link("Wi-Fi", "wifi", 1), vec![]),
                (link("LAN fiber", "fiber", 2), vec![silent(20.0, 30.0)]),
                (link("LAN DSL", "dsl", 3), vec![]),
            ],
        },
        Scenario {
            name: "laptop-shared-isp",
            profile: "laptop",
            held_out: false,
            summary: "two LANs behind one ISP both fail silently at 20 s; Wi-Fi is another ISP",
            links: vec![
                (link("Wi-Fi", "wifi", 1), vec![]),
                (link("LAN 1", "fiber", 2), vec![silent(20.0, 30.0)]),
                (link("LAN 2", "dsl", 2), vec![silent(20.0, 30.0)]),
            ],
        },
        Scenario {
            name: "phone-leave-wifi",
            profile: "phone",
            held_out: false,
            summary: "walking away: Wi-Fi loss ramps to 100% over 3 s from 20 s, then disassociates",
            links: vec![
                (
                    link("Wi-Fi", "wifi", 1),
                    vec![
                        Impairment::LossRamp { start: s(20.0), end: s(23.0), from: 0.0, to: 1.0 },
                        visible(23.0, 1e6),
                    ],
                ),
                (link("Cellular", "cellular", 2), vec![]),
            ],
        },
        Scenario {
            name: "phone-dead-zone",
            profile: "phone",
            held_out: false,
            summary: "cellular silently stops for 3 s at 20 s (tunnel, elevator)",
            links: vec![
                (link("Wi-Fi", "wifi", 1), vec![]),
                (link("Cellular", "cellular", 2), vec![silent(20.0, 23.0)]),
            ],
        },
        Scenario {
            name: "router-modem-drop",
            profile: "router",
            held_out: false,
            summary: "4 cellular modems; modem 1 silently drops for 5 s at 20 s",
            links: vec![
                (link("Modem 1", "cellular", 11), vec![silent(20.0, 25.0)]),
                (link("Modem 2", "cellular", 12), vec![]),
                (link("Modem 3", "cellular", 13), vec![]),
                (link("Modem 4", "cellular", 14), vec![]),
            ],
        },
        Scenario {
            name: "router-same-tower",
            profile: "router",
            held_out: false,
            summary: "modems 1+2 share a tower: both drop at 20 s and again at 40 s (3 s each)",
            links: vec![
                (link("Modem 1", "cellular", 11), vec![silent(20.0, 23.0), silent(40.0, 43.0)]),
                (link("Modem 2", "cellular", 12), vec![silent(20.0, 23.0), silent(40.0, 43.0)]),
                (link("Modem 3", "cellular", 13), vec![]),
                (link("Modem 4", "cellular", 14), vec![]),
            ],
        },
        Scenario {
            name: "router-satellite-blips",
            profile: "router",
            held_out: false,
            summary: "satellite + 2 modems; satellite blacks out 150 ms every 15 s",
            links: vec![
                (
                    link("Satellite", "satellite", 21),
                    vec![silent(15.0, 15.15), silent(30.0, 30.15), silent(45.0, 45.15)],
                ),
                (link("Modem 1", "cellular", 11), vec![]),
                (link("Modem 2", "cellular", 12), vec![]),
            ],
        },
        // Held out from here on.
        Scenario {
            name: "laptop-wifi-flapping",
            profile: "laptop",
            held_out: true,
            summary: "Wi-Fi + fiber LAN; Wi-Fi silently drops for 300 ms every 3 s from 15 s to 45 s",
            links: vec![
                (link("Wi-Fi", "wifi", 1), (0..10).map(|i| silent(15.0 + 3.0 * i as f64, 15.3 + 3.0 * i as f64)).collect()),
                (link("LAN fiber", "fiber", 2), vec![]),
            ],
        },
        Scenario {
            name: "phone-cell-fade",
            profile: "phone",
            held_out: true,
            summary: "slow cafe Wi-Fi (6 Mbps) + cellular; cellular fades to 15% over 10 s from 20 s, leaving less capacity than the stream needs",
            links: vec![
                (LinkSpec { up_mbps: 6.0, ..link("Wi-Fi", "wifi", 1) }, vec![]),
                (link("Cellular", "cellular", 2), vec![Impairment::CapacityRamp { start: s(20.0), end: s(30.0), to: 0.15 }]),
            ],
        },
        Scenario {
            name: "router-congested-modem",
            profile: "router",
            held_out: true,
            summary: "3 modems; modem 1's cell congests to 10% capacity at 20 s for 10 s (no outage, deep queue)",
            links: vec![
                (
                    link("Modem 1", "cellular", 11),
                    vec![
                        Impairment::CapacityRamp { start: s(20.0), end: s(20.5), to: 0.1 },
                        Impairment::CapacityRamp { start: s(30.0), end: s(30.5), to: 1.0 },
                    ],
                ),
                (link("Modem 2", "cellular", 12), vec![]),
                (link("Modem 3", "cellular", 13), vec![]),
            ],
        },
    ]
}

/// Recorded real links, aligned, as one scenario. Returns it with the
/// recording's length in seconds.
pub fn recorded(replays: Vec<Replay>, length_us: u64, shared_upstream: bool) -> (Scenario, u64) {
    let names: Vec<String> = replays.iter().map(|r| format!("{} at {} Mbit/s", r.interface(), r.mbps())).collect();
    let links = replays
        .into_iter()
        .enumerate()
        .map(|(i, replay)| {
            let spec = LinkSpec {
                name: replay.interface().to_owned(),
                kind: "recorded",
                owd_ms: 0.0,
                jitter_ms: 0.0,
                // Delay and loss come from the recording; no model queue.
                up_mbps: 1e6,
                queue_ms: 0.0,
                loss: BurstLoss::NONE,
                wandering: false,
                metered: false,
                upstream: if shared_upstream { 1 } else { i as u32 + 1 },
                replay: Some(replay),
            };
            (spec, Vec::new())
        })
        .collect();
    let scenario = Scenario {
        name: "recorded",
        profile: "real",
        held_out: true,
        summary: Box::leak(format!("replayed recordings: {}", names.join(", ")).into_boxed_str()),
        links,
    };
    (scenario, length_us / 1_000_000)
}
