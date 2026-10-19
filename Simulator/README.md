# VERZ bonding simulator

Tests bonding methods against identical, repeatable link failures before any
of them touches the app or the relay. Everything runs on one Mac: fake links,
a fake server and simulated time. Nothing here talks to a real network.

```sh
cd Simulator
cargo run --release -- --list                     # scenarios
cargo run --release -- --seeds 5                  # full comparison (~7 s)
cargo run --release -- --scenario phone --verbose # one family, with internals
cargo run --release -- --scenario router-modem-drop --timeline  # per 0.5 s
cargo test --release                              # 58 tests
```

Options: `--mbps` (stream rate, default 8), `--deadline-ms` (default 200),
`--seconds` (default 60), `--seeds` (default 3).

## What is compared

| Name | What it runs |
|---|---|
| **Split** | Bonded Speed as shipped. `UdpEngine/src/bonded.rs` and `reassembly.rs` are compiled **from the engine's own files**, with the shared-core `Sender`. |
| **Copy** | Continuity as shipped: `Sender::forward` plus a copy on every other live link, received by the real class-4 reassembly. |
| **New** | `Engine/vendor/verz-bonding-core/`: originals placed by the same Bonded Speed scheduler, plus the new protection layer. Protects according to risk. |
| **New-always** | The same, but always protects against any single link failing. |

Only the glue from `UdpEngine/src/lib.rs` and `gateway.rs` is re-expressed in
`sim/src/methods/shipped.rs`: 100 ms heartbeats, "healthy means a reply within
the last second", ACK/NACK sent on every known path, and the 10 ms gateway sweep.

## Real links

`record-links.sh` records this Mac's Wi-Fi (`en0`) and LAN (`en7`) against
the measurement relay already running on the server (`verz-link-relay`, UDP
39000) with `Engine/src/bin/verz-link-record.rs`. Nothing on the server
changes; it only acknowledges. Every send, every acknowledgement and every
carrier change go to `recordings/<stamp>-<interface>.csv`.

```sh
Simulator/record-links.sh 10 3    # 10 minutes, 3 Mbit/s per link
# meanwhile: pull the LAN cable, switch Wi-Fi off and on, walk out of range
cd Simulator && cargo run --release -- --record recordings/<stamp>-en0.csv --record recordings/<stamp>-en7.csv
```

The simulator then replays the recordings in place of fake links
(`sim/src/replay.rs`): every simulated packet gets the fate of the recorded
packet sent closest to the same moment, lost or delivered after the recorded
round trip. Links recorded by separate processes are aligned on the wall
clock. Both links here share one public address, so they are treated as one
ISP (`--separate-upstreams` otherwise).

Replay limits: the recording was made under the recorder's own load, so
queueing from a heavier simulated stream is not reproduced (record at about
the stream rate per link: 3–4 Mbit/s each for an 8 Mbit/s stream over two
links); loss is charged to the uplink only; one-way delay is half the round trip.

## The new method (`Engine/vendor/verz-bonding-core/`)

Sans-IO: it never opens sockets or reads clocks, so the same code can run on
macOS, iOS, Android, Windows, the router and the server.

1. **Repair packets instead of copies.** A repair is a GF(256) combination of
   the recent unconfirmed originals. One repair rebuilds *any one* missing
   original in its range; nobody needs to know which one was lost.
2. **Failure detection from feedback rhythm** (`health.rs`). Two kinds of
   evidence, each judged against what the link itself has shown to be normal:
   a send left unanswered longer than its usual round trip, and feedback
   that stops arriving on a busy link. Bayes' rule turns either into a
   probability of failure. Detection takes about 10 ms on wired links and
   30–50 ms on cellular, against about 1 s for the heartbeat timeout.
3. **Exact per-link loss counts.** Every report says how many packets arrived
   on each link. Links deliver in order, so the sender knows exactly how many
   it lost, one round trip later, without naming them. It repairs at once on a
   different link, and stops using a link whose loss rate passes 20%.
4. **Minimum-cost protection** (`planner.rs`). An exact linear program chooses
   standing repair rates per link so that any protected failure is survivable.
   With 3 equal links that is +50% data instead of +200% for copies. Metered
   links are used last.
5. **Shared-fate learning.** Links behind the same public IP, or seen failing at
   the same moment, are treated as one failure, and emergency repairs avoid them.
6. **Risk-based protection.** Standing repairs are paid for only when fast
   reaction could not rebuild the loss before its deadline.
7. **Congestion handling** (`delay.rs`, `Slow` state). The lowest echo delay
   over 10 s is the link's delay with an empty queue; the lowest over the
   last 30 ms is its delay now. The difference is the queue. A link whose
   queue would make packets late becomes *Slow*: still used by the scheduler
   with its true delay when nothing better exists, never for repairs. While
   it queues, its delivery rate is measured as its capacity, and after it
   recovers originals are admitted at that rate, growing 25% per second
   while it keeps up, so it is never flooded again on re-admission.
8. **Bounded bursts, uncoupled repairs.** A repair burst is capped by what
   each target link can work off before the repairs would be late. Reactive
   repairs end at the last packet their link has echoed, so a loss on one
   link is never held hostage to an undetected loss on another; covers of a
   failed link carry a few extra repairs for the same reason.

## Results on real links (first recording, 2026-10-19)

Six minutes of this Mac's Wi-Fi and LAN at 3 Mbit/s each, with the links
disabled by hand: Wi-Fi off/on, LAN cable out/in (twice), both off together
for ~10 s. Replayed as an 8 Mbit/s stream with a 200 ms deadline.

| | Missed | Extra data |
|---|---|---|
| Split | 11,437 | +0.3% |
| Copy | 10,878 | +84% |
| **New** | **10,701** | **+0.4%** |

All of New's misses fall in the ~13 s window where both links were off,
where nothing can deliver. In every window with one link alive New missed
nothing; Split missed 479 and Copy 45.

Before this recording the method lost 1,302 packets in the first cable-pull
window alone. Real Wi-Fi stalls for 100–150 ms about 1% of the time, and the
detector called that "dead" with near certainty; with the LAN out it then
refused to send at all. Three changes came out of the recording: a link with
a carrier is always better than nothing; the round-trip evidence respects a
real 1% stall rate (99th-percentile anchor); and the wait recorded for an
echo is that of the *oldest* packet it answers, since after a stall the echo
names the newest packet of the burst and would hide the stall. None of this
was visible on the synthetic links.

## Results on synthetic links (5 seeds, 8 Mbps, 200 ms deadline)

Averaged per scenario. "Missed" means packets that never arrived or arrived
after the deadline, out of about 41,700 per run. Seed-to-seed spread is
large on the router scenarios (±30% is common), so small differences are noise.

| | Missed/run | Worst gap | Extra data |
|---|---|---|---|
| Split | 1,358 | 251 ms | 2.6% |
| Copy | 94 | 781 ms | 180% |
| **New** | **35** | **130 ms** | **2.9%** |

Held-out scenarios (added after tuning, never tuned against):

| Scenario | Split | Copy | New |
|---|---|---|---|
| laptop-wifi-flapping | 87 missed, +0.3% | 1.2 missed, +100% | **0 missed, +1.3%** |
| router-congested-modem | 2,806, +6% | **2.0, +197%** | 79, +4% |
| phone-cell-fade (over capacity) | 13,688 | 9,033 | 11,228 |

Before congestion handling and the real recording, New scored 9.6 missed at
+12% on the tuned set and 175 missed at +36% on the congested modem. Each
robustness fix driven by real links lowered the data cost further and cost a
few more misses on the synthetic router scenarios (same-tower 24→105,
satellite blips 14→114), whose cellular model has exponential jitter and no
stalls. Those synthetic cellular links are now the least trusted part of the
simulator; recordings of real cellular links should settle it. Making the
risk model more eager (a five-minute prior on the failure rate) was tried and
reverted: it switched protection on everywhere and cost more packets than it saved.

The full table is printed by `cargo run --release -- --seeds 5`.

## Limits — read before drawing product conclusions

- **The New method was tuned on the nine non-held-out scenarios.** Their
  numbers flatter it. The held-out scenarios are the fairer test.
- **Congestion is handled, but the first episode still costs packets.** A
  queue is seen one round trip late; on the congested modem the first 100 ms
  of queueing puts ~50 packets beyond their deadline before the link is
  avoided. Copy wins there (2 vs 124 missed) at 22× the data.
- **Protection economics are unsettled.** When to buy standing repairs is
  decided from an estimated failure rate per link; a link carrying 75% of
  the stream that blips every 15 s is the case where this matters most, and
  the better answer is probably to move traffic *off* such a link rather
  than protect it. Not done.
- **Link capacity is assumed to be 10 Mbps** until a link congests or the
  scheduler has measured more (`ASSUMED_CAPACITY_BPS` in
  `sim/src/methods/coded.rs`). Real per-link capacity probing still has to be built.
- **When total capacity is below the stream rate, nothing works**
  (`phone-cell-fade`). The product needs to tell the encoder to lower the
  bitrate; bonding cannot fix that.
- **The results above are from synthetic links.** Their parameters are
  typical, not measured. Recordings of real links can now be replayed (see
  *Real links*); the first recordings with real failures are the next step.
- The server's decoding cost is not measured yet. The simulator tracks which
  packets can be rebuilt, not the bytes. Byte-exact rebuilding is covered by
  the core crate's tests.
