# Throughput investigation — September 8, 2026

## Version 0.2.3 follow-up: acknowledged-packet loss

The one-source reproduction released 1,499 reordered TCP packets into the old
1,024-packet PacketWriter channel. It dropped 475 packets after Scheduler had
marked them received and generated ACKs. Outer retries were then suppressed
as duplicates, leaving inner TCP to recover. This can occur with one uplink;
multiple adapters are not required for a missing/reordered segment.

The fix reserves an admission slot before Scheduler marks or acknowledges
new data. A full queue produces no ACK and no receive marking, preserving
retry eligibility. Already accepted duplicates and probes remain serviceable
even when the queue is full. TcpReorder now belongs to the writer task and
released bursts are written directly, without a second smaller lossy channel.
Large write batches yield every 32 packets; no reactor wait on a blocked TUN
is introduced. Reorder and input storage remain bounded. Writer errors stop
the session rather than silently discarding acknowledged traffic.

Six runtime tests cover the 1,499-packet burst, one-source admission/retry,
shared multi-client admission, closed/failed writers, and retained Join.
The existing 36 library and 7 Swift tests also pass. On the one-CPU relay,
the controlled cut test retained TCP/hash integrity and 650/650 ICMP replies
with a 73.441 ms maximum observed gap. The fast virtual-link fixture measured
188.59 Mbps and 650/650 replies (55.394 ms maximum gap). Neither fixture is
a Speedtest result or a physical Mac failover acceptance result.

New telemetry separates receive_backpressure and socket_backpressure from
queue_drops, which now counts outbound scheduler admission drops. Refused
receive admission is not an acknowledged-packet loss: the sender may retry.
Remaining outbound drops, single-core packet-I/O cost, and Wi-Fi health
instability still need measurement; this fix is not a 300 Mbps claim.

The diagnosis-only comparison immediately before this fix measured one-stream
private-relay download 176.51 Mbps with both links and 249.82 Mbps with Ethernet
alone. Uploads varied across the short 16 MiB runs. Background traffic was not
stopped and the live session retained learned congestion state, so those are
diagnostic observations, not a repeated controlled A/B acceptance result.
During the Ethernet interval queue_drops rose by 177 and relay CPU reached
91% for one second (32% user / 59% system). A subsequent sample profile showed
18.20% of CPU samples in virtio transmit notification work. CPU optimization
remains separate from the confirmed queue/ACK correctness fix.

### Deployed 0.2.3 Mac checks

| Mode | Single-stream download | Three 16 MiB uploads |
| --- | ---: | --- |
| Wi-Fi + Ethernet | 202.84 Mbps | 151.31, 168.61, 162.27 Mbps |
| Ethernet alone | 231.64 Mbps | 170.03, 182.51, 188.06 Mbps |

Both downloaded 124,886,528 bytes and passed all download/upload SHA-256
checks. These are private-relay TCP tests, not Speedtest. Artifacts are
/tmp/verz-mac-throughput.pFaNVm and /tmp/verz-mac-throughput.2FzSya.
Across both test intervals the relay reported zero outbound queue_drops and
zero socket_backpressure; kernel UDP receive drops also remained zero.
receive_backpressure was 4 after the dual-link check and 79 after the
single-link check: these admissions were refused without false ACKs and the
transfers still completed with correct hashes. The new counter must not be
confused with the old acknowledged-packet delivery drops.

The previously observed Ethernet-only download was 249.82 Mbps; this run's
231.64 Mbps is lower. Background traffic, elapsed time, and retained congestion
state prevent a clean speed attribution. Do not claim the correctness fix
alone improves every throughput measurement or establishes no-regression.
Both Use switches and the user's Metered settings were restored/preserved.
The signed universal 0.2.3 app and matching relay are deployed; further
throughput and physical failover acceptance work remains.

The user reports over 300 Mbps direct and approximately 40 Mbps download /
30 Mbps upload with VERZ. Wi-Fi and Ethernet use the same router. If that
router has one 300 Mbps internet service, the target is to preserve that
capacity, not claim 600 Mbps from two local connections to it.

## Confirmed software problems

1. ReplayWindow scanned its entire BTreeSet on every authenticated packet.
   Two full windows on the one-CPU relay processed 100,000 packets in 7.432091 s
   (74,321 ns/packet), before encryption, syscalls, scheduling or TCP work.
   A fixed ring of exact counter tags reduced that microbenchmark to
   0.001934 s (19.3 ns/packet). This is NOT network throughput.
2. The relay UDP socket had a 212,992-byte receive buffer and recorded receive
   buffer drops. The new runtime requests larger per-socket buffers without
   changing global sysctls. Linux's privileged socket options apply only to
   this runtime's sockets; unprivileged diagnostics use normal kernel limits.
3. TCP resequencing allowed only 64 packets per flow (roughly 77 KB). That is
   insufficient for a 300 Mbps path with a 40 ms arrival difference (1.5 MB).
   The new bound is 4,096 packets per flow and 8,192 globally. The hold bound is
   80 ms, covering the outer repair's 70 ms minimum timer plus a short alternate
   RTT; the old 50 ms hold released gaps before repair could arrive. ACK-only
   TCP/UDP never wait here. A 1,498-packet out-of-order burst test passes.
4. Idle probe failures repeatedly halved learned capacity even without lost
   data. Eligibility still changes immediately, but only actual data repairs
   now invoke congestion backoff. Added faster initial capacity discovery and
   retained fractional additive growth for large congestion windows.
5. Each data packet previously required a separate encrypted ACK datagram.
   Negotiated path-local ACK batches preserve up to 16 individual IDs and send
   timestamps; partial batches flush on the 2 ms tick. Old clients/relays keep
   ordinary ACKs. Both mixed-version directions passed real TCP/hash checks.

## Measurements

| Configuration | Download | Upload | Scope |
| --- | ---: | ---: | --- |
| Original engine | 29.14 Mbps | — | Both endpoints sharing the single Linux CPU; virtual 400 Mbps links, 10 ms RTT |
| Replay-ring change alone | 120.47 Mbps | — | Same isolated fixture; SHA-256 matched |
| Original app/relay | 41.55 Mbps | 43.38–46.97 Mbps | Real Mac, both adapters, private relay TCP |
| Replay-ring change alone | 51.26 Mbps | 75.66–112.77 Mbps | Real Mac, both adapters, private relay TCP |
| Replay-ring change, Ethernet alone | 139.70 Mbps | 70.77 Mbps | Real Mac, private relay TCP |
| Ring + buffer/reordering changes | 100.92 Mbps | 78.60–130.35 Mbps | Real Mac, both adapters; all hashes verified |
| Plus capacity-controller changes | 154.55 Mbps | 44.01–102.09 Mbps | Real Mac, both adapters; all hashes verified |
| Plus ACK batching | 184.01 Mbps | — | Isolated Linux fixture, both endpoints sharing one CPU; 650/650 ICMP replies |
| Final ACK-batching Mac build, one stream | 201.16 Mbps | 77.05–151.23 Mbps | Both adapters; all download/upload hashes verified |
| Final ACK-batching Mac build, four parallel streams | 256.91 Mbps | 162.20 Mbps | Aggregate bytes / total wall time, including startup; private relay, not Speedtest |
| Direct SSH, VERZ disconnected | ~237 Mbps | ~251 Mbps | 128 MiB to/from the same relay; includes authentication and SSH overhead |

These individual runs show improvement but do not establish repeatable
no-regression performance or the user's 300 Mbps target. Upload remains below
the direct baseline. The final parallel run downloaded 4 × 124,519,424 bytes in
15.51 seconds and uploaded 4 × 16,777,216 bytes in 3.31 seconds. Compare like
with like: the earlier single-stream figures are not parallel-run baselines.
Shared-bottleneck scheduling and the full acceptance matrix remain open.
No capacity is inferred by adding Wi-Fi and Ethernet measurements when they
share the same internet service.

The final relay socket reported zero kernel receive-buffer drops, and ACK
batching was confirmed negotiated. The session still accumulated 6,702
scheduler queue drops during the parallel-load tests, so queue/congestion
handling remains a performance investigation item rather than a solved claim.

The final isolated link-cut run retained one TCP connection with a matching
SHA-256 and 650/650 ICMP replies. Its maximum reply gap was 100.572 ms, so this
is **not** a passed strict 100 ms gap gate. No physical Mac unplug timing gate
is claimed. An intermediate buffer-only fixture had 646/650 replies; later
controller/ACK-batching fixture runs had 650/650. Do not hide this variability.

## Reproduce

Run the signed Xcode app and connect, then:

```sh
bash Engine/scripts/check-mac-throughput.sh
```

This downloads an unpaced ~124 MB generated test payload and performs three
16 MiB uploads of zeros. Both directions verify SHA-256. It preserves private
test artifacts in a new temporary directory and changes no adapter selection.
The old `/stream` endpoint remains deliberately rate-limited by default and
must not be used as a maximum-throughput benchmark.

The four-stream download used `curl --parallel --parallel-immediate
--parallel-max 4` against `/bulk` four times, writing to `/dev/null`, timed with
`/usr/bin/time -p`. The four-stream upload ran four concurrent copies of the
same 16 MiB upload operation, waiting for all to succeed. Those parallel runs
checked successful HTTP transfers; the sequential script separately verifies
download/upload hashes.

For isolated Linux comparisons, the existing continuity script accepts
VERZ_TEST_BOND_BIN / VERZ_TEST_CLIENT_BIN / VERZ_TEST_HTTP_BIN, VERZ_TEST_RATE,
VERZ_TEST_DELAY_LOW / VERZ_TEST_DELAY_HIGH, VERZ_TEST_STREAM_DELAY_MS and
VERZ_TEST_STREAM_REPEATS. Shaping remains confined to disposable namespaces.
CPU-only replay measurements use `cargo run --release --bin verz-replay-bench`.

The supplied Speedtest URL is blocked by the browser tool's site policy. No
automated Speedtest run was performed and none of these numbers is labeled as
a Speedtest result. Physical 100 ms unplug recovery is also not established.
