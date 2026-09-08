# Throughput investigation — September 8, 2026

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
