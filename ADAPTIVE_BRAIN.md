# Adaptive brain — 0.5.1

The server is an advisory controller. It is not in the payload path for direct
flows, and the Mac never waits for it to detect or react to a path failure.
Secure Continuity payloads still traverse the encrypted relay; a brain-only
control connection cannot preserve an ordinary TCP session across public IPs.

## What learns

Each authenticated client has a separate, in-memory controller. It receives
adapter identifiers, TCP-acknowledged upload bytes, received bytes, send backlog,
retransmitted bytes, busy-flow count, congestion hold state, sample time, probe
RTT/jitter, reachability-probe failure ratio, health and metered state.
It receives no hostnames, source addresses, application payloads or TLS keys.

The controller measures upload and download goodput independently and maintains
an observed-rate envelope with 30-second exponential decay. This is a lower
bound observed under the current workload, not a capacity measurement. It uses
bounded proportional weights. Unknown/mixed-use connections use the smaller
of the two directional weights, not their average. Changing an adapter's
address resets its evidence.
State is not persisted across control sessions. This is an online statistical
controller, not a neural model, LLM, cross-user training system, or novelty claim.

The Mac samples each live direct TCP socket at most four times per second,
including while it is stalled. On macOS, acknowledged payload is a lower bound
derived from successful writes minus the send-buffer bytes (which include
in-flight data); closed/reset sockets cannot turn discarded buffers into ACKs.
Linux uses TCP_INFO's acknowledged-byte counter. A failed/unsupported sample is
not zero latency or proof of successful delivery. Early closure can undercount.
The native macOS layout follows the SDK header, including its single TFO
bitfield word; the libc 0.2.189 layout has incorrect offsets for later counters.
See [Apple's TCP structure](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/netinet/tcp.h).

There is **no destination-direction cache**. A new HTTPS connection may upload,
download, or switch directions on the same socket. The scheduler uses projected
busy work `(busy + connecting + 1) / conservative weight`; keep-alives idle for
one second without backlog no longer count as work. This is an admission
heuristic, not measured unused capacity or TLS/application identification.

An upload with at least 64 KiB written and 16 KiB still outstanding puts new
bulk placement on hold if its own RTT rises 50 ms above its observed baseline,
ACK progress stalls for 500 ms, or an interval has at least 4 KiB retransmitted
and a retransmission/delivery ratio of at least 5%. Retransmission bytes are
not a packet-loss percentage; remote receiver backpressure can also trigger
the conservative hold. Local holds override positive remote advice.

The hold lasts three seconds after the last bad sample. Unknown/recovering
secondary paths receive at most one new trial every five seconds while the
preferred path is busy, and no new trial while that path has busy work.
Recovery requires 64 KiB of subsequent acknowledged data and expiration of the
hold. The initial unknown primary is the lowest measured probe-RTT path, with
a stable name tie-break when RTT is unavailable. Paths are retained as connect
fallbacks, and the only usable path is never blackholed by this policy.
Existing direct connections are never moved between ISPs. A limited trial can
still become a long upload: its eventual direction and size are unknowable.

## Traffic handling

| Traffic | Placement and protection |
| --- | --- |
| Downloads | New unknown TCP flows use conservative two-way weights; this may trade some download aggregation for avoiding weak-upload placement. |
| Uploads | TCP delivery, backlog and congestion guide new connections; download performance cannot stand in for upload capability. |
| Voice/control | Small packets, ICMP and EF-marked packets have priority in the secure scheduler; existing selective duplication/repair remains. |
| Live video | Explicit video DSCP and recognizable RTMP/RTSP TCP ports have a separate priority queue; large video packets are not duplicated wholesale. |

Hybrid sends recognizable RTSP/RTMP/SIP/TURN TCP ports (554, 1935, 5060/5061,
3478/5349) and protected-domain rules to the warm relay from the start.
Continuity preference relays all new proxy-aware TCP flows. Unknown traffic on
443 is not guessed to be voice/video. Add relevant domains before starting a
call or stream, or use Secure Continuity. Non-proxy-aware IPv4, including UDP,
continues through the Hybrid system tunnel; transparent selective direct UDP
is not implemented. Direct Smart alone covers proxy-aware IPv4 TCP, not all apps.

The secure scheduler reserves bounded congestion-window headroom for urgent
packets, and keeps all responsive paths available for bulk. The 75/65 ms
threshold/hysteresis applies to latency-sensitive placement only. Relay-local
RTT, acknowledged capacity, pacing and repair remain authoritative in both
directions. Fresh brain real-time weights provide a bounded bias to the Mac's
secure outbound scheduler; relay outbound scheduling stays local to the relay.
An added-delay controller stops window growth above 10 ms of queue delay and
reduces the window at most once per RTT toward baseline + 5 ms; it does not
label a high geographic baseline as loss. This helps avoid the queue buildup
seen when the initial all-path bulk change was tested without delay control.
The remote brain currently learns direct-flow byte rates, not combined relay
capacity. Highly unequal relay path delays can still exceed the 80 ms bounded
TCP reorder hold; that throughput acceptance case remains open.

## Safety and limits

- Advice expires after at most five seconds; disconnect clears it immediately.
  The same controller keeps learning locally during a brain outage.
- Local health, Data Saver, security mode and domain rules override advice.
  v0.5.1 requires `delivery-aware-v3` advice and falls back locally with older
  brains. Its compact report accepts legacy field names on the server; older
  clients reject the v3 strategy and use their own controller until upgraded.
- Probes do not overlap per adapter. Destination-specific connect failures no
  longer mark the whole ISP offline or contaminate uplink RTT.
- Hybrid's helper recovers a missing secondary scoped default from that
  adapter's DHCP router, not the other ISP's same-numbered gateway. Added
  routes are session-owned and removed on disconnect. Static configurations
  without an existing route or DHCP router still need a usable gateway.
- Probe failures are **not packet-loss measurements**. Direct sockets now
  expose cumulative retransmitted bytes; the relay separately observes its
  own packet acknowledgements and repair.
- No artificial bulk probe traffic is generated to claim unused capacity.
- A single direct TCP flow cannot combine different public IPs. Aggregate
  gains require parallel flows and independent bottlenecks. HTTP/2 or QUIC may
  keep a workload on one connection despite many browser requests.
- These mechanisms do not establish interruption-free voice/video, 600 Mbps,
  improved single-flow speed, or a physical failover gap below 100 ms.

## Verification

Rust tests cover separate upload/download strengths, capacity changes, adapter
identity changes, legacy protocol defaults, 256-adapter frame bounds, failed
paths, connection reservations, expired advice, live byte metering and TCP
half-close. Native loopback tests check ACK counter bounds, sampling a stalled
send without incoming reads, and backlog/busy cleanup on cancellation. Tests
also cover false capacity from buffered writes, weak upload/strong download,
bounded recovery trials, and local congestion overriding remote weights.
Scheduler tests cover priority order, video non-duplication,
congestion-window headroom and advice expiry without reviving failed paths.
Encrypted round-trip and wrong-key rejection tests are retained.

Run the existing Rust, Swift and isolated Linux checks listed in README.
Real two-ISP throughput and sustained voice/video under physical unplug need
separate acceptance measurements; unit tests are not performance results.

### v0.5.1 verification — September 9, 2026

- Mac: 64 engine-library tests, 6 relay-runtime tests, 3 helper tests, and
  9 Swift tests passed. Engine all-target and helper Clippy checks passed.
- Linux relay host: the same 70 engine/runtime tests passed, including native
  TCP statistics and a deliberately stalled socket; optimized build passed.
- Debug Xcode build and development-signed universal Release build passed;
  codesign verification passed. No production signing/notarization claim.
- Deployed the matching advisory brain with a binary backup, restarting only
  that service. The relay process was not restarted.
- Reopened the Mac app as v0.5.1, reconnected Hybrid with Ethernet and phone
  Wi-Fi enabled, and confirmed live TCP delivery counters on both adapters and
  an authenticated brain connection in Settings.
- Three concurrent 1 MiB synthetic HTTPS uploads through the app's SOCKS
  endpoint each returned HTTP 200 (roughly 0.29–0.37 seconds). These small
  functional checks are **not** a controlled upload-capacity benchmark.

Still pending: a matched-server, repeated Ethernet-only / hotspot-only /
combined throughput comparison. Existing browser connections should be closed
between cases; refreshing a page alone may retain an old TCP connection.
