# Adaptive brain — 0.6.1

The server is an advisory controller. It is not in the payload path for direct
flows, and the Mac never waits for it to detect or react to a path failure.
Secure Continuity payloads still traverse the encrypted relay; a brain-only
control connection cannot preserve an ordinary TCP session across public IPs.

Customer-facing builds do not need to explain or expose the brain, relay
endpoint, packet scheduler, private tunnel addressing, or path-decision
telemetry. Those details belong in protected VERZ engineering diagnostics.
Automatic Hybrid may use the selected ISP public IP for direct flows and the
relay public IP for protected flows, so one public-IP label is not a complete
description of the session. Version 0.6.1 remains a development build, still
exposes development-oriented details, and does not measure a trustworthy relay
active/idle state; see
[Product identity and disclosure](ARCHITECTURE_V3.md#product-identity-and-disclosure).

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
hold. The initial unknown bulk primary follows the lowest measured end-to-end
request delay; adapter order is only the tie-break when no path has been
measured. Handshake RTT is not treated as evidence of bandwidth or of delay:
the probe times a real HTTP request/response on 1.1.1.1:80, because a
TCP-splitting middlebox (satellite/cellular accelerator) completes handshakes
locally in a few milliseconds while the actual path carries hundreds. Paths are
retained as connect fallbacks, and the only usable path is never blackholed by
this policy.
Existing direct connections are never moved between ISPs. A limited trial can
still become a long upload: its eventual direction and size are unknowable.
A path carrying far more end-to-end delay than the best path (beyond a 50 ms
dead zone) receives new flows only in proportion to a delay penalty, and is
trialled only once the primary carries eight or more concurrent busy flows.

## Champion–Challenger allocation (0.6.1)

The controller now learns separate download and upload champions. An unproven
path is a Challenger and receives weight 1 against the Champion's weight 64.
It must deliver at least 64 KiB in three measurement intervals before it can
become Champion or earn an allocation proportional to its observed directional
delivery rate. One short burst cannot promote a path.
The Champion changes only when another learned path exceeds it by 15%, avoiding
rapid oscillation between similar paths. Download evidence can prove a path;
it no longer requires application upload acknowledgements.

The Mac classifies the current aggregate workload once per second as download
dominant, upload dominant, or balanced for telemetry only. New unknown flows
use the balanced Champion and two-way weights: a machine-wide shape is not
evidence about an unrelated new connection, and applying it changed every
second. Directional weights remain in the protocol for a future per-flow
signal. Existing TCP connections stay pinned. Realtime traffic
continues to use latency, jitter, reachability, and the 75 ms policy instead of
bulk capacity ranking.

The controller retains a decaying recent delivered-rate envelope for the
Champion. When two or more paths are actively delivering but their aggregate
rate falls below 95% of that envelope, new flows contract to weight 64 for the
Champion and weight 1 for Challengers in that direction. This is a safety
response, not proof of unused capacity or a guarantee that an already-running
transfer can be repaired. The floor becomes meaningful only after the current
session has collected representative load; learning is not yet persisted
across app restarts or network changes.

The v0.6.1 engineering telemetry reports the current traffic shape, directional
Champions, and guard state. These fields are for VERZ testing and must not be
shown in the production customer interface.

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

### Connection startup

Hybrid prepares interface-scoped physical and tunnel routes before changing
global internet routing. It verifies the encrypted peer with a bounded ICMP
check and a real SOCKS DNS/TCP handshake to example.com:443, then publishes the
prepared proxy and captures non-proxy traffic. Failure before activation
restores only session-owned preparation. A site blocking this readiness target
can prevent activation; the check transfers no application payload.

Hybrid preserves the Mac's DNS configuration instead of replacing it at Connect.
This is not a promise that Hybrid DNS uses the relay: a local ISP/router resolver
can remain local. Secure Continuity still installs and restores relay DNS.
Hybrid relay TCP sockets explicitly bind to the assigned utun and tunnel source
address, so protected flows cannot fall through to the old physical default
while routes are being prepared or removed.

New direct TCP handshakes first try the controller-selected adapter. Multiple
resolved addresses may race on that same adapter, but a later unproven adapter
cannot steal the connection merely by completing its handshake sooner. Remaining
adapters open only after the selected adapter fails its bounded attempt, sized
at three times its smoothed handshake time plus 100 ms and clamped to
300–1200 ms (1.2 s until the first probe); they share a three-second direct
fallback budget. Optional relay
fallback has a separate two-second budget. DNS has a two-second application
deadline; an underlying OS resolver worker may finish later.
This bounds connection establishment, not retransmission on an existing session.
Existing TCP sessions are not deliberately reset or migrated. A controlled
pre-update test already preserved one IPv4 HTTPS connection across Connect;
that does not establish that all browsers/protocols tolerate proxy/route changes.

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
  The client requires `champion-challenger-v7` advice and falls back to its
  local v6 controller with older brains; cloud advice carrying no delivery
  evidence is also ignored in favour of the local delay-based cold start. Its
  compact report accepts legacy field names on the server; older clients reject
  the newer strategy and use their own controller until upgraded. Learned
  envelopes decay over 30 s while a path carries traffic and over 10 minutes
  while idle, so a pause does not hand the champion to whichever path moved
  bytes last.
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

### v0.5.2 handover verification — September 9, 2026

- Mac: 69 engine-library tests, 6 relay-runtime tests, 6 helper tests, and
  9 Swift tests passed. Engine all-target and helper Clippy checks passed.
- Debug Xcode and development-signed universal Release builds passed;
  deep/strict codesign verification passed. No server update was required.
- Two live Connect tests using `scripts/check-mac-handover.swift` completed
  280 one-byte HTTPS requests with zero failures. Both persistent-session and
  fresh-session lanes automatically changed from unproxied to proxy connections
  in URLSession metrics, without manual page refresh. The first test's slowest
  persistent/fresh requests were 0.183/1.688 seconds; the second's were
  0.106/0.228 seconds. This is a functional handover test, not a speed benchmark.
- Preparation and readiness took 95 ms and 113 ms in Activity. The second run
  temporarily protected example.com (the readiness destination), verifying an
  explicitly tunnel-bound TCP connection before global capture. A safety check
  confirmed preparation had not captured the global internet route.
- A temporary api.ipify.org rule returned the relay's public IP through SOCKS;
  removing that rule returned the ISP's public IP again. Test rules were restored
  to their original empty value. DNS preferences stayed unchanged on both
  adapters; disconnect restored the original default route and disabled SOCKS.

The reported 15-second browser freeze was not reproduced in these controlled
tests. Re-test the user's already-open page during Connect; HTTP/2, QUIC, long
uploads and application-specific proxy handling remain separate acceptance cases.
