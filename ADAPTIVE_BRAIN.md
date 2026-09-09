# Adaptive brain — 0.5.0

The server is an advisory controller. It is not in the payload path for direct
flows, and the Mac never waits for it to detect or react to a path failure.
Secure Continuity payloads still traverse the encrypted relay; a brain-only
control connection cannot preserve an ordinary TCP session across public IPs.

## What learns

Each authenticated client has a separate, in-memory controller. It receives
adapter identifiers, cumulative socket byte counts, sample time, RTT, jitter,
reachability-probe failure ratio, active-flow count, health and metered state.
It receives no hostnames, source addresses, application payloads or TLS keys.

The controller measures upload and download goodput independently and maintains
an observed-rate envelope with 30-second exponential decay. This is a lower
bound observed under the current workload, not a capacity measurement. It uses
bounded square-root weights and a neutral prior for unmeasured paths to avoid
starving a new/quiet link. Changing an adapter's address resets its evidence.
State is not persisted across control sessions. This is an online statistical
controller, not a neural model, LLM, cross-user training system, or novelty claim.

The Mac counts successful socket reads/writes during a transfer, including
partial/reset transfers. It assigns new connections by active-flow count divided
by the appropriate weight. Idle paths get exploration opportunities. Direction
is initially unknown; a bounded, Mac-only destination cache learns upload or
download dominance after 64 KiB, updating roughly once per MiB for later flows.
HTTPS destinations can change behavior, so this is a heuristic, not application
identification. Existing direct connections are never moved between ISPs.

## Traffic handling

| Traffic | Placement and protection |
| --- | --- |
| Downloads | Directional observed-rate weights for new direct TCP flows; high RTT alone does not exclude a usable ISP. |
| Uploads | Independent upload weights; not assumed symmetric with download capacity. |
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
  An old v1 brain cannot restore its blanket latency cutoff in a v2 client.
- Probes do not overlap per adapter. Destination-specific connect failures no
  longer mark the whole ISP offline or contaminate uplink RTT.
- Hybrid's helper recovers a missing secondary scoped default from that
  adapter's DHCP router, not the other ISP's same-numbered gateway. Added
  routes are session-owned and removed on disconnect. Static configurations
  without an existing route or DHCP router still need a usable gateway.
- Probe failures are **not packet-loss measurements**. The relay separately
  observes packet acknowledgements and repair. Direct TCP loss estimation is
  not implemented.
- No artificial bulk probe traffic is generated to claim unused capacity.
- A single direct TCP flow cannot combine different public IPs. Aggregate
  gains require parallel flows and independent bottlenecks. HTTP/2 or QUIC may
  keep a workload on one connection despite many browser requests.
- These mechanisms do not establish interruption-free voice/video, 600 Mbps,
  improved single-flow speed, or a physical failover gap below 100 ms.

## Verification

Rust tests cover separate upload/download strengths, capacity changes, adapter
identity changes, legacy protocol defaults, 256-adapter frame bounds, failed
paths, active-flow reservations, expired advice, live byte metering and TCP
half-close. Scheduler tests cover priority order, video non-duplication,
congestion-window headroom and advice expiry without reviving failed paths.
Encrypted round-trip and wrong-key rejection tests are retained.

Run the existing Rust, Swift and isolated Linux checks listed in README.
Real two-ISP throughput and sustained voice/video under physical unplug need
separate acceptance measurements; unit tests are not performance results.
