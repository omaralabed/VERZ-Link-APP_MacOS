# VERZ Link V3 hybrid architecture

This document records the user-approved redesign. It is an implementation map,
not a claim that every stage is complete.

## Product modes

### Direct Smart

The Mac is the data plane. It sends each supported outbound connection directly
to its destination through one selected physical adapter. No payload is relayed,
encapsulated, or encrypted by VERZ. Application protocols such as HTTPS retain
their normal end-to-end encryption.

The local scheduler owns fast decisions: path health, RTT, metered status,
connection assignment, exclusion, and recovery. In Automatic Hybrid, a remote
brain sends advisory weights over an authenticated Noise/ChaCha20-Poly1305
channel, but it never receives the user's payload, destination, or browsing
data. The normal Direct Smart interface does not expose or require a relay.

Version 0.5.0 implements this for proxy-aware IPv4 TCP using a loopback SOCKS5
engine. Connections are balanced as whole flows, never striped packet by packet.
This preserves TCP ordering and avoids tunnel encryption/encapsulation overhead.

### Secure Continuity

The existing authenticated Noise/ChaCha20-Poly1305 multipath relay remains for
traffic requiring privacy, a stable public IP, or one-session continuity across
uplink address changes. This mode intentionally pays relay distance, encryption,
encapsulation, and relay-capacity costs.

### Automatic Hybrid

Version 0.5.0 runs Direct Smart and a warm Secure Continuity tunnel together.
Proxy-aware TCP is sent direct by default. Explicit domain-suffix rules use the
encrypted relay, and a flow falls back to it if every direct connection attempt
fails. A secure rule never downgrades to direct. Non-proxy-aware IPv4 traffic
currently follows the warm system tunnel; transparent per-flow classification
for that traffic and UDP/QUIC remains the Network Extension stage.

Both relay subflows remain authenticated and warm. Dropping an uplink does not
replace the tunnel session, private IP, or public relay identity. Direct TCP
flows retain the physical limit described below and therefore cannot be given
the same session-migration guarantee.

## Control and trust boundaries

- Payload data stays local/direct in Direct Smart.
- The implemented brain/control service exchanges only authenticated policy,
  path names, RTT/health/metered state, failure counts, and path weights over
  Noise NNpsk0 with X25519 and ChaCha20-Poly1305.
- The Mac validates advisory policy and makes immediate local decisions when a
  path changes; internet reachability never waits for the control service.
- The control service is optional for direct connectivity. Its outage cannot be
  allowed to stop an already valid direct policy.
- No component decrypts HTTPS/TLS application payloads.

## Physical limits kept explicit

- Two adapters behind one router usually share the same WAN bottleneck. They do
  not create 600 Mbps internet capacity when the router or ISP link is 300 Mbps.
- Multiple independent destinations or connections can be distributed. One
  ordinary TCP connection cannot use two public source IPs without cooperation
  from the destination or an aggregation relay.
- Changing the source IP of an established TCP session breaks that session.
  Stable single-session failover belongs to Secure Continuity.
- Transparent system-wide UDP/QUIC and non-proxy-aware traffic require the
  Apple Network Extension entitlement and a production packet-tunnel/app-proxy
integration. The current SOCKS milestone does not claim that coverage.

## Adaptive controller milestone (0.5.0)

See [ADAPTIVE_BRAIN.md](ADAPTIVE_BRAIN.md). The former global 75 ms cutoff
has become traffic-specific. A stateful Rust controller learns directional
goodput from live byte counters, retains exploration, and supplies expiring
advice. The Mac retains authoritative health/cost/security checks and a local
controller. Known real-time ports and Continuity preference use the warm relay
from connection establishment. Unknown TLS traffic still needs explicit rules.
This is online statistical adaptation, not a pretrained AI model or a claim of
automatic application recognition, universal bonding, or zero interruption.

## Next acceptance gates

1. Verify app-managed SOCKS setup and exact restoration on the development Mac.
2. Measure matched-server browser throughput with one and multiple adapters.
3. Verify whole-flow distribution, directional learning and traffic-specific
   latency preferences with controlled links.
4. Verify physical unplug/replug without app or macOS networking freezes.
5. Expand classification beyond explicit suffixes using local, privacy-safe
   connection requirements and measured continuity risk.
6. Obtain Apple Network Extension capability for transparent UDP/QUIC coverage.
7. Repeat physical failover and throughput matrices on independent WANs.
8. Repeat on a clean second Mac, then complete Developer ID signing/notarization.
