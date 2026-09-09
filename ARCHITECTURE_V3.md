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
connection assignment, exclusion, and recovery. A remote control service may
later send signed advisory policy and learned weights over TLS, but it never
needs the user's payload or a relay IP in the normal interface.

Version 0.3.0 implements this for proxy-aware IPv4 TCP using a loopback SOCKS5
engine. Connections are balanced as whole flows, never striped packet by packet.
This preserves TCP ordering and avoids tunnel encryption/encapsulation overhead.

### Secure Continuity

The existing authenticated Noise/ChaCha20-Poly1305 multipath relay remains for
traffic requiring privacy, a stable public IP, or one-session continuity across
uplink address changes. This mode intentionally pays relay distance, encryption,
encapsulation, and relay-capacity costs.

### Automatic Hybrid

The target mode chooses Direct Smart for ordinary traffic and escalates only
eligible traffic to Secure Continuity when its requirements demand a stable
identity, privacy, or session continuity. Version 0.3.0 exposes this as a preview
and runs the direct data path; selective escalation is not implemented yet.

## Control and trust boundaries

- Payload data stays local/direct in Direct Smart.
- A future brain/control service exchanges only authenticated policy, path
  summaries, capability information, and aggregate measurements over TLS.
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

## Next acceptance gates

1. Verify app-managed SOCKS setup and exact restoration on the development Mac.
2. Measure matched-server browser throughput with one and multiple adapters.
3. Verify whole-flow distribution and 75 ms exclusion with controlled links.
4. Verify physical unplug/replug without app or macOS networking freezes.
5. Build the authenticated advisory control service and signed policy format.
6. Implement selective Direct/Secure classification for Automatic Hybrid.
7. Obtain Apple Network Extension capability for transparent UDP/QUIC coverage.
8. Repeat on a clean second Mac, then complete Developer ID signing/notarization.
