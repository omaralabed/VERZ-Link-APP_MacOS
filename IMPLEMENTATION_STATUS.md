# VERZ Link macOS implementation status

This is engineering tracking, not a claim that the product is complete.

Source requirements: `VERZ/VERZ_LINK_V2.md`, September 8, 2026, plus the user's
requirements for native Xcode development, Rust networking, one-CPU relay
support, simultaneous Macs, and at most 100 ms failover in supported tests.

The user-approved V3 split supersedes relay-always operation: Direct Smart is
the default local data plane, Secure Continuity preserves the relay tunnel, and
Automatic Hybrid selects between them per supported TCP flow.

## Implemented V3 Direct Smart milestone

- Rust SOCKS5 CONNECT engine binds every outbound IPv4 TCP connection to the
  selected physical adapter; application payloads never cross the VERZ relay.
- No VERZ payload encryption or encapsulation in Direct Smart. HTTPS/TLS and
  other application encryption remain end to end.
- Whole-flow round robin for Smart/Performance, stable lowest-RTT selection for
  Continuity, and unmetered preference for Data Saver.
- Independent one-second path probes. A path at 75 ms RTT or above receives no
  new flows while a healthier sub-75 ms path exists; failed paths keep probing.
- Native app mode selector and mode-specific status/security details. Relay IP
  and key controls are hidden from the normal Direct Smart experience.
- Signed helper enables the loopback proxy only on selected macOS network
  services and records/restores their prior SOCKS settings on disconnect,
  engine failure, app loss, adapter removal, and normal exit.
- Direct traffic counters aggregate selected physical adapters. Direct public
  IP verification explicitly traverses the local flow engine.
- Automatic Hybrid runs the direct engine and a warm Secure Continuity tunnel
  in one Rust process. Explicit domain suffixes use the encrypted relay, all
  other proxy-aware TCP is direct, and failed direct connection attempts fall
  back to the relay without restarting the Hybrid session.
- The authenticated encrypted brain service receives metadata-only path reports
  and returns bounded path weights plus cutoff policy. Loss of the brain channel
  leaves the local safe policy running and reconnects in the background.
- Current Direct Smart coverage is proxy-aware IPv4 TCP. Transparent UDP/QUIC,
  non-proxy-aware applications, and migration of one established session are
  future Network Extension gates; they are not claimed as implemented.

## Implemented baseline

- Native SwiftUI application and shared Xcode scheme, macOS 14+.
- Universal arm64/x86_64 app and Rust executables.
- Authenticated, encrypted IPv4 system tunnel and relay NAT.
- Independent concurrent Mac sessions and unique private IPv4 assignments.
- Credential/profile import and export without bundling credentials.
- Live interface byte counters, actual ICMP/file-transfer diagnostics.
- Automatic discovery of named Wi-Fi/Ethernet interfaces (latest source).

## Implemented multipath changes — acceptance still incomplete

- A single device session spanning independently bound physical uplinks.
- Bidirectional authenticated path probes and health state transitions.
- Bounded queues, cross-path duplicate rejection, acknowledgements and repair.
- Automatic link loss/recovery without removing the device tunnel.
- Traffic-aware scheduling, congestion limits and operating preferences.
- Actual per-path telemetry in the native app, not UI-generated metrics.
- Smart bulk scheduling uses unequal-latency links, with per-TCP-flow bounded reordering.
- 75 ms smoothed RTT exclusion; recovery below 65 ms. Keep the least-latency
  responsive link as a last resort if every link exceeds the cutoff.
- Retained/retried UDP Join after socket backpressure; preserve NAT mapping
  during temporary silence instead of repeatedly discarding the socket.
- Constant-time tagged replay ring replacing per-packet window scans.
- Per-socket UDP burst buffers; no host-wide sysctl changes.
- Bounded 4,096-packet per-flow TCP resequencing with an 80 ms hold limit;
  ACK-only TCP and UDP bypass the hold. Fast-start capacity discovery and
  congestion backoff driven by data repair, not idle heartbeat failure alone.
- Negotiated ACK batching with individual delivery IDs/timestamps preserved;
  older clients and relays retain the original single-ACK behavior.
- Version 0.2.3 reserves bounded delivery capacity before acknowledging new
  data. Reordering now lives in the TUN writer, so released bursts cannot
  overflow a smaller intermediate channel. Backpressure leaves packets
  unacknowledged and eligible for outer repair, without blocking the reactor.
- Separate receive-admission and UDP socket backpressure counters; the existing
  queue_drops counter now describes outbound scheduler admission drops.
- UI control writes and TUN delivery cannot block the failover/UI event loops.
- Connected-only interface list, including carrier present before DHCP completes.
- Signed SMAppService/XPC launcher replacing per-connection AppleScript.
  Caller identity is enforced using Apple's code-signing requirement API.
  Root executes only verified copies in a newly created root-only directory.

## Verified on September 8, 2026

- 46 Rust library tests plus 6 runtime regression tests pass on macOS and
  release Linux; Rust clippy clean on macOS.
- 7 Swift tests pass; universal app and helper signatures verified.
- Controlled isolated Linux test: one 30.97 MB TCP transfer survived two link
  cuts with matching SHA-256; 650/650 ICMP replies, maximum reply gap 46.105 ms.
- Two independently shaped 10 Mbps links at 20/60 ms baseline RTT: one TCP
  transfer measured 8.25 Mbps / 7.83 Mbps individually and 12.11 Mbps combined.
  This is 46.8% above the better single-link test, NOT sum-capacity acceptance.
- Mac en0/en7 protocol check: 524/524 encrypted relay-kernel ICMP replies,
  88 ms maximum reply gap after a software-controlled subflow cut. This check
  does NOT route Mac apps or measure physical WAN/TCP interruption.
- Signed Xcode app registered the managed helper; after the user's one-time
  approval, connection and disconnect/reconnect succeeded without a password
  prompt. Disconnect restored the original en7 route and stopped the session
  engine; reconnect restored the utun route and private TCP endpoint access.
- Two real Mac app TCP transfers, each 30,972,416 bytes, completed with matching
  SHA-256 while Ethernet or Wi-Fi was separately disabled using the app's Use
  control. Both adapters were restored afterward. These rate-limited continuity
  tests are not throughput benchmarks or physical-unplug timing measurements.
- Running app shows only the two connected Wi-Fi/Ethernet interfaces, hiding
  inactive ports. User-selected Use/Metered preferences remain intact.
- Throughput investigation reproduced the user's slowdown: original Mac
  private-relay TCP download 41.55 Mbps, upload 43.38–46.97 Mbps. Controlled
  one-CPU throughput rose from 29.14 to 184.01 Mbps after packet-processing
  changes. These are not Speedtest results; see [performance](PERFORMANCE.md).
- Version 0.2.2 real Mac retest with both adapters: single-stream download
  201.16 Mbps, upload 77.05–151.23 Mbps with matching hashes. Four parallel
  streams measured aggregate 256.91 Mbps down / 162.20 Mbps up. This does not
  establish the user's 300+ Mbps target or eliminate the remaining regression.
- Mixed-version client/relay interoperability preserved TCP/hash integrity in
  both directions. The version 0.2.2 virtual cut test preserved TCP/hash integrity,
  but its 100.572 ms maximum ICMP reply gap does not pass a strict 100 ms gate.
- Version 0.2.3 virtual cut retest: matching TCP SHA-256, 650/650 ICMP replies,
  maximum observed reply gap 73.441 ms. This is one controlled run, not a
  physical Mac unplug or universal 100 ms acceptance claim.
- Deployed 0.2.3 Mac/relay: both-adapter and Ethernet-only private TCP/hash
  checks pass; respective single-stream downloads 202.84 and 231.64 Mbps.
  Uploads range 151.31-168.61 and 170.03-188.06 Mbps. Relay outbound queue
  drops and kernel UDP receive drops remained zero in these intervals;
  receive admission backpressure is tracked separately and preserves retry.
  These runs do not establish 300+ Mbps or repeatable no-regression throughput.
- Version 0.3.0 Direct Smart was verified locally through a real SOCKS5 HTTPS
  request bound to en0. It returned the direct Verizon public IPv4 rather than
  the Linode relay address. Six concurrent HTTPS requests in the signed app
  produced bytes on both en0 and en7. Forced app termination stopped the child
  engine and restored both services to SOCKS disabled with blank endpoints.
  Secure Continuity was then reconnected and verified with the relay public IP.
  Full browser/Ookla, physical unplug, and second-Mac acceptance remain.
- Version 0.4.0 signed-app Hybrid verification used one live session for both
  routes: a configured `api.ipify.org` secure rule exited through the Linode
  (`69.164.213.57`), while an unlisted domain exited directly through Verizon
  (`72.68.150.247`). The app received advancing encrypted-brain advice.
- With Ethernet retained, Wi-Fi was powered off for two seconds and restored
  during 250 ICMP probes through the same warm tunnel session: 250/250 replies,
  zero observed loss, 51.130 ms maximum RTT. This run passes the 100 ms gate for
  that tested event and showed no packet interruption; it is not a universal
  no-interruption claim for every failure mode.

## Known open user issues

- Physical cable unplug/replug and application-goodput regression matrix remain
  unverified; the Wi-Fi software-power failover result above does not replace it.
- User reports 300+ Mbps direct access on the shared-router setup. That target
  and repeatable no-regression throughput are not yet established in the app.
- The user added an Apple Development signing identity and selected Mina Alabed
  (Personal Team) in Xcode; this selection is preserved. This is not Developer
  ID/notarized distribution or a Network Extension. Installation and approval
  on a second Mac remain unverified.

## Additional V2 requirements not complete

- Measured no-regression controller and sum-capacity acceptance gate.
- XOR protection and recovery-budget/capacity validation under impaired links.
- Per-device enrollment, revocation, short-lived key rotation and Hub integration.
- Corporate-VPN underlay coexistence and routing/DNS leak compatibility matrix.
- IPv6 forwarding, release-quality lifecycle, signing/notarization and updates.
- Multiple relay regions, capacity/abuse controls and relay-failure topology.
- 72-hour chaos, security review and the complete V2 acceptance test matrix.

Do not label a baseline connection, a synthetic probe, a predicted timeout, or a
partial feature set as a completed V2 product or a passed 100 ms failover gate.
