# Old app: complete-datagram UDP port, build 22

## Scope and evidence

Source reference: MacOS-2 Git commit `654232ae7d379ee0e76df071721fa49132eaaa87`.
The reference checkout was read only. Nothing in MacOS-2 was edited.

Build 21 still froze in the user's physical cable tests. Its sender-only port
retained TUN fragments and the old shared path lifecycle. It was not an
end-to-end reproduction of the reference UDP capture method.

Build 22 adds `UdpProxy` and `UdpEngine` to the old Xcode project:

- `NEAppProxyUDPFlow` reads/writes complete application datagrams, before TUN
  fragmentation. The provider does not capture TCP.
- The reference engine, sender, packet identity, independent source-address /
  interface-bound sockets, and per-path heartbeat are retained. Removing one
  adapter changes only that adapter's socket; it does not recreate the engine.
- Smart and Continuity send immediate copies over all healthy UDP paths.
  Performance uses the reference scheduler; Data Saver disables upload copies.
  Downlink replication remains the reference gateway's behavior in all modes.
- Gateway egress stays one connected UDP socket per session/flow/destination.
  Upload uses the reference bounded reassembly/repair. Mac downlink delivers
  the first valid copy immediately, with duplicate suppression, not ordering.
- A new Noise NNpsk0 encrypted carrier wraps the reference authenticated packets.
  Public packets are `VZU1`, never plaintext `BDLK`. The raw reference gateway
  is reachable only through loopback sockets inside the gateway process.
- The existing TCP engine source was not changed in this implementation.
  The existing `verz-bond.service` on UDP 443 does not need replacement/restart.

## Integration

Secure Continuity and Automatic Hybrid start the UDP provider first and wait
for an authenticated WAN before starting the existing engine. Direct Smart is
unchanged. Failure to start the new provider fails the connection explicitly.
Disconnect also stops the provider. Selected interfaces and policy propagate
to both components. Independent UDP per-interface carrier counters are shown
separately and explicitly include copies; application totals deduplicate them
in Secure mode. Hybrid totals retain their existing physical-interface basis.

The new system extension requires the verified paid Omar Alabed team
`H7728UD4B3`. Main app: `com.omaralabed.verzlink.classic`; extension:
`com.omaralabed.verzlink.classic.udp`. A distinct signed helper service
`com.omaralabed.verzlink.classic.session-service` avoids the old registered
helper's personal-team signing requirement. Selected old preferences migrate
once; the existing protected enrollment file remains at its original path.
App name stays VERZ Link. No MacOS-2 identity is reused or uninstalled.

This is an Apple Development signed test build, not notarized distribution.
macOS extension/background-helper approval must be granted by the user.

## Deployment plan

New service: `verz-udp-gateway.service`, UDP 4443, on `69.164.213.57` only.
Credential loaded by systemd from existing `/etc/verz-link-lab/secret`, not
included in the source archive. The new process runs as a dynamic non-root
user with no capabilities. No routing/NAT/TUN privileges are needed.

Staged source: `/opt/verz-link-lab/udp-proxy.i68clT`.
Signed build: `/tmp/verz-udp-release.GXPI5u/Build/Build/Products/Release/VERZ Link.app`.
Installation/deployment acceptance is recorded below only after verification.

## Tests performed before installation

- Ten isolated Rust tests pass: authenticated UDP, wrong-key denial, replay /
  tamper denial, packet limits, stable egress, mode changes, actual local
  socket removal/recreation, reference upload reassembly, and silent path cuts.
- 1,200 complete 1,332-byte datagrams survived simulated bidirectional WAN
  cuts and return, with identical payloads and stable egress source socket.
- Native local FFmpeg/SRT: encrypted 6 Mbps H.264 stream, 120 ms SRT latency,
  70 decoded frames at 10 fps; both WANs separately cut and restored. Final
  rerun maximum inter-frame gap: 107 ms. Initial test failure was an invalid
  MPEG-2 CBR encoder setup (`stuffing too large`), fixed in the test generator.
- Warnings-denied Rust Clippy passes. Ten existing Swift tests pass.
- Universal arm64/x86_64 Release Xcode build and deep/strict signature checks pass.

These do not simulate USB driver events, macOS route changes, or prove that
the physical five-second freeze has disappeared. Physical acceptance is pending.

## Boundaries

- IPv4 public-destination UDP, payloads up to 16,384 bytes; private/local,
  multicast and gateway-address traffic is excluded. No new IPv6 claim.
- Typical 1,332-byte SRT UDP payload plus carrier/IP headers fits 1,500-byte
  MTU. Larger application datagrams may still cause outer IP fragmentation.
- 256 live proxy flows per Mac; 65,535 non-reused flow IDs per connection.
  Gateway limits are global 256 egress flows/streams, 128 encrypted sessions,
  16 paths per session; these are guards, not tested customer-capacity claims.
- Replication consumes bandwidth on every participating WAN. This change is
  not a bandwidth fairness controller or a promise of additive throughput.
- Existing UDP sockets created before proxy activation may need reopening.
  A gateway restart / loss of all paths is not the same as one-WAN failover;
  automatic recovery of lost encrypted gateway sessions is not established.
- The first-copy path is bounded, not a universal zero-loss or zero-pause guarantee.

## Rollback

Disconnect the new app, stop/disable only the new UDP service, and restore the
saved build-21 app. Leave `verz-bond.service` untouched. The new UDP firewall
rule may be removed independently; no old firewall rule needs changing.

## Installation and live verification

Installed build 22 in `/Applications/VERZ Link.app`, verified deep/strict code
signature, and launched its executable. Previous app is both archived and
preserved as `previous-installed.app` under
`/Users/viewvision/Library/Application Support/VERZ Link/udp-proxy-backup.AbMcnZ/`.
The previous helper-registered Xcode Debug app was not overwritten.

Deployed new `verz-udp-gateway.service` on `69.164.213.57`, running PID 14719
at verification. Opened only new UDP port 4443 in UFW. Gateway binary SHA-256:
`d62932249758fabc7bb57300781d07dc13b194cbe97d5a3e1e552759b367e94b`.
Existing `verz-bond.service` still PID 12367, start time 2026-09-11 21:05:26 UTC,
unchanged binary SHA-256
`9aafa60abc75e0c4183bc609c791c015ca15b938d819479da5a25e66c2664155`.

Live encrypted gateway test over Ethernet passed 100 complete 1,332-byte UDP
echoes; server observed one stable egress source socket and 133,200 bytes each
direction with zero rejections/send errors. The temporary echo service exited.
This single-path test is not a failover test.

Live two-path test did **not** pass while the app/helper was off: Ethernet
authenticated, Wi-Fi did not. Read-only route inspection found no scoped
Internet route for `en0`, despite a valid DHCP address/router. The existing
`Helper/src/network.rs::add_uplink` prepares missing scoped routes at app
connection. Verify two authenticated paths after that startup step. Do not
equate two displayed adapters with two working UDP paths.

The new extension/helper approval, connected-app capture (including concurrent
TCP), and physical unplug/replug acceptance are still pending. Do not label
this a verified physical-failover fix yet.

UI automation enumerates the running `com.omaralabed.verzlink.classic` process,
but selecting its bundle ID fails and selecting the installed path resolves
the stale `com.verz.link.mac` identity, even after refreshing registration.
Connect was not clicked and no macOS permission was bypassed. User action is
needed to start Connect/approve the new provider before live capture checks.
The signed install archive is retained at `dist/udp-proxy-build-22/VERZ Link.zip`.

## Build 23: activation rejection correction

macOS rejected build 22 before approval or any gateway connection. At
2026-09-11 19:17:37 local time, `sysextd` reported NetworkExtensionErrorDomain
code 6: `NEMachServiceName` was not prefixed by an entitled App Group. The
extension had no `com.apple.security.application-groups` entry. The statement
that build 22 only needed user approval was incomplete; this was a packaging bug.

Build 23 adds `$(TeamIdentifierPrefix)com.omaralabed.verzlink.classic` to both
app and provider entitlement files, matching the existing Mach service name.
Both signed products resolve the group to
`H7728UD4B3.com.omaralabed.verzlink.classic`. Xcode build and deep/strict code
signature checks pass. `scripts/verify-udp-signing.swift` rejects build 22 and
passes build 23. The source-mapping check runs in the Xcode native build
phase; the final signed-product check runs before the packaging script archives.

Installed build 23 at `/Applications/VERZ Link.app`; build 22 preserved under
`/Users/viewvision/Library/Application Support/VERZ Link/signing23-backup.PqpSoz/`.
Archive: `dist/udp-proxy-build-23/VERZ Link.zip`.
No engine or gateway changes in this correction. macOS activation and live
connection still require a new Connect attempt; physical failover remains unverified.

## Build 24: invalid capture rules and confirmed startup

Build 23 was approved (`activated enabled`), but at 2026-09-11 19:22:40–41
local time macOS rejected its network settings: "Either a non-wildcard port
or a non-wildcard address must be specified." The included 0.0.0.0/0 rule
and excluded 0.0.0.0/8 rule both used port 0. This was an app/provider bug,
not a gateway rejection or a missing approval.

`UDPCaptureRules.swift` now constructs outbound, UDP-only rules using nine
nonzero CIDRs covering 1.0.0.0 through 223.255.255.255. Existing private,
link-local, loopback and gateway exclusions remain. 0/8 and 224/3 are not
included; TCP and IPv6 scope are unchanged. Both Xcode targets and Swift
regression tests compile the same rule builder. Startup failures retrieve
the actual `NEVPNConnection` disconnect error instead of always suggesting
approval/connectivity. No Rust engine or gateway was changed in this build.

Verification:

- `swift test -q`: 13 tests passed, including actual NENetworkRule attributes,
  contiguous CIDR coverage, and private-network exclusions.
- Universal Release Xcode build passed; deep/strict signatures and App Group
  verification passed for the installed build.
- Installed `/Applications/VERZ Link.app` build 24; archived at
  `dist/udp-proxy-build-24/VERZ Link.zip`. Build 23 is preserved under
  `/Users/viewvision/Library/Application Support/VERZ Link/rules24-backup.GzjTvH/`.
- macOS reports the build-24 extension activated/enabled. It connected at
  19:31:27 local and remained connected in the subsequent live checks.
- Connected-app TCP HTTPS returned HTTP 200; a UDP DNS query to 1.1.1.1
  returned valid answers. Scoped gateway routes exist for both en0 and en7.
- At 23:33:57 UTC, the new gateway reported one encrypted session, cumulative
  97,520,255 upload bytes / 97,901,268 download bytes, zero rejections and
  zero send errors. Counters increased throughout the checks. The old TCP
  gateway remained active with unchanged PID 12367.

The app-control inventory briefly launched the saved backup instead of the
installed build. That backup process was stopped and its Launch Services
registration removed; the backup files remain recoverable. UI selection of
the installed app stayed unreliable, so connection confirmation above comes
from the actual provider/system logs, server counters, and network requests,
not an assertion that an automated UI click succeeded.

This fixes and verifies startup. Physical unplug/replug and uninterrupted SRT
playback are a separate acceptance test and are **not** proven by these checks.

## Build 25: isolate interface discovery from UDP forwarding

After build 24, the user reported successful operation with a remaining roughly
0.5-second playback freeze only when Ethernet was plugged back in. Inspection
found `SCNetworkInterfaceCopyAll` and `getifaddrs` running synchronously on the
same serial queue as the 5 ms packet pump. That is a concrete head-of-line
blocking risk during OS network reconfiguration, but the old build had no
timing instrumentation proving this caused the reported half-second freeze.

`UDPInterfaceScanner` moves OS discovery to a separate serial queue and returns
snapshots to the packet owner. Concurrent scan requests are coalesced, failed
queries do not remove every WAN, and cancelled-generation results cannot apply
to a restarted engine. Filtering of disabled adapters and all Rust engine access
remain on the original packet queue. Rust session/socket/reassembly/scheduler
logic is unchanged; adding Ethernet still preserves an unchanged Wi-Fi socket.
No arbitrary failback delay was added.

The provider reports `pump_max_gap_ms`, `inventory_max_ms`, and
`adapter_apply_max_ms` in its status message and logs any corresponding event
above 100 ms. These measurements distinguish a packet-queue stall from a slow
background scan or socket update during subsequent physical testing.

16 Swift tests passed, including deliberately blocked discovery while packet
owner work continues, hot-plug burst coalescing, cancelled-result suppression,
and failed-snapshot handling. The universal Release build, strict/deep signing,
and signed App Group/team checks passed. Installed build 25 in
`/Applications/VERZ Link.app`; archive `dist/udp-proxy-build-25/VERZ Link.zip`.
Build 24 remains recoverable in
`/Users/viewvision/Library/Application Support/VERZ Link/rejoin25-backup.mQvPGu/`.
The app reopened after installation; activation of the updated provider requires
Connect. Physical replug playback validation remains outstanding. Do not claim
the half-second freeze is fixed based only on these tests.

Separate live finding, not changed in build 25: at 23:39:42–57 UTC the UDP
gateway reported 256 flow entries and increasing inner `udp.rejected` counters
(1126 to 1132), with zero outer authentication rejections. Gateway code caps
egress/ordered-stream tables at 256 and retains idle entries for 600 seconds.
Short-lived DNS flows can exhaust those tables. This needs its own tested
flow-lifecycle correction; it is not established as the cause of the SRT replug
freeze. The cloud services and TCP engine were deliberately left unchanged.

### Build 25 acceptance update

The user subsequently reported **"yes fixed"** for the remaining LAN-replug
freeze. This is a user-observed physical replug acceptance result, not a
guarantee for every network or protocol. macOS confirms build 25 activated and
enabled. Connected-app TCP HTTPS returned HTTP 200 and UDP DNS returned valid
answers. Gateway payload counters increased at 23:51:02–17 UTC, with one
encrypted session and no increase in rejection/send-error counters during that
window. The separate flow-capacity limitation above remains unresolved.
No additional app or gateway changes followed the successful user test.

## Gateway UDP flow lifecycle update (2026-09-11)

Deployed only `verz-udp-gateway.service` on `69.164.213.57:4443` at
2026-09-12 00:20:22 UTC (20:20:22 EDT). Installed Mac app **build 25 is
unchanged**, including the user-accepted physical replug fix. The existing
TCP service `verz-bond.service` retained PID 12367, its original start time,
and its executable checksum throughout this deployment.

### Changes and limits

- Gateway-wide egress and ordered-stream guards increased from 256 to 1,024
  each. These are flow/state limits, **not a claim of 1,024 customers**. The
  existing Mac engine's 256-flow guard and gateway session limits are unchanged.
- Valid standard DNS requests track pending transaction IDs. Reclaim their
  egress socket after all tracked replies arrive and two seconds elapse idle;
  unanswered DNS uses a 30-second idle timeout. Further traffic refreshes the
  timer. Malformed/nonstandard requests fall back to general UDP handling.
- General UDP retains a five-minute idle timeout. Active traffic in either
  direction preserves its socket and associated reorder state. Active streams
  are never evicted to admit a new flow; a genuinely full table rejects admission.
- DNS bypasses ordered-stream allocation but retains bounded duplicate
  suppression. Other UDP forwarding and recovery behavior is unchanged.
- Reorder/copy payload storage now has a gateway-wide 32 MiB guard, in addition
  to existing per-stream bounds. This is a memory guard, not bandwidth control.
- Poll only readable/error-ready egress sockets; perform idle cleanup every
  250 ms and before capacity rejection. No socket recycling on WAN changes.
- Status logs expose flow expiration, DNS expiration, capacity/memory rejection,
  peak flows, current stream count and buffered-byte limits.

The conservative general UDP lifetime and special DNS lifetime are informed by
[RFC 4787 section 4.3](https://www.rfc-editor.org/rfc/rfc4787.html#section-4.3).
This application-aware proxy change is not a claim of complete NAT conformance.

### Verification

- macOS and Linux release library suites: 17 passed, two opt-in integrations
  skipped by default. Clippy with warnings denied passed locally.
- Synthetic lifecycle test completed 5,000 DNS conversations with injected time,
  while actual loopback stream packets retained the same egress socket.
- 1,024 actual loopback egress flows admitted; the next flow rejected while an
  existing stream continued. Downstream-only activity preserved sequencing.
- Global reorder-buffer saturation and session cleanup tested at 32 MiB.
- Initial Linux stress run failed because the SSH shell's descriptor soft limit
  was 1,024. Re-running under the service's existing 8,192 descriptor limit
  passed every test; no service limit change was needed.
- Real local FFmpeg/SRT test: 70 decoded frames, maximum inter-frame gap 106 ms,
  5,622,572 uploaded bytes, with both simulated WAN cuts/restores. This does not
  substitute for physical cable testing or a production throughput benchmark.
- Deployed encrypted echo test: 100 complete 1,332-byte replies through two
  authenticated interface-bound paths, including secondary test-socket removal
  and restoration. The first run during the app-reconnection window timed out
  on reply 27; an unchanged repeat after reconnection passed. Its cause was not
  isolated, so this is not evidence of zero packet loss under all transitions.
  The temporary echo endpoint accepted only this gateway's own source address;
  firewall rules were unchanged and the process had a bounded lifetime.
- Restart invalidated the previous encrypted session as expected. The user
  confirmed Disconnect/Connect. Connected-app HTTPS returned HTTP 200 and all
  12 UDP DNS requests returned answers. At 00:22:02 UTC, 50 DNS mappings had
  been reclaimed, with zero inner capacity, memory or send errors. UDP payload
  counters continued increasing. The outer authentication-rejection count
  stopped increasing after the old session was replaced.

### Deployment and rollback record

New executable SHA-256:
`1112cef6101e533c79bb944cfd5cb2623b835313f3d245db98e4d1ee41f29507`

Previous executable SHA-256:
`d62932249758fabc7bb57300781d07dc13b194cbe97d5a3e1e552759b367e94b`

Source-only deployment package and previous executable/unit are preserved in
`/opt/verz-link-lab/udp-flow-cleanup.VQqSVJ/`. The previous executable is
`verz-udp-gateway.before`; the installed unit was not modified. Rollback requires
atomically restoring that executable to `/opt/verz-link-lab/verz-udp-gateway`
and restarting **only** `verz-udp-gateway.service`, followed by one app reconnect.
Do not restart the TCP service or replace the working Mac app for this rollback.

This resolves the observed stale-DNS accumulation mechanism. Finite capacity,
authentication after server restart, and real-network packet loss remain
explicit limitations; no unlimited scale or universal zero-interruption claim
is made.
