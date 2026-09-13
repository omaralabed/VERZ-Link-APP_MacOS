# Secure Continuity repair — development build 0.6.8 (19)

## Deferred media protection (0.6.8, not deployed)

The scheduler previously discarded the opportunity to send a protected media
copy if the healthy alternate was paced or window-full at the instant of the
primary send. A regression test first failed on that implementation: releasing
the Wi-Fi window two milliseconds later did not emit the backup before the
ordinary repair timer.

Pending media packets now retain one intended backup path, reusing the existing
bounded pending body (no separate unbounded payload queue). Each tick attempts
these backups before ordinary repairs and new traffic, with at most 64 such
sends. All current liveness, latency-placement, pacing, congestion-window and
Data Saver rules still apply. A blocked backup does not delay the primary.
The first authenticated delivery ACK cancels pending backup work; actual
backup sends retain the same packet ID and the receiver delivers only once.
Removed/failed paths, expired packets and a switch to Data Saver cancel the
queued intent. Normal loss repair remains the fallback when no backup can send.
Telemetry adds protection_deferred and protection_deferred_sent counters.

Validation: 112 library tests, 6 runtime tests, 4 secure-packet tests, one
bidirectional media simulation and two SRT upload audit tests pass. The upload
audit uses 1332-byte UDP payloads fragmented at the tunnel MTU, 10.656 Mbps,
and silent loss/rejoin of either link in Smart and Continuity: 7000/7000
datagrams arrive in each of six scenarios, with maximum gap 6 ms. The existing
native encrypted loopback SRT/ffmpeg test passes with 70/70 decoded frames,
106 ms maximum decoded-frame interval for a 10 fps source, and one sender
socket throughout. It still uses the smaller 1128-byte SRT payload. Unit tests
cover pacing/window deferral, ACK cancellation, duplicate suppression,
in-flight accounting, removal and Data Saver. Clippy library checks pass.

These tests establish the skipped-backup repair, NOT the cause or resolution of
the user's multi-second physical LAN unplug/replug freeze. The runtime socket,
USB-driver and real-WAN path still require aligned delivery measurements.
Neither cloud service was modified/restarted for this change. The separate
SRT gateway candidate is out of scope and must NOT be deployed as part of this
repair. This scheduler change does not change the wire format; the existing
relay can receive it, but using it on relay-to-Mac traffic requires a relay
update too. The Mac build is staged separately and not launched automatically.

Signed universal Release build 0.6.8 (19) completed and passed deep/strict
codesign verification. Both arm64 and x86_64 app architectures are present.
Archive: `dist/VERZ-Link-0.6.8-deferred-protection.zip`.
Build product: `/tmp/verz-protection-build.ZkDWin/Build/Products/Release/VERZ Link.app`.
All-target Clippy also passed. The archive has not been installed or launched.

## Boundlink-inspired delivery changes (0.6.7)

Boundlink was inspected read-only. Its deployed gateway embeds revision
`10f523b16e33375310c1ebe4fbb1a0966410848d` with dirty build metadata. Local
gateway tunnel/reassembly sources match that revision, but the uncommitted
binary changes and running Pi version have not been established. Local Pi
source checks carrier before sends, falls back to another WAN, and retains
session/dedup identity. Its voice policy can stripe similar paths or use a
primary plus a redundant payload copy. The gateway fans return packets out.

VERZ adopts the independent-delivery and retained-session behavior; this is
not a wholesale port or a claim of identical deployment behavior:

- The Rust Mac runtime queries Darwin SIOCGIFMEDIA before each scheduling
  tick. A reported carrier loss fails only that subflow and closes its socket;
  surviving sockets and session/sequence/dedup state remain intact. Unknown
  media status falls back to authenticated probes and existing OS events.
- Opening a replacement socket resets only that path through add_path, so
  a returning used adapter also observes the existing probation interval.
- Recognized SRT and the existing small realtime UDP class use an eligible
  alternate when their preferred path is silent, paced, or window-limited.
  The preferred path can no longer gate both primary and protection copies.
- Existing encryption, congestion limits, Data Saver policy and packet-ID
  deduplication are retained. SRT/RTP applications retain their own media
  reordering; no generic extra UDP holding buffer is introduced.

Validation: the formerly failing silent-SRT-pin test passes, as do paced and
window-full primary cases. A deterministic bidirectional voice test covers
each path disappearing and returning in Smart and Continuity policies: all
350 packets per direction arrive once, no queue drops, maximum permitted
delivery gap 60 ms. The real loopback SRT/ffmpeg test now restores the lost
path midstream and measures decoded-frame gaps: 70/70 decoded frames and
107 ms maximum observed gap with a 10 fps source. These tests do not emulate
USB driver, DHCP, or the user's actual WAN behavior. Physical acceptance is
still outstanding; 0.6.6 failed it. No further user cable test is requested
on the strength of simulation alone.

Deployed on user request at 2026-09-10 22:10:16 UTC to the VERZ relay
69.164.213.57. The service is active and listening on UDP 443; SHA-256:
`187f87d048d96115175a060fe9e2c939195cf9e9676ceacc7ca314763d84e760`.
The previous 0.6.6 binary is preserved at
`/opt/verz-link-lab/backups/verz-bond.v066-before-boundlink-adaptation-20260910`.
All relay source modules, Cargo.toml and Cargo.lock match the local engine
by SHA-256. The signed universal Mac app was launched and its UI verified as
0.6.7 (18), disconnected, with Wi-Fi available. Physical acceptance remains
outstanding. Boundlink files and services are unchanged.

## Scope and deployment boundary

This repair targets Secure Continuity and the secure leg of Automatic Hybrid.
It does not change the user to Hybrid or implement direct UDP/QUIC steering.
The current live app/server were left running while these changes were built.
Local test results are not a claim that native streaming or physical failover
on the user's actual Mac/cloud path has passed. Those checks must use the
matching new Mac and relay builds.

The authenticated bond prologue is now `multipath v2 / MTU1280`. It deliberately
rejects the old MTU1000/MTU1200 peers. Update the Mac and relay together; retain
the old binary/app as a rollback pair. A relay restart interrupts existing
sessions and is a maintenance step, not a failover test. Do not replace just
one side while a customer is streaming.

## Changes

- A pinned UDP flow respects its own congestion window, urgent reserve and
  pacing clock. Waiting packets stay in FIFO order while unrelated flows can
  use a different link. Scanning and emission are bounded per reactor turn.
- Pinning follows current health, latency-sensitive placement and Data Saver
  eligibility; it cannot revive a removed or excluded link.
- With a responding alternate, three missing periodic replies plus observed
  jitter stop new placement on a silent link. This is separate from the longer
  250–2,000 ms path eviction timer. Pending repair retains the packet identity;
  new UDP packets may re-pin to the responding alternate. The only still-usable
  path is not excluded just because its replies are temporarily late.
- The inner IPv4 MTU is 1,280 bytes. This accommodates QUIC's minimum
  1,200-byte UDP payload plus IP and UDP headers. Bond framing (18 bytes) and
  Noise framing/tag have a separate, bounded transport allocation. The maximum
  current bond packet is 1,372 bytes including outer IPv4/UDP headers.
  This is not dynamic path-MTU discovery or a guarantee about every underlay.
- Larger IPv4 UDP datagrams may be fragmented by the host. Fragment handling
  uses the IP ID, not payload bytes misread as UDP ports; short tails are not
  falsely classified as separate voice packets. Destination kernels reassemble
  the original datagram. Fragment pins have a short lifetime, and the pin table
  is bounded. At the pin limit, additional flows use ordinary placement rather
  than allocating unbounded state.
- Legacy tunnel transports still enforce their original payload limit despite
  the larger shared receive buffer. Authentication, replay protection and
  malformed/oversized frame rejection remain enabled.
- MTU-dependent regression fixtures use the configured size. UDP fixtures now
  contain deterministic IP headers rather than seed bytes that accidentally
  set IPv4 fragment flags.

## Automated verification

Run `cargo test --manifest-path Engine/Cargo.toml --all-targets` and
`cargo clippy --manifest-path Engine/Cargo.toml --all-targets -- -D warnings`.
Run the helper's Cargo tests and `swift test` as well.

New tests cover a full pinned window, pacing, independent-flow progress beyond
128 waiting packets, FIFO retention, a silent-path repair without explicit
unplug notification, fallback with only one path, and fragment classification.

`Engine/tests/secure_packets.rs` exercises real Noise handshakes, encrypted
packet/framing round trips, acknowledgements and replay rejection in both
directions. It includes full-MTU TCP packets, QUIC-sized UDP packets, small
media-sized packets and larger fragmented UDP datagrams. These are packet-level
checks, not SRT/WebRTC/QUIC application handshakes.

The silent-path unit scenario budgets a 10 ms alternate delivery and asserts
repair/new placement below 100 ms. This is one deterministic scenario, not a
measured macOS end-to-end failover guarantee. High alternate RTT, congestion,
media buffering and loss require separate measurements.

An opt-in native application test is available:

```sh
VERZ_FFMPEG=/opt/homebrew/bin/ffmpeg cargo test --manifest-path Engine/Cargo.toml --test native_srt -- --ignored --nocapture
```

This launches test-owned FFmpeg SRT/video endpoints on loopback through two
real encrypted scheduler instances. It drops one carrying logical path in both
directions without sending a failure notification. On this Mac it decoded all
70 requested frames: the cut occurred after frame 35, five outer data packets
were deliberately dropped, and 262 packets were delivered afterward using the
same sender socket. It does not alter OBS/VLC or establish physical-WAN timing.

At this checkpoint, 100 library tests, six runtime tests, four encrypted-packet
integration tests, six helper tests and ten Swift tests passed. The separate
native SRT test also passed. Strict Clippy passed. The universal Xcode Release
build is signed and includes both arm64 and x86_64 engine slices.

## Live SRT acceptance

User test endpoints (do not publish or change their configuration):

- OBS sends SRT to `69.164.208.201:9000`.
- VLC receives SRT from `69.164.208.201:9001`.
- VERZ Secure Continuity relay is `69.164.213.57:443` (UDP).

The original v0.6.1 session placed the live SRT flow on LAN. Removing Wi-Fi did
not interrupt it, while removing LAN froze it. This asymmetry identified the
carrying-path repair as the relevant failure rather than an OBS/VLC setup issue.

On September 10, 2026, v0.6.2 was deployed to both the Linode relay and the Mac
engine and tested in **Secure Continuity** with the existing OBS/VLC stream.
The LAN path was carrying nearly all stream traffic when its in-app `Use`
switch was disabled. A packet capture at the relay measured:

- SRT upload: 15,524 packets over 14.506 seconds; largest inter-packet gap
  87.693 ms.
- SRT download: 17,243 packets over 14.506 seconds; largest inter-packet gap
  29.042 ms.
- OBS remained streaming at 30 fps with zero reported dropped frames and no
  reconnect event during the cut. VLC playback time continued advancing.
- The relay recorded one path failure, moved delivery to Wi-Fi, reported no
  queue drops, and returned to two healthy paths after LAN was enabled again.

This closes the controlled LAN-removal failure seen through the app. A physical
cable pull and an upstream-blackhole test are still separate acceptance cases;
the loopback native-SRT test covers a deterministic silent-path failure but is
not a substitute for physical-WAN timing.

The user subsequently repeated the failover in **Automatic Hybrid** and saw no
visible SRT freeze. Record this as a user-observed continuity pass. It does not
yet have the relay-side packet-timestamp measurement captured for the Secure
Continuity test, so no numeric Hybrid failover bound is claimed here.

For each supported traffic class, verify one Wi-Fi path, one LAN path, both
paths, Wi-Fi loss, LAN loss, upstream silence without carrier loss, and recovery.
Observe both upload and download, stream/socket identity, media frame progress,
loss/retransmission counters and the actual delivery gap. Do not use an app
status label or one Speedtest public-IP result as continuity evidence.

Use an actual HTTP/3-only client for QUIC (no silent TCP fallback), a browser
WebRTC session with transport stats, native SRT playback, and long-lived TCP
upload/download sessions. Keep destinations/test settings matched. Direct
TCP cannot acquire relay-style source-IP continuity by this patch.

The private diagnostic endpoint `10.78.0.1:8080` was initially unavailable
because `verz-bond-http.service` was stopped. It was restored and the expected
health response was verified through the Mac tunnel. The v0.6.2 relay was then
deployed and restarted; `verz-bond.service`, `verz-brain.service`, and the
private diagnostic service are active. Full diagnostic transfer measurements
remain to be run. The diagnostic endpoint is not the SRT server.

### Physical cable-pull detection repair

The first live unplug test exposed an approximately two-second SRT pause even
though the in-app Use toggle did not pause. This was a real implementation bug:
the app polled macOS interface state every two seconds, and the engine also
allowed historical jitter to stretch fast silent-path steering toward its
two-second path-eviction ceiling.

The app now subscribes to SystemConfiguration Link/IPv4 notifications and
sends the updated path set to the running engine as soon as macOS reports
carrier loss. A one-second inventory poll remains only as a compatibility
safety net. Independently, when another encrypted path is answering, the Rust
scheduler stops new placement on a path after 60 ms without a probe, ACK, or
data response. Historical jitter may still widen final path eviction when it
is the only path, but it cannot widen multi-path failover. Automated coverage
includes a simulated 500 ms historical-jitter path whose eviction timer is two
seconds but whose SRT flow moves inside the 100 ms delivery gate.

This repair still requires a fresh physical unplug/replug measurement on the
Mac; compilation and deterministic scheduler tests alone are not acceptance.
The matching candidate was rebuilt into the Xcode Debug app and deployed to
the Linode relay on September 10, 2026. The deployed Linux binary SHA-256 is
`48ccdbd252ffa1d4e2420ebf8cbca9fe768d598c39c07cedb589b77bd757c39c`.

### Physical-cable capture and SRT continuity candidate 0.6.3

A subsequent full relay capture showed that the earlier physical-cable repair
did not meet acceptance. LAN stopped delivering encrypted packets at
18:56:42.803 UTC and Wi-Fi remained authenticated, but a later path transition
created a 167.748 ms gap in the OBS-to-SRT-server media packets. The external
SRT server then sent no media-sized packets back for 8.442717 seconds, although
its smaller SRT control packets continued. This matches the visible VLC freeze;
it was not a six-second wait for Wi-Fi authentication.

The relay counters exposed the failure chain. When LAN returned, its old
multi-megabyte congestion window was reused. The resulting burst filled the
1,024-packet TUN admission queue (`receive_backpressure` increased by 1,026)
and repairs increased from 77 before the event to 2,619. The recovered link
also became eligible to take the established fragmented UDP flow again.

Build 0.6.3 changes that behavior:

- SRT is learned from its standard control-packet header instead of a fixed
  port. Smart, Performance, and Continuity policies send each recognized SRT
  packet with the same authenticated VERZ packet ID over two usable paths;
  the receiver delivers the first and deduplicates the other. Data Saver does
  not add this redundancy. This intentionally spends approximately one extra
  path's worth of bandwidth for active SRT traffic.
- IPv4 fragments are associated with the UDP 5-tuple learned from their first
  fragment. The complete SRT datagram now keeps one flow identity and every
  fragment receives the same continuity treatment.
- An established SRT primary is not moved merely because a probe is 60 ms
  late. Explicit carrier removal still removes it immediately, final liveness
  failure still removes a silent path, and the proactive alternate copy is
  already in flight during either event.
- A returned adapter restarts at the bounded 32-MTU discovery window instead
  of retaining its pre-failure window. The TUN admission queue is also bounded
  at 8,192 packets to absorb legitimate recovery bursts without false ACKs or
  silent drops.
- The Tokio runtime is multi-threaded so packet writing and socket/control work
  do not all compete on one executor thread on multi-core Macs. A one-vCPU
  relay remains supported.

Automated verification for this candidate includes 104 library tests, six
runtime tests, four secure-packet tests, six helper tests, ten Swift tests,
strict Clippy, and a native FFmpeg SRT/video test that decoded all 70 requested
frames across a silent carrying-path cut. The signed Xcode Debug build is
universal (`arm64` and `x86_64`). The deployed Linux relay SHA-256 is
`b8d5a9e0d307d373e12c6a8cb0c955c17d9176e6720981486b031e3abe04e663`;
the immediately previous relay binary is retained under
`/opt/verz-link-lab/backups/srt-continuity-before-20260910/`.

After deployment, the relay immediately recorded duplicate authenticated SRT
packet IDs arriving through both healthy paths with no queue backpressure or
repair. This proves the protection mechanism is active, but a new physical
LAN pull with packet timestamps is still required before claiming the visible
freeze is closed.

### Physical-cable acceptance failure and standby training candidate 0.6.4

The next physical test rejected 0.6.3 in both Automatic Hybrid and Secure
Continuity. The relay capture `/tmp/verz-srt-v063-acceptance.pcap` contains
919,798 packets with zero kernel drops. During the second live LAN failure,
encrypted client traffic continued on Wi-Fi, but the external SRT sender had a
5.374866-second media-sized packet gap (19:27:02.025–19:27:07.400 UTC). A
separate 2.965-second upload gap coincided with the app changing sessions/modes,
not with the physical-path handoff.

The matching relay telemetry identified a different capacity-accounting bug.
Immediately before the failed-path event, the faster path had 10,487,125
acknowledged bytes while the protected Wi-Fi path had zero, even though Wi-Fi
was receiving every redundant copy. The first ACK removed the packet from the
pending map, so the later ACK from the standby copy was discarded. After LAN
failed, Wi-Fi therefore began with the untrained 40,960-byte window; repair
processing reduced it to 27,321 and then 21,807 bytes while timeouts rose to
28. SRT entered recovery even though the encrypted Wi-Fi path never
disconnected.

Build 0.6.4 retains a bounded one-second ledger for redundant attempts after
the first path completes delivery. A later authenticated ACK now trains the
path that actually delivered the standby copy—RTT, delivered bytes, delivery
rate, and congestion-window growth—without keeping the packet in the repair
queue or counting duplicate payload as application goodput. The ledger is
bounded at 32,768 attempts and pruned continuously. Automated coverage asserts
that the first copy completes delivery, the later standby ACK grows only the
standby path, and no repair is generated for the already-delivered packet.

This is a measured candidate fix, not yet a physical-unplug acceptance result.

### Physical unplug/replug rejection of 0.6.5 and survivor-window candidate 0.6.6

The user rejected build 0.6.5 after a synchronized physical test. The relay
capture `/tmp/verz-v065-acceptance.pcap` contains 1,183,208 packets with zero
kernel drops. LAN stopped delivering encrypted packets at
20:50:24.774773 UTC, stayed unplugged, and rejoined with a new NAT source port
at 20:50:48.868920 UTC. Wi-Fi remained authenticated for the entire test.

The failure was throughput collapse, not session loss. About four seconds
after LAN disappeared, the external SRT download fell from roughly 400 data
packets per second to 7–22 packets per second for about six seconds. A second
collapse followed LAN re-entry: 9–20 download packets per second for another
six seconds, followed by a retransmission burst. The largest individual
external SRT packet gaps were about 276 ms after removal and 299 ms after
re-entry, both long enough to exhaust a small live-media latency buffer.

Relay telemetry explains the collapse. With Wi-Fi as the only healthy path,
repairs rose from 1 to 603 and Wi-Fi timeouts rose from 1 to 45. Its congestion
window repeatedly fell into the 20–29 KB range even though the path stayed
healthy and no admission queue, socket, or packet-expiry counter increased.
Build 0.6.5 correctly avoided charging the live path for a missing redundant
copy on dead LAN, but it still treated a missing ACK for a packet sent only on
Wi-Fi as proof of congestion. That created a feedback loop during both path
transitions.

Build 0.6.6 keeps same-path repair and timeout telemetry, but a lone responsive
copy no longer receives loss-based window backoff. Its continuously measured
RTT and queue delay still control the window. Redundant copies that are all
responsive still provide enough evidence for the ordinary loss response, and
an unresponsive attempted path is still penalized. This change has deterministic
coverage for both the dead-redundant-copy case and the lone-survivor case. It
is a new physical-test candidate, not an acceptance result.

## macOS helper lifecycle repair

An in-place Xcode rebuild replaced the signed helper executable while the
previous build's privileged daemon was still resident. macOS rejected the old
process audit token with status `-67065`, and the app correctly surfaced
`Couldn’t communicate with a helper application.` The relay and both physical
links were healthy; no networking engine had started.

The stale registration was recovered once through macOS **Login Items &
Extensions**. The registered parent bundle is now build 13. The service now
exits successfully one second after its final VERZ session releases, provided
no other local user has a session. launchd starts the current signed helper on
the next connection. A controlled disconnect produced helper exit code 0 and
disabled the SOCKS proxy; reconnect launched a new helper PID, restored the
Hybrid proxy, and returned both relay paths to healthy without another approval
or password prompt. This lifecycle prevents later in-place development rebuilds
from retaining a stale helper process.
