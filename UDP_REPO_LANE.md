# Repository UDP lane port — 2026-09-11

## Status

Build 21 also failed the user's subsequent physical test (approximately five
seconds of freeze). The complete-datagram replacement is documented in
`UDP_PROXY_PORT.md`; the earlier unit/native tests below were not physical
acceptance and must not be described as a verified fix.

Build 20 was installed/deployed. Physical acceptance was **partial**: the user
reported continuous data, but a brief approximately one-second freeze on cable
removal/return. Build 21's receiver correction is described at the end; it is
not proof that the remaining physical freeze is resolved.
The preceding scheduler-only candidate failed the user's physical test with
a five-second SRT upload stall. It is not evidence for this implementation.

## Exact source and adaptation boundary

`Engine/vendor/verz-link-core` comes from MacOS-2 repository commit
`654232ae7d379ee0e76df071721fa49132eaaa87`, path
`Vendor/verz-link-core`. The sender, scheduler, packet cache, packet encoding,
and duplicate-suppression code are reused, not replaced by another ACK-window
tuning change. `Engine/src/udp_reassembly.rs` is that commit's
`Tests/GatewayFixture/src/reassembly.rs`. The six imported core source/manifest
files were compared to the commit and match except trailing EOF whitespace.
The reassembly copy has local corrections in build 21, listed below.

The old app uses a TUN ingress, whereas the reference app captured application
UDP datagrams with a transparent proxy. The adapter therefore uses the
reference packet's TUN payload format to preserve complete IPv4 packets and
fragments. The existing assigned IP, TUN, gateway NAT mapping, Noise session,
and per-adapter socket lifecycle stay in place. This is a port of UDP sender
and recovery behavior, not a claim that the two apps have identical capture
architectures. No MacOS-2 working-tree source was used or edited.

## Live path

- IPv4 UDP bypasses the old scheduler's pending queue, cwnd, pacer, ACK admission
  gate, and TCP reorder writer in both directions.
- The imported Sender performs immediate writes and same-call alternate-path
  attempts on socket errors. ACK trims cache; it is not permission to send.
- Smart and Continuity protect relayed UDP with same-sequence copies across
  all ready WANs. This includes unknown/large UDP and fragment tails. Copies
  consume real bandwidth on every used WAN. Performance uses the reference
  scheduler; Data Saver disables its extra copies.
- Receiver uses the imported per-stream reassembly (50 ms gap budget, 25 ms
  repair grace), duplicate suppression, and independent bounded UDP delivery
  queue. Neither path disappearance nor return recreates session/flow state.
- Existing direct TCP, relayed TCP scheduler/recovery, and TCP reorder path
  are untouched by the lane. They still share physical bandwidth and sockets;
  this is not a new WAN fairness controller or a universal throughput guarantee.
- Inner reference packets are authenticated with a session-derived key AND
  encrypted inside the old Noise transport. They are never sent as plaintext
  HMAC-only reference packets. Largest normal outer IPv4 datagram is 1426 bytes
  at the existing 1280-byte inner MTU (below a 1500-byte WAN MTU).
- New authenticated `UdpReady` negotiation prevents treating the old relay's
  echoed Join bits as proof of support. Unsupported old relays cause an explicit
  connection error after three seconds. New relay still supports old clients.
- Initial UDP traffic has a separate 256-packet queue while capability/probes
  complete; it never enters TCP's queue.

## Bounds and limitations

The exact sender has a 512-packet resend cache. The adapter limits flow mapping
to 4096 active entries and 65535 non-reused IDs per session; exhausted identities
are reported as drops, not silently reused. Fragment associations expire after
two seconds. Receive state is limited to 256 active streams with 64 pending and
64 copy slots each, plus a 1024-packet output queue and separate 1024-packet TUN
writer queue. Backpressure/drop counters are exported in `udp_lane` telemetry.
Authentication does not provide bandwidth fairness; saturating UDP can still
consume a physical uplink's capacity. Higher-latency surviving WANs can change
arrival delay. No zero-interruption claim is made for arbitrary networks.

## Verification

- Imported core: 15 original tests pass.
- Engine: 124 library + 7 runtime + 2 media + 4 secure packet + 2 SRT audit +
  4 new repo-lane tests pass (143 normal tests; native video tests opt-in).
- New lane sends 24000 fragmented packets in each of two deterministic path
  failure scenarios with TCP queues/windows full and all UDP ACKs suppressed.
  Both pieces of every simulated datagram arrive once across silent loss,
  socket errors, and return. These are logical-clock tests, not line-rate claims.
- Real loopback UDP sockets verify encryption, tamper/replay rejection,
  maximum packet size, same sequence/flow identity, socket removal and return,
  and no modification of TCP pending state.
- Real FFmpeg/SRT test uses 1316-byte payloads, TUN-shaped fragmentation,
  encryption, bidirectional traffic, silent path loss and return. 70 frames
  decoded with a maximum 108 ms interval for a 10 fps source, one sender socket.
  This does not simulate the USB driver or physical Mac route changes.
- TCP and existing engine regression tests remain green. The production
  physical unplug test remains the acceptance boundary, not a passed claim.

## Deployment

Installed **0.6.9 (20)** and restarted only `verz-bond.service` on
`69.164.213.57` at **2026-09-11 20:39:03 UTC**. No relay key, firewall, network
unit, streaming server, or other service was modified.

Mac product: `/tmp/verz-repo-udp-build.Dz51mU/Build/Products/Release/VERZ Link.app`.
Installed in `/Applications/VERZ Link.app` and the existing helper-registered
Debug product at
`/Users/viewvision/Library/Developer/Xcode/DerivedData/VERZ_Link-ddfrjxkejzzgcoeqtypmbfygdlcb/Build/Products/Debug/VERZ Link.app`.
Both passed deep/strict codesign verification. Embedded engine contains arm64
and x86_64; SHA-256
`a51a56358c927616073c3ceb994d6d5e74e21f15c9db987a9123b2c215eaf412`.
Archive: `dist/repo-udp-build-20/VERZ Link.zip` (integrity checked).

Both previous app bundles are archived in
`/Users/viewvision/Library/Application Support/VERZ Link/repo-udp-backup.onQyre/`.

Server source/build/rollback directory:
`/opt/verz-link-lab/repo-udp.UMoy3P`.
`previous-verz-bond` and `previous-verz-bond.service` preserve the prior deployed
state. New binary SHA-256 (also checked against running `/proc/8630/exe`):
`1ba07e973dea5ea55075484607f3f21e898598fa952c3ece08aa24daedd27fca`.
Service active, restart count zero after this intentional restart. Linux ran
the same 143 normal tests successfully before installation.

Post-installation: app reports Connected, both paths healthy, version 0.6.9.
Server reports `udp_enabled:true` with increasing UDP and legacy/TCP counters;
an HTTPS request returned 200 during concurrent UDP traffic. This is a smoke
check, not an unchanged-throughput or physical-failover claim.

The user had selected **Secure Continuity connection mode + Performance
preference**; those settings were preserved. The full redundant repo behavior
for the next physical acceptance test requires **Smart or Continuity preference**.
Secure connection mode and scheduling preference are separate settings.

## Build 21 — receiver gap recovery correction

The latest test used Continuity preference (confirmed in the app afterward),
so this is not being attributed to the previous Performance setting. During
several LAN loss/return events the relay continued receiving approximately
5.8–6.1 Mbps of UDP; Wi-Fi RTT rose to roughly 50–90 ms in some five-second
samples. These samples cannot resolve a one-second interruption or identify
its exact cause. UDP send/backpressure counters did not show new failures,
but the original adapter failed to count reassembly insertion errors.

A deterministic test reproduced an adapter defect: with faster LAN as primary,
one Wi-Fi copy delayed 45 ms and 45 SRT datagrams fragmented into 90 IP packets,
the 64 future-copy slots filled. Even the gap-filling packet was rejected with
`FEC buffer capacity reached`. Also, the adapter marked refused packets in its
duplicate ledger before insertion succeeded, making subsequent retries ineligible.

Corrections, keeping TCP scheduling/routing and encryption unchanged:

- 128 fragment slots preserve the reference's effective 64-datagram capacity
  for the usual two-fragment SRT shape. This is bounded, not unlimited buffering.
- A packet that fills the next sequence gap is delivered even if future-copy
  slots are full; it needs no spare slot.
- Drain all contiguous primary/copy packets together when a gap closes, rather
  than releasing one protection copy per timer tick.
- Let Stream own delivery deduplication; update the separate duplicate telemetry
  only after successful admission, never poisoning a refused packet's retry.
- Count `reassembly_rejections`. Include UDP counters in final session output.
- Log `CARRIER_QUERY_DELAY` for measured adapter-status calls lasting at least
  50 ms. This adds observation only; no unproven USB-driver scheduling change.

Bounds for build 21 are 128 pending + 128 copy entries per receive stream,
256 receive streams maximum, and the existing 1024-packet delivery/writer
queues. Larger fragment counts may still exceed the effective datagram budget.

Verification: the 45-ms delayed-copy reproducer now delivers all 90 fragments
with zero rejection. Additional tests verify admission of a missing copy into
a full buffer and successful retry of a previously refused copy. All 146 normal
Mac engine tests and warnings-denied Clippy pass. Native encrypted fragmented
SRT again decoded 70 frames, maximum interval 108 ms at 10 fps, through silent
loss and return. This is a demonstrated receiver bug fix, **not a proven
explanation or resolution of the user's exact physical one-second freeze**.

### Build 21 deployment

Installed **0.6.10 (21)** in `/Applications/VERZ Link.app` and the existing
helper-registered Debug product named above. Both pass deep/strict codesign
verification. The embedded universal arm64/x86_64 engine SHA-256 is
`4559b05a8f1ad044e5c6c38d3d0a3748a05d388ef4361095b9bb179dc45c2565`.
Product: `/tmp/verz-udp-reassembly-build.esXfbV/Build/Products/Release/VERZ Link.app`.
Archive: `dist/udp-reassembly-build-21/VERZ Link.zip` (integrity checked).

Previous app bundles are archived, with integrity checks, in
`/Users/viewvision/Library/Application Support/VERZ Link/udp-reassembly-backup.YiNGbf/`.
The Debug destination contained preview/debug dylibs absent from the signed
Release product. The intermediate merged bundle was moved into this rollback
directory as `merged-debug-product.app`; a fresh exact copy then passed signing
verification. No source files were removed.

Relay source/build/rollback directory:
`/opt/verz-link-lab/udp-reassembly.bhCjEE`.
Linux all-target tests and release build succeeded before replacement. The
previous binary and unchanged service unit are preserved there. Only
`verz-bond.service` was restarted at **2026-09-11 21:05:26 UTC**; it is active,
PID **12367**, restart count zero. Installed and running `/proc/12367/exe`
SHA-256 match:
`9aafa60abc75e0c4183bc609c791c015ca15b938d819479da5a25e66c2664155`.
The deployment SSH connection timed out after the restart; a fresh connection
confirmed the actual service state and hashes before reporting deployment.
No keys, firewall, network configuration, or streaming server changed.

Post-installation UI inspection confirms version 0.6.10, **Disconnected**,
Secure Continuity mode and Continuity preference, with both adapters enabled.
No automatic reconnect or physical failover acceptance was performed. Direct
TCP source SHA-256 remains
`097109c5806d8f0f675fc5d3e73e1185d4330c805b4d2d24707775e2ceee577a`.
