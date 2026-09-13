# Old-app UDP failover candidate — 2026-09-11

Status: **FAILED physical acceptance after installation/deployment**. The user
reported a five-second SRT upload freeze after LAN removal and Wi-Fi upload
falling to 0.2 Mbps. The tests below did not reproduce or resolve that failure.
The separate repo-sender port now in progress is documented in UDP_REPO_LANE.md.
This is a correction of demonstrated scheduler gaps, not a claim that the
reported physical USB/LAN unplug freeze is resolved.

## Scope and reference

Work is confined to `VERZ Link MacOS`, targeting its existing relay at
`69.164.213.57`. The reference is the MacOS-2 repository commit
`654232ae7d379ee0e76df071721fa49132eaaa87`,
“Preserve working macOS SRT bonding baseline.” Its committed sources, not its
modified working tree, were inspected. No MacOS-2 or prototype files were changed.

The reference protects UDP independently of application-handshake detection and
keeps backup delivery independent of preferred-primary selection. It also keeps
session identity across adapter changes. This candidate applies the first two
principles to the old scheduler; its existing session and socket lifecycle is
retained. This is not a wire-protocol transplant or a complete engine replacement.

## Targeted changes

- Explicit **Continuity policy** protects large unrecognized IPv4 UDP and IPv4
  UDP fragments, even when the stream began before VERZ connected. This policy
  is distinct from the **Secure Continuity connection mode**.
- Recognized SRT and the existing small realtime-UDP class remain protected in
  Smart. Generic bulk UDP in Smart and Data Saver keeps its old behavior.
- A healthy UDP backup is no longer excluded merely because its RTT exceeds
  the preferred-primary cutoff. Faster eligible paths remain preferred.
- If the preferred UDP primary is paced or window-full, an eligible slower
  carrier can send. An unavailable preferred primary cannot hold both copies.
- Protection still uses the existing bounded primary-plus-one-backup design,
  not unlimited copies across every interface. Copies obey the existing pacing
  and congestion-window limits, reuse the packet ID, and are delivered once.
  A delivery ACK cancels any unsent backup.

TCP placement, direct TCP routing, encryption, wire format, helper routing,
UI, and session lifecycle code were not changed in this task. Copies still
consume real WAN bandwidth; this is not a new bandwidth-sharing controller or
a guarantee of unchanged mixed-traffic throughput.

Source changes: `Engine/src/bond.rs` and `Engine/tests/media_handover.rs`.
All pre-existing changes were preserved. Regression tests first failed for
missing generic-UDP protection, excluded high-RTT backup, and skipped deferred
high-RTT protection, then passed after the correction.

## Verification

- Engine all-target suite: 119 library, 6 runtime, 2 bidirectional-media,
  4 secure-packet, and 2 SRT-upload tests passed (133 total).
- Opt-in native encrypted loopback SRT/FFmpeg test passed separately: 70 decoded
  frames, one sender socket, silent path cut and return, maximum decoded-frame
  interval 115 ms for a 10 fps source. It does not use physical interfaces.
- Ten scheduler handover scenarios each delivered all 350 packets per direction
  once, with no queue drops. Tests include either path failing and returning,
  Smart/Continuity, small UDP, generic large UDP in Continuity, and backup RTT
  of 120 ms. Maximum arrival gap was 74 ms with the slower backup. This includes
  the change in propagation delay, not zero packet-arrival interruption.
- Helper: 6 tests passed. Swift: 10 tests passed.
- All-target Clippy with warnings denied, Rust formatting, and Git whitespace
  checks passed.
- Release built through `VERZ Link.xcodeproj` using the existing signing setup.
  App and embedded engine both contain arm64 and x86_64. Deep/strict codesign
  verification and archive integrity checks passed.

## Candidate and deployment boundary

Signed app:
`/tmp/verz-old-udp-build.I8qDVh/Build/Products/Release/VERZ Link.app`

Archive:
`dist/udp-failover-candidate.lBTG5I/VERZ Link.zip`

Embedded engine SHA-256:
`464e6743fab071fbdb85365a4b66a7a38e8f4e24240c11f4b438ac5e2cdf6a8c`

The app version was not bumped; identify this candidate by its archive and
engine hash. It was initially staged without changing the running app or relay.
The subsequent authorized deployment is recorded below. Previous dist archives
were not overwritten.

The wire format is unchanged, so the existing relay can receive candidate
packets. Applying the corrected **downlink send scheduling** also requires
building and deploying this engine on the old relay. A Mac-only update does not
change the server's packet placement.

Before accepting physical failover: deploy matching client/server candidates
with the previous binaries preserved, test upload and download during physical
LAN removal and return and Wi-Fi loss and return, and correlate packet delivery
and path counters at both ends. Verify working TCP behavior as well. These
local tests do not reproduce USB-driver stalls, real-WAN congestion, server
load, SRT receiver buffering, or external application reconnection behavior.

## Authorized installation and deployment — 2026-09-11

The user requested: “ok install and deploy so i can test.”

- Installed and launched `/Applications/VERZ Link.app` (0.6.8 build 19).
- Updated the existing macOS-helper-registered Xcode copy at
  `/Users/viewvision/Library/Developer/Xcode/DerivedData/VERZ_Link-ddfrjxkejzzgcoeqtypmbfygdlcb/Build/Products/Debug/VERZ Link.app`.
  This prevents the registered helper from launching the previous Rust engine.
  Both app bundles passed strict/deep signature checks and contain the exact
  candidate engine hash listed above.
- Preserved the previous Xcode app as
  `/Users/viewvision/Library/Application Support/VERZ Link/update-backup.Ts0mzk/previous-Xcode-app.zip`.
  Its archive passed integrity verification. Debug-only dylibs not part of the
  signed Release app were moved into that backup folder, not deleted.
- Server source/build tree:
  `/opt/verz-link-lab/udp-candidate.Vo0VGO` on `69.164.213.57`.
  Cargo manifest, lockfile and scheduler hashes matched the local source.
  All 133 normal Engine tests passed on Linux; the optional native FFmpeg test
  was not run on Linux. The release engine was built there with one build job.
- Preserved the previous relay executable and service definition as
  `previous-verz-bond` and `previous-verz-bond.service` in that server tree.
- Atomically installed the candidate at `/opt/verz-link-lab/verz-bond` and
  restarted only `verz-bond.service` at **2026-09-11 19:09:16 UTC**.
  The unit, credentials, firewall, and other services were not changed.
- New Linux executable SHA-256:
  `188ade819dce72935d2a908ba80a6bf751e8335c31c0d0c0f515907b92676275`.
  Previous executable SHA-256:
  `187f87d048d96115175a060fe9e2c939195cf9e9676ceacc7ca314763d84e760`.
- Verified the restarted service active and listening on UDP 443, with no
  automatic restarts. Connected the installed Mac app successfully using its
  saved **Secure Continuity connection mode + Smart preference**. Wi-Fi `en0`
  and Ethernet `en7` both reported healthy and carried traffic. A normal HTTPS
  request returned HTTP 200 after connection.

No physical adapter was unplugged/disabled during deployment, and OBS/VLC
settings were not changed. The user can now perform the physical stream test.
Generic large UDP protection requires the separate **Continuity preference**;
the saved Smart preference was deliberately left unchanged. Actual physical
failover acceptance remains outstanding.
