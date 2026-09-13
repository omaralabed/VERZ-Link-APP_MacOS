# TCP window correction — 2026-09-12 UTC

Installed Mac **build 26** and deployed the matching TCP gateway to
**69.164.213.57** at **03:02:38 UTC**. This is a narrow congestion-window
correction, not acceptance of complete TCP bonding or hotspot performance.

## Reproduced defects

`Path::observe` consumes heartbeat RTT observations as well as data ACKs.
Previously, an elevated heartbeat RTT reduced the congestion window and ended
slow start even with **zero data in flight**. A regression test establishes a
20 ms baseline, then supplies 80 ms heartbeat replies for 9.5 seconds without
sending any data. Before the fix, the initial 40,960-byte window fell to
20,480 bytes. The test now passes without suppressing RTT or liveness updates.

A second boundary defect let the delay-backoff floor increase a window that
loss handling had already reduced below that floor. Delay backoff now cannot
increase the existing window.

These defects are demonstrated in tests. They are **not proof of the complete
cause** of the user's hotspot slowdown. The earlier hotspot screenshots were
captured while their Cloudflare tests were still running; their displayed
rates must not be presented as completed matched measurements.

## Scope

- `Engine/src/bond.rs`: do not reduce the window or slow-start threshold on
  delayed observations with zero data outstanding. Do not grow either there.
- Preserve pacing, active-transfer delay response, loss recovery, and framing.
  No new transport, fixed bandwidth allocation, or removed congestion control.
- Add bounded, per-path `window_control` telemetry: actual delay/loss window
  reduction counts, idle delay observations, ACK growth pauses, and the last
  reduction's reason, time, before/after window, in-flight bytes and RTT data.
- Main app build number 25 to 26 in its Info.plist and Xcode configurations.
- Keep the previous TUN intake and Linux TCP send batching corrections.
- No changes to UDP source, UDP gateway, connection preferences, capture rules,
  protocol selection, or public-IP behavior.

## Verification

- macOS Engine suite: **158 tests passed** (137 library tests included).
  The two optional native SRT integrations were not run.
- Linux library suite: **138 passed**, one root/isolated-TUN test ignored.
  Actual Linux GSO socket tests ran in this suite.
- Three added regression tests cover idle initial discovery, a previously
  earned window across idle heartbeat delay, and delay backoff below its floor.
  Existing active-transfer delay and loss tests also verify the new counters.
- Strict Clippy reports two pre-existing warnings in `egress.rs` (conditional
  Default implementation) and `intake.rs` (nested if). With only those two lint
  categories allowed, library Clippy passes. No claim of a clean strict run.
- Xcode Release build completed; universal app signing and the UDP/App Group
  mapping verified for Omar Alabed team `H7728UD4B3`. `git diff --check` passes.
- Candidate gateway started/stopped in isolated network and mount namespaces;
  its 2,048-packet TUN ring and TCP send telemetry were verified before deploy.
- App reconnected successfully. Route inspection confirmed `utun4`, MTU 1280.
  UDP DNS queries to both 1.1.1.1 and 8.8.8.8 returned valid answers.

### LAN-only HTTP checks

Wi-Fi was inactive throughout. Each download is a fresh IPv4 HTTP/1.1 request
for 25,000,000 Cloudflare bytes; uploads post 10 MiB with `Expect` disabled.
Every request completed with HTTP 200 and the expected byte count. No compile
was running during these tests. Direct tests were made while VERZ was
disconnected and routing through Ethernet. Mbps = average bytes/sec × 8 / 1e6.

| Condition | Download Mbps, three runs | Upload Mbps, three runs |
| --- | --- | --- |
| Before update, connected build 25 | 94.47 / 180.00 / 199.67 | 100.49 / 165.78 / 107.66 |
| Direct, VERZ disconnected | 278.50 / 304.79 / 292.97 | 155.19 / 177.65 / 165.40 |
| After update, build 26 | 257.37 / 266.30 / 234.61 | 95.18 / 102.00 / 140.79 |
| Build 26 repeat without reconnecting | 249.79 / 261.86 / 260.63 | 132.95 / 114.86 / 131.31 |

Downloads improved in these samples but remain below the direct samples.
Uploads remain variable and below the direct samples. The before/after app
session was restarted, tests are short, and network conditions vary; this is
not a controlled isolation of the correction's performance effect.

After the repeat: zero kernel TUN drops, queue drops, intake waits/oversize
drops, TCP send errors, socket backpressure, receive backpressure or repairs.
Maximum intake queue residence was 13.965 ms. The gateway path was healthy,
with no timeouts; its cumulative path-failure counter was 1. There were
27 active delay reductions and no loss reductions; the window was 692,014
bytes. Idle-delay observations were zero in this LAN sample, so this live run
does not itself reproduce the idle-hotspot condition from the unit test.

## Installed components and rollback

Remote stage: `/opt/verz-link-lab/tcp-window.mtjmun/`. Source, smoke/install
scripts, candidate and previous TCP executable retained. The offline build
used one job at reduced CPU priority. Installation checked both prior TCP/UDP
hashes and UDP PID, then atomically replaced TCP and restarted **only** TCP.

- New TCP SHA-256:
  `69e5fa3b8df7e1b8d87ac6526ccd31f255d78b148c48c79f177d517a50d47e3c`.
  PID 29099, active since 03:02:38 UTC.
- Previous TCP SHA-256:
  `a3ccaf02c5291fd57e177a95a8a7f45b2b9b0ff7ab533cba864da041db85331a`.
  Retained as `previous-verz-bond` in the remote stage; includes intake + GSO.
- UDP gateway SHA-256:
  `1112cef6101e533c79bb944cfd5cb2623b835313f3d245db98e4d1ee41f29507`.
  PID **17808 unchanged**, active since 00:20:22 UTC; no restart or replacement.
- Mac build 26 installed at `/Applications/VERZ Link.app`. TCP executable:
  `faafadcd497337359192a21f82d427d3193dbe3eca1fdaaa5adf04fb81476dcd`.
  App PID 33862; new TCP client PID 33887 at verification.
- The installation candidate uses the Xcode-built main app/TCP binaries but
  reuses the exact previously installed, signed UDP extension build 25. The
  outer app was re-signed and verified after this packaging step. Unmodified
  Xcode output remains in `/tmp/verz-tcp-window.1wU4zY/Xcode/`.
- UDP provider remained PID **21150**, with matching installed/running binary
  SHA-256 `33e07c7d6bb1e2eb8da5fa540df8b4fe9ec884e8064d6dd0a1edefa2cd09ef5d`.
  Its connection was stopped/restarted during the app upgrade; the extension
  process/binary was not replaced. UDP source checksums match pre-change ones.
- Previous app archive is retained at
  `.build/rollback-20260912-030238/previous-app-build25.zip` in this repository.
  Other temporary build and test artifacts are under
  `/tmp/verz-tcp-window.1wU4zY/` and may be removed by macOS later.

Rollback, if needed: disconnect/quit VERZ, restore and verify that saved app,
verify/restore the previous TCP executable, restart only `verz-bond.service`,
then reconnect. Do not change the separate UDP gateway/extension.

## Still unverified / next decision

1. Hotspot-only post-update throughput and window-reduction reasons: awaiting
   Wi-Fi reconnection to the phone hotspot. No claim that its slowdown is fixed.
2. LAN + independent hotspot contribution; preserve the faster path while
   investigating the slower path. This update does not implement a new
   aggregation policy or establish aggregate-speed gains.
3. Mixed TCP/OBS/SRT and physical unplug/replug regression after this update.
   UDP binaries were preserved, but that is not a substitute for a live test.

No commit or push was requested or performed during this correction.
