# TCP premature-repair correction — build 30

## Status

Installed the signed Xcode build 30 and updated only the TCP gateway on
69.164.213.57 after the user confirmed the interruption was safe. This fixes a
reproduced early-retransmission defect. It does **not** establish that the
reported throughput shortfall is fully solved or that independent WAN speeds
will add perfectly. Normal deadline-driven repairs still occur.

## Confirmed defect and correction

The old scheduler used its new-packet placement list as a loss detector. When
another path was fresh, a path quiet for 60 ms dropped out of that list. TCP
packets recently sent there could then be retransmitted after only 2 ms, even
though the path remained live and the packet's normal repair timer had not
expired. A policy change excluding a metered path had the same problem.

Three new deterministic regressions failed before the change and pass after
it, including a 7-ms-old packet on a still-live path. The TCP guard allows an
unexpired attempt to finish despite placement exclusion. Explicit carrier
failure/removal still permits immediate recovery; a silent path still recovers
at the normal packet deadline. No wire protocol, queue sizing, congestion-window
algorithm, UDP lane, or receiver reordering behavior was changed.

New bounded counters distinguish unique early deferrals, deferrals acknowledged
before any repair, normal TCP deadline repairs, and unavailable-path repairs.
These count transport decisions, not useful application bytes or interface
capacity. The guard applies to sequence-bearing TCP recognized by the existing
parser; bare ACK and fragmented-packet policies are unchanged.

## Validation

- Engine suite: **177 passed, 2 optional native-SRT tests ignored**.
- Five added tests cover early silence, policy exclusion, deadline recovery,
  explicit failure/removal, and unchanged legacy UDP recovery.
- Existing tests continue to exercise large-backlog TCP bonding, bounded path
  waits, UDP isolation, and recovery under queue/window pressure.
- Formatting check and Clippy passed. Only the two pre-existing lint categories
  `derivable_impls` and `collapsible_if` were allowed.
- Xcode Debug target build succeeded; deep/strict signature and Omar Alabed
  UDP extension/App Group validation passed before installation.

### Isolated Linux native TCP

Real kernel TCP, two engine processes, authenticated transport, and TUN devices
inside private mount/network/PID namespaces. Each run verified SHA-256 for
64 MiB in each direction. Equal paths were each 40 Mbps/6 ms RTT; unequal paths
were 40 Mbps/6 ms and 10 Mbps/40 ms. No host WAN routes were altered.

| Case | Baseline upload/download Mbps | Build 30 upload/download Mbps |
|---|---:|---:|
| Equal paths | 66.25 / 67.85 | 66.78 / 67.80 |
| Unequal paths | 42.58 / 41.98 | 42.06 / 43.02 |
| Unequal with 0.1% loss | Not rerun | 42.26 / 42.22 |

The repeated candidate path-down/up test also passed SHA-256 on the same TCP
connection (37.14 / 42.26 Mbps). Its briefly overlapping baseline check also
passed; their speeds are not treated as a controlled performance comparison.
The first flap run's SSH control channel was interrupted when the Mac app was
closed. That local SSH process was stopped only after confirming its remote
test children no longer existed. The candidate repeat saved its result on the
server, so completion could be verified independently of that connection.

### Actual Mac

Both interfaces currently use the same home router. These are private
Mac-to-gateway tests, not the user's independent cellular-hotspot setup. All
12 measured private transfers passed length and SHA-256 checks.

| Case | Three upload results, Mbps | Download Mbps |
|---|---|---:|
| Both 1 | 166.31, 211.11, 219.89 | 264.70 |
| LAN only | 180.81, 149.51, 139.19 | 274.47 |
| Both 2 | 178.53, 208.68, 214.55 | 277.84 |

In the two dual-interface batches, **45 and 47** TCP packets respectively were
ACKed without a repair after the old early-repair condition was suppressed.
343 and 189 normal TCP deadline repairs still occurred. The new guard therefore
addresses a real case on this Mac, not all observed retransmissions. Snapshot
intervals and unrelated background traffic limit exact batch attribution.

Across subsequent checks the session counter reached 272 early deferrals ACKed
without any retransmission, out of 629 unique deferrals. No local queue drops
were reported. Deferral is not equivalent to avoiding a repair: some packets
still needed their normal timeout recovery.

Short external HTTP/1.1 Cloudflare downloads, 25 MB each, returned HTTP 200:
direct over en7 299.15 Mbps; connected on both paths 230.19 Mbps; connected on
LAN only 264.69 Mbps. These are individual cold-transfer averages, not repeated
capacity estimates, but they do **not** support claiming full speed recovery.
Routes confirmed en7 for direct and utun4 for the connected request.

One intentionally paced 16 MiB upload completed on a single TCP connection,
source port 62166, while Ethernet and Wi-Fi were individually removed and
restored using VERZ's Use controls. SHA-256 matched; engine PID and connection
remained unchanged. This was a software path-removal check, not physical cable
unplugging, and socket buffering means small send-call gaps cannot establish
zero network interruption. A preliminary 40 MiB test was rejected by the
endpoint's existing 16 MiB cap; the harness was corrected, not the server.
An explicit UDP DNS query succeeded. No OBS/SRT streaming test was performed.

## Deployment and preservation

- Installed app: `/Applications/VERZ Link.app`, 0.7.0 build **30**.
- Built product: `/Users/viewvision/Library/Developer/Xcode/DerivedData/VERZLink-Repair/Build/Products/Debug/VERZ Link.app`.
- App PID 54143; TCP engine PID 54152 after reconnect.
- Installed universal TCP resource SHA-256:
  `65e0000f8ad8b9217e7fd4f65ba64c786a77dc581e060490d91121183210e26e`.
- TCP gateway PID 45082, active since **2026-09-12 07:51:35 UTC**, SHA-256:
  `a0c5195512634b3a89f2d2551816c556ac7e70278b84e816c8a62877a79a5602`.
- UDP gateway **unchanged**, PID 41955, active since 06:51:36 UTC, SHA-256:
  `1112cef6101e533c79bb944cfd5cb2623b835313f3d245db98e4d1ee41f29507`.
- UDP source was not edited. Xcode rebuilt/re-signed the embedded extension;
  do not describe that binary as byte-identical. Before/after executable hashes:
  `52e1deae60d6d97781fb160dedd01774867623d51cce973a8b5f79eda9f39bcd` /
  `7c75967838473a121e8451f9d80e1c459d501e535149170f99019ce1bc9b3c8b`.
- Both Use switches restored ON, connected, with both paths healthy.
- Temporary TCPTransportDiagnostics preference restored to its original absent
  state. No permanent extra file logging enabled. No commit or push performed.
- Pre-existing worktree changes preserved.

Rollback app archive:
`.build/xcode-run-backups/previous-164EBA64-FF53-4781-975A-8BC30D9EA3C0.zip`.
Rollback TCP gateway binary:
`/opt/verz-link-lab/tcp-repair.5oPvMW/previous-verz-bond`, SHA-256
`93481ad1fe58ef6724e9f32577050e2ba38efee5b6647b4f0081ceb81e61656e`.
Restoring requires disconnecting VERZ and restarting only the TCP gateway after
restoring its executable. Do not alter the separate UDP service.

Detailed evidence/scripts: `.build/tcp-repair-trial.LK4roF/` locally and
`/opt/verz-link-lab/tcp-repair.5oPvMW/` on the gateway. The Linux candidate used
its own copied build cache; the old shared release artifact was not overwritten.

## Remaining throughput work

The next unresolved question is why ordinary packet deadlines are reached so
often on two paths: distinguish late data/ACKs, actual loss, and the interaction
between per-path pacing, RTT estimation, and receiver gaps. Do not interpret
this patch as validation of the existing experimental congestion controller.
Single-interface performance and the independent-hotspot configuration still
need controlled validation before claiming the requested highest-speed result.
