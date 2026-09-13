# TCP gateway intake correction — 2026-09-11 / 12 UTC

Follow-up: the intake fix remains in place. A TCP-only server send-path
optimization was subsequently deployed at 02:13:07 UTC; see
[TCP_EGRESS_FIX.md](TCP_EGRESS_FIX.md) for the current binary, measurements,
rollback point and remaining verification. The results below describe the
earlier intake-only deployment.

Deployed to **69.164.213.57**, `verz-bond.service`, at
**2026-09-12 01:07:49 UTC**. The installed Mac application and the separate
`verz-udp-gateway.service` executable/service configuration were not changed.
The existing Mac build 25 was disconnected and reconnected for the TCP restart.

## Scope and result

The confirmed Linux TUN internal-ring overflow was eliminated in the observed
post-deployment workload: **0 kernel TX drops over seven complete 25 MB
downloads**, versus **1,963 additional drops** during the final pre-deployment
three-request baseline (one of those requests stalled and timed out).

**This is not a claim that the full TCP speed problem is solved.** New TCP
connections still averaged 106–186 Mbps in this sample, compared with 262–303
Mbps directly. Reused TCP connections reached 237–241 Mbps. Outer transport
repairs remain present and require further investigation; there is no evidence
yet identifying every remaining throughput constraint.

## Implementation

- `Engine/src/intake.rs`: dedicated asynchronous reader, independent of the
  server's scheduling/encryption/select loop. Single ordered bounded channel.
- 1,024 queued packets maximum, each at most the tunnel MTU of 1,280 bytes
  (1.25 MiB of queued payload), plus one 64 KiB scratch buffer and a consumer
  batch of at most 64 packets. Oversize packets are counted, not truncated.
- Channel space is reserved before reading. Full-channel backpressure waits;
  there is no `try_send` drop path. Reader yields every 64 packets, and a sparse
  batch returns immediately without a batching-delay timer.
- Reader errors reach the server owner. Dropping the owner aborts the reader,
  including while waiting for TUN input or queue space.
- Linux TUN `verzb0` internal ring explicitly set and verified at 2,048 packets,
  up from 500. This is scoped to that interface, not a global kernel setting.
  Kernel SKB overhead is additional to payload memory. Queues remain bounded.
- Server consumes up to 64 packets per selection without changing validation,
  session lookup, encryption, scheduling policy, TCP reordering, or UDP routing.
- Five-second JSON reports now include `tun_intake` packet/byte counts,
  oversize drops, queue waits, current/peak occupancy, and maximum queue delay;
  `kernel_tx` includes absolute/start/report drops and actual ring length.
  Unavailable counters and unknown intervals are null, not false zeros.

Source comparison against the source that produced the previously deployed
binary confirmed only `src/intake.rs`, its `src/lib.rs` export and the server
integration in `src/bin/verz-bond.rs` changed. Cargo manifests/lockfile, vendor
code, congestion control, and reordering were identical to that deployed base.

## Verification

- macOS: **151 automated tests passed**, including five new intake tests and
  seven existing runtime tests. Two optional native SRT integration tests were
  not run in this task. Formatting checks passed for edited Rust files.
- Linux: **130 library tests passed**; the privileged test was run separately.
- A real Linux TUN test in isolated network **and mount** namespaces sent a
  burst of 1,500 IPv4 UDP packets while the consumer was paused: every generated
  packet arrived in sequence, with no kernel drops. This exceeds the previous
  500-packet ring size. Five unit tests additionally cover exact queue bounds,
  sparse traffic, oversize packets, cancellation, read errors, and counter resets.
- Candidate service startup/shutdown was checked in isolation with ring size
  2,048 and functioning telemetry before deployment.
- Test-harness corrections before acceptance: Linux emits unrelated IPv6 router
  solicitations on the test interface, so the test verifies the generated IPv4
  stream explicitly; a network namespace also needs its own sysfs mount to read
  its interface counters. The initial harness runs failed, then passed after
  these corrections. No production change was deployed on a failing check.
- Post-deployment 12-second `skb:kfree_skb` trace contained **zero FULL_RING
  events**. There were 18 other host-wide drop events; those are not attributed
  to this relay's packet intake. Interface counters stayed at zero afterwards.
- At 01:11:23 UTC: 144,418 packets / 183,499,447 bytes read by intake; zero
  oversize drops, queue waits, kernel drops or scheduler queue drops. Peak intake
  occupancy 594/1,024; maximum observed queue residence 74,845 microseconds.
  That residence and continuing repairs are reasons not to claim the complete
  throughput/latency issue solved.

### HTTP measurements

Cloudflare 25,000,000-byte endpoint; IPv4 HTTP/1.1, body discarded to `/dev/null`.
The app remained in Secure Continuity with both en0 and en7 selected. These
interfaces share the user's home router/internet service. OBS was previously
reported stopped; this task did not start streaming. No compilation ran during
these measurements. A full service/app reconnection resets transport learning,
so before/after short-transfer rates alone do not establish a causal speed gain.

| Condition | HTTP / completion | Average Mbps |
| --- | --- | --- |
| Old relay, fresh request 1 | 200 / 25 MB | 97.73 |
| Old relay, fresh request 2 | 200 / timed out at 20 s, only 15 MB | 6.00 partial |
| Old relay, fresh request 3 | 200 / 25 MB | 147.71 |
| VERZ disconnected, request 1 | 200 / 25 MB | 262.41 |
| VERZ disconnected, request 2 | 200 / 25 MB | 301.87 |
| VERZ disconnected, request 3 | 200 / 25 MB | 303.44 |
| New relay, fresh request 1 | 200 / 25 MB | 106.45 |
| New relay, fresh request 2 | 200 / 25 MB | 160.72 |
| New relay, fresh request 3 | 200 / 25 MB | 185.61 |
| New relay, keepalive sequence, first request | 200 / 25 MB, new connection | 174.11 |
| New relay, keepalive sequence, request 2 | 200 / 25 MB, reused connection | 238.61 |
| New relay, keepalive sequence, request 3 | 200 / 25 MB, reused connection | 236.70 |
| New relay, keepalive sequence, request 4 | 200 / 25 MB, reused connection | 240.78 |

These are short HTTP averages, not sustained aggregate WAN capacity guarantees.
No new physical unplug/replug or live OBS mixed-traffic acceptance test was run.

## Deployment and recovery

Remote staging and rollback assets:
`/opt/verz-link-lab/tcp-intake.udFDuq/`

- `candidate-verz-bond` and live `/opt/verz-link-lab/verz-bond` SHA-256:
  `72712e6823d176cdfaafb15cd0fcb7426504c2e2dcb97e155f0e383443442e6d`
- `previous-verz-bond` SHA-256:
  `9aafa60abc75e0c4183bc609c791c015ca15b938d819479da5a25e66c2664155`
- `previous-verz-bond.service`: unchanged unit backup.
- `after-drops.data`: completed kernel drop trace (no packet payload capture).
- `smoke.sh`, `smoke.log`, `install.sh`: isolated startup check and guarded
  deployment with rollback on TCP startup failure.

The candidate was built offline, with one build job and reduced CPU priority.
Only the TCP executable was atomically replaced; the unit was not edited.
TCP PID **23845**, zero unexpected restarts, memory charge ~4.4 MiB at the final
check. Preserve the backup for recovery; no commit or push was requested.

Unchanged UDP: PID **17808**, active since 00:20:22 UTC, zero restarts, SHA-256
`1112cef6101e533c79bb944cfd5cb2623b835313f3d245db98e4d1ee41f29507`.

Unchanged installed Mac: build **25**, bundled TCP engine SHA-256
`06b532733136c0559f7f46046382fb267f4a759eae6c13498c1c3f3e3d519b8c`.
At handoff, app PID 21113 was connected through `utun4`; TCP engine PID 27564.

Next investigation should correlate outer retransmission timing, ACK arrival,
client resequencing and pacing with real TCP throughput. Do not remove
congestion control, enlarge queues without bounds, or alter the working UDP
failover to conceal the remaining TCP gap.
