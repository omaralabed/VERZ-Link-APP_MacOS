# TCP sender correction — build 28

Installed the Xcode-built old Mac app at `/Applications/VERZ Link.app` and
updated only `verz-bond.service` on `69.164.213.57` at **2026-09-12 03:58:23 UTC**.
This corrects two demonstrated defects. **It does not establish that TCP
throughput matches the direct interface or that aggregation is production-ready.**

## Evidence and changes

1. The scheduler reclassified every queued packet even when pacing or the
   congestion window prevented every path from sending. New tests showed
   3,000 classifications and zero sends per blocked tick before the change.
   It now checks the smallest queued sizes and available budgets first,
   including the bulk reservation. It preserves queue order, pacing, window
   limits, priority traffic, and progress on other eligible paths. The size
   prepass remains O(queue length); it avoids repeated packet classification,
   allocation and path sorting, rather than claiming constant-time scheduling.
2. Light reverse-direction TCP ACK traffic reduced the gateway's window even
   when it was barely used: the live trace recorded 4,420 bytes outstanding
   against a 97,808-byte window. A regression using 98,000 bytes shrank to
   20,480 before the correction. Delay-only backoff and ACK-based growth now
   require recent use of at least half the window. A two-RTT history (bounded
   to 20–1,000 ms) covers loaded tail ACKs, expires after light traffic, and
   resets on path rejoin. RTT/liveness and pacing continue updating. Loaded
   delay response and the existing loss-repair policy remain enabled.

The distinction between unused and validated capacity is informed by
[RFC 7661](https://www.rfc-editor.org/rfc/rfc7661.html). This is **not** a full
implementation of RFC 7661, CUBIC, or QUIC congestion control. The pre-existing
experimental delay-gated loss policy still needs fairness/loss validation.

Added real queue-scan, blocked-turn, queued-packet and application-limited
window counters. An opt-in Mac diagnostic flag (`TCPTransportDiagnostics`)
saves one bounded latest telemetry JSON in Application Support, at most once
per second, off the UI queue. No payload or key is included. The flag was
turned off after these checks; normal operation does not write these snapshots.

## Live tests and limits

LAN only (`en7`, 192.168.1.235); no OBS stream. Direct routing was verified via
192.168.1.1/en7, connected routing via utun4/MTU 1280. Tests use IPv4 HTTP/1.1
with Cloudflare pinned to 162.159.140.220, retaining TLS verification. A reused
connection performed twelve 10 MiB uploads then eight 25,000,000-byte downloads.
No build was running during the connected performance checks.

| Completed batch | Download Mbps | Upload Mbps |
| --- | ---: | ---: |
| Direct, immediately before final deployment | 305.09 | 96.19 |
| Build 28 and updated TCP gateway | 199.43 | 140.84 |

These are total successful payload bits divided by total transfer time,
including startup/server response time, not averages of peak rates. All
requests in these two batches returned HTTP 200 with the expected byte count.
The upload baseline varied substantially during the investigation: earlier
direct samples reached roughly 320 Mbps, while the later direct batch had
about 1.76 MB of retransmissions and averaged 96 Mbps. Therefore the table
must **not** be presented as a causal upload improvement from this patch.
The completed download comparison still shows a material VERZ deficit.

A follow-up produced two successful downloads (one with 462 ms time-to-first-
byte, the next with 35 ms), followed by six HTTP 429 responses from Cloudflare.
That batch is not a speed result. No further Cloudflare requests were issued
after observing the rate limit. It does not retroactively explain all earlier
slow tests. Further performance acceptance needs a controlled test endpoint
and matched repeated direct/relay tests, not additional requests to a throttled
endpoint or another speculative tuning change.

During the pre-fix instrumented upload, the Mac scheduler recorded 133 queue
drops. The completed final batch recorded zero queue drops, receive/socket
backpressure and expired packets on both ends. Mac repairs: 4; gateway repairs:
30. Gateway kernel TUN drops: 0; maximum intake residence: 4.557 ms. Real window
counters showed application-limited observations being ignored, and loaded
Mac traffic still producing delay reductions. These are correctness signals,
not proof of full-speed performance or all traffic loss being eliminated.

## Verification and component identity

- Mac Engine: **163 tests passed**, two optional native SRT tests not run.
- Linux library: **143 passed**, one isolated privileged TUN test ignored.
- Five added regressions cover paced/full budgets, bulk reserve plus priority
  progress, light ACK traffic, and loaded-tail history expiration. The existing
  standby-ACK test still requires delivery/RTT accounting but no longer expects
  a single control packet to validate a larger congestion window.
- Clippy passed with only the two pre-existing allowed categories
  (`derivable_impls`, `collapsible_if`). `git diff --check` passed.
- Candidate Linux startup passed in private mount/network namespaces before
  deployment. Installation checked prior executable hashes and UDP PID, saved
  the prior TCP executable, and included automatic startup rollback.
- Xcode Debug build succeeded, both architectures built, deep/strict signing
  verified. Installed bundle matched Xcode's Debug product byte-for-byte.
- Two UDP DNS checks (1.1.1.1 and 8.8.8.8) returned valid answers after reconnect.
- Mac app build **28**, version 0.7.0. Main PID 39189 and TCP PID 39206 at the
  final traffic checks. TCP executable SHA-256:
  `e95c6531c2946badbbd14062884260c48a98f471c7dc3fab66500c52ba241486`.
- Gateway TCP PID **31731**, executable SHA-256:
  `1f73e888c2120ea826a51bd5aa17146238bb83c1555909b12cb91842152dcd09`.
- Separate UDP gateway **PID 17808 unchanged**, no restart or replacement;
  SHA-256 `1112cef6101e533c79bb944cfd5cb2623b835313f3d245db98e4d1ee41f29507`.
- Current Mac UDP executable SHA-256:
  `c91588b8ce15c05c3e613225755e51b298405d967451985bb3b69d13ebd38696`.
  The saved pre-build-28 archive contains
  `d4539066de712a09bdfbfa710bae248652717671ffa6e79126737b90fa67c521`.
  Xcode rebuilt/re-signed the embedded extension; its binary is **not**
  byte-identical to that archive. UDP engine/provider source and capture rules
  were not edited in this turn. Physical
  unplug/replug and mixed live SRT performance were not revalidated this turn.

## Artifacts and rollback

Remote source, tests, smoke/install scripts, candidate and prior TCP executable:
`/opt/verz-link-lab/tcp-send.9oiS7S/`. Prior TCP hash:
`69e5fa3b8df7e1b8d87ac6526ccd31f255d78b148c48c79f177d517a50d47e3c`.

Local logs and comparison script: `/tmp/verz-tcp-speed.lyqlDy/` (temporary).
Pre-build-28 app archive:
`.build/xcode-run-backups/previous-B6B5B66A-DA27-472A-A97F-E4C2429777E1.zip`.
That archive includes the scheduler-only diagnostic iteration. The earlier
`.build/xcode-run-backups/previous-12394C5F-DB4A-4D3A-96AA-398E1D7C35B1.zip`
preserves the original installed build 27 before this investigation's changes.

For rollback, disconnect and quit the app, restore/verify the chosen signed
archive, restore the saved TCP gateway executable and restart only
`verz-bond.service`, then reconnect. Do not alter the UDP gateway.

The app was left connected. No commit or push was performed.
