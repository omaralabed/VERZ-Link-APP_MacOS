# TCP path scheduling — build 29

Scope: old Mac project and TCP gateway at `69.164.213.57`. UDP engine/provider
source, capture rules and the separate UDP gateway are unchanged. Build 29 was
installed from the signed Xcode Debug product and the TCP gateway updated at
**2026-09-12 04:54:55 UTC**. The app was reconnected with LAN and the phone hotspot.

## Correction

- Bulk TCP now compares the completion of **this flow's** queued data on a
  temporarily paced/full fast path against sending immediately on an eligible
  slower path. A short fast-path wait can avoid placing the early segment on
  the hotspot and creating a receiver ordering gap. Unrelated flows do not
  inflate that flow's backlog, and deferred packets retain FIFO order.
- The wait is bounded to one estimated fast-path RTT, clamped to 2–20 ms.
  Liveness, removal, congestion windows and pacing still govern eligibility.
  A large backlog or comparable paths can use both links; this is not a
  permanent LAN pin or TCP/UDP selector. No adapter names or fixed capacities
  participate in scheduling. Each sender handles its own direction.
- Fresh loaded samples of first-ACKed bulk TCP tunnel bytes refine placement
  estimates. Late duplicate ACKs do not count. Samples expire after one second
  and reset on rejoin; quiet traffic cannot validate a lower capacity. There
  is 25% estimation headroom, without changing the underlying pacer or window
  growth algorithm.
- TCP retries choose estimated earliest delivery, including a healthy original
  path. If its data retry also goes unanswered, a repair-interval penalty lets
  an alternate recover even if probes still answer. Same-path retries retain
  their existing in-flight charge; every copy consumes pacing and sent bytes.
- Receiver telemetry now reports held packets, peak buffered packets, total
  and maximum hold time, and deadline/limit gap releases. Runtime snapshots are
  copied once per second, not locked per packet. No receiver hold limit or
  release behavior was changed.

The scheduling is inspired by completion/blocking estimation in
[ECF](https://www.repository.cam.ac.uk/handle/1810/279112) and
[BLEST](https://olivier.mehani.name/publications/2016ferlin_blest_blocking_estimation_mptcp_scheduler.pdf).
It is not their MPTCP implementation and does not change VERZ's wire protocol.

## Evidence and limits

Three regressions failed against the pre-change scheduler and pass after the
change: brief full-window spill, brief pacer spill while UDP progresses, and
an unnecessary slow-path retry. Additional checks cover bounded waiting,
removal, full-window repair progress, large-backlog bonding, per-flow isolation,
rate expiry/rejoin, parsing, and truthful receiver gap counters.

The rate metric is unique **tunnel admission** throughput, not application
goodput. Receiver ordering counters are observability, not a new wire-feedback
controller. Completion is predicted from RTT/window/rate/backlog; this cannot
guarantee that every secondary path improves throughput under every network
condition. The existing experimental congestion controller and LAN-only relay
overhead are separate issues; this change does not establish they are solved.

Native Linux TCP tests use two real engine processes, kernel TCP sockets,
TUN devices, Noise framing and independently shaped veth links inside private
mount/network/PID namespaces. Each case verifies SHA-256 for 16 MiB upload and
16 MiB download. These are controlled lab checks on one host, not physical
Mac hotspot/ISP speed or OBS acceptance.

## Completed validation

- Mac Engine suite: **172 passed**, two optional native-SRT tests ignored.
- Linux library suite: **152 passed**, one isolated privileged TUN test ignored.
- Clippy passed with the two pre-existing allowed categories; diff check clean.
- Xcode Debug build and deep/strict signing verification passed. Installed app
  and built product compare identical. Xcode's existing Run/install workflow
  remains in place, with version 29 in the project and Info.plist.
- All native lab uploads/downloads completed with SHA-256 integrity. Cases use
  40 Mbps / 6 ms RTT for the fast link; the second is either equal or
  10 Mbps / 40 ms RTT. Tests use independently shaped directions, no public
  speed-test endpoint, and no changes to host WAN routes or production services.

| Native lab case | Before upload / download Mbps | Build 29 upload / download Mbps |
| --- | ---: | ---: |
| Single link, one run | 34.44 / 34.72 | 34.45 / 34.74 |
| Equal links, one run | 57.91 / 68.28 | 68.08 / 68.78 |
| Unequal links, median of three paired runs | 40.77 / 40.86 | 40.15 / 39.40 |

The unequal-link case does **not** demonstrate a throughput improvement:
candidate medians were 1.5% lower upload and 3.6% lower download. It still
exceeded single-link throughput. Median largest application read gap fell from
46.92 to 35.16 ms. The link-flap case also completed intact (candidate largest
download read gap 76.27 ms); cut timing relative to transfer progress means
its throughput should not be used as a matched speed comparison. The candidate
is deployed for the identified scheduling defects, **not** certified as a full
recovery of the user's reported 35% upload loss or additive WAN bandwidth.

After installation on the real Mac, 2,940,784-byte TCP download and upload
through `10.78.0.1:8080` both matched the gateway executable's SHA-256. An
external HTTPS request and UDP DNS queries to 1.1.1.1 and 8.8.8.8 succeeded.
The small transfers are integrity/connectivity checks, not capacity benchmarks.
Gateway telemetry after these checks had no queue drops, receive/socket
backpressure, expired packets, or reorder deadline/limit releases; maximum
observed receiver hold was 45 ms. That does not mean all TCP ordering waits
are eliminated. Physical Mac unplug/replug and OBS were not rerun this turn.

The subsequent real-Mac private-gateway TCP download transferred 188,210,176
bytes in 5.353308 seconds: **281.26 Mbps**. Three 16 MiB uploads each passed
SHA-256 verification at 176.08, 189.31, and 193.78 Mbps; combined throughput
was **186.06 Mbps**. These used the existing private `10.78.0.1:8080` test
service with VERZ connected. They are not Cloudflare results, do not include
the gateway-to-Internet leg, and have no matched pre-change/direct baseline.
They confirm sustained functional TCP, not that the reported Internet-speed
regression has been resolved.

## Installed components and rollback

- Mac version 0.7.0, build 29; main PID 43451, TCP PID 43470 at reconnect.
- Installed universal TCP resource SHA-256:
  `15c3b6ac76cc2fc46bf4afcaa5953a34e0c21ec9840b9304ce2981067027d1d4`.
  The privileged helper's executable copy was not directly hash-readable;
  installation signature/resource validation and new gateway telemetry were
  checked instead of claiming that inaccessible file was hashed.
- Gateway TCP PID 35403, SHA-256:
  `93481ad1fe58ef6724e9f32577050e2ba38efee5b6647b4f0081ceb81e61656e`.
- UDP gateway remains PID 17808, SHA-256:
  `1112cef6101e533c79bb944cfd5cb2623b835313f3d245db98e4d1ee41f29507`.
- Xcode rebuilt/re-signed the embedded UDP extension without source changes;
  its new executable hash is
  `0c347557d14337b33e08baee34290848692adddfa9922edfc72c6c25241af098`.
  Do not describe that binary as unchanged.

The prior signed app is saved at
`.build/xcode-run-backups/previous-EA4F5DFC-9FFC-4E00-9B8F-E68F7D9C5959.zip`.
The prior TCP gateway binary is in the remote staging directory as
`previous-verz-bond`, SHA-256
`1f73e888c2120ea826a51bd5aa17146238bb83c1555909b12cb91842152dcd09`.
Installation checked exact prior/candidate hashes and retained startup rollback.
Rollback requires disconnecting the app, restoring the signed archive and saved
TCP executable, restarting only the TCP service, then reconnecting. Do not
restart or replace the separate UDP gateway. No commit or push was performed.

Temporary local artifacts: `/tmp/verz-tcp-scheduling.MwyK7G/`.
Remote isolated staging/tests: `/opt/verz-link-lab/tcp-scheduler.z88qqq/`.
