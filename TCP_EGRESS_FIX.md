# TCP gateway send-path optimization — 2026-09-12 UTC

Deployed to **69.164.213.57**, `verz-bond.service`, at **02:13:07 UTC**.
This follows the [TUN intake correction](TCP_INTAKE_FIX.md). It changes the
server's TCP carrier send path only. The installed Mac remains build 25;
the separate UDP gateway was neither replaced nor restarted.

## Evidence and scope

With the intake fix already running, three 25 MB downloads averaged
152.66, 179.35 and 184.76 Mbps. The latter two reused the first TCP connection.
Mac `nettop` reported no duplicate/OOO receive bytes or retransmitted bytes for
that curl workload, inner RTT approximately 14.5–19.5 ms, and receive windows
approximately 3–4 MB. That sample did not establish an ACK/reordering defect.

The one-vCPU gateway, however, used 82–87% CPU in active download samples,
including 58–63% system CPU. A 679-sample profile attributed 59.22% of samples
to the kernel; UDP send/network stack work was prominent. Source inspection
showed one send syscall per encrypted packet, even when the existing scheduler
released a batch. This supported optimizing kernel send overhead, not changing
TCP ACK timing or removing congestion control.

## Implementation

- New `Engine/src/egress.rs`, exported by `lib.rs` and used by the server's
  `send_server` in `Engine/src/bin/verz-bond.rs`.
- Linux UDP segmentation offload (GSO) submits consecutive, already-encrypted
  TCP carrier datagrams with one nonblocking `sendmsg`. The kernel splits them
  into the original wire datagrams. This is not a new transport protocol.
- Groups must have the same destination, path and ciphertext length. Maximum
  32 packets and 48 KiB per group. No waiting for additional packets, extra
  batching timer, persistent queue, or change to scheduler pacing budgets.
- UDP/media and control frames are not eligible for grouped sends. No change
  to encryption, nonce allocation, congestion control, TCP resequencing or the
  separate UDP engine. Already-scheduled recovery traffic follows the same
  eligibility rules as other TCP carrier data.
- Per-message `UDP_SEGMENT`, not a socket-global setting. Unsupported offload
  falls back to the same ciphertext sent individually. Would-block and other
  errors remain visible to the existing scheduler recovery logic. Counters do
  not count failed/short sends as successful sends, nor claim remote delivery.
- `tcp_socket_tx` telemetry reports batch/single calls, datagrams/bytes accepted
  by the local socket, fallbacks, blocked datagrams and failed datagrams.
- No global kernel, network-card offload, service-unit or Mac configuration
  changes. Hardware UDP segmentation was reported off; live batching works
  through Linux's supported software segmentation path.

Primary references: [Linux udp(7), UDP_SEGMENT](https://man7.org/linux/man-pages/man7/udp.7.html),
[Linux segmentation offloads](https://kernel.org/doc/html/latest/networking/segmentation-offloads.html),
and [Linux 6.8 UDP GSO self-test](https://raw.githubusercontent.com/torvalds/linux/v6.8/tools/testing/selftests/net/udpgso.c).

## Verification

- macOS: **155 tests passed**; two optional native SRT tests were not run.
- Linux: five egress tests passed, including actual IPv4 and IPv6 kernel GSO
  socket tests checking all 32 datagrams, every byte, order and destination.
- Unit cases cover size/path/destination/media boundaries, bounds, fallback,
  and blocked/failed/short sends without falsely reporting success.
- Formatting checked with the crate's Rust 2024 edition. Staged Linux source
  hashes match the three edited local Rust files.
- Candidate startup/shutdown passed in isolated network and mount namespaces
  before installation. Deployment guarded both the prior TCP hash and UDP PID,
  saved a rollback executable, and restarted only the TCP service.

### Download measurements

IPv4 HTTP/1.1, 25,000,000-byte Cloudflare downloads, all HTTP 200 and complete.
Mbps is curl's average bytes/second multiplied by 8 / 1,000,000. The Mac uses
Secure Continuity through `utun4`. Wi-Fi and Ethernet share one home router/ISP;
this does not test the capacity sum of independent internet services. No OBS
stream was started, and no compilation ran during these HTTP measurements.

| Condition | Three request averages, Mbps |
| --- | --- |
| Intake-fixed relay, before GSO; one curl, keepalive | 152.66 / 179.35 / 184.76 |
| GSO relay; one curl, keepalive | 230.73 / 266.72 / 256.57 |
| GSO relay, repeat; three fresh TCP connections | 245.48 / 252.99 / 258.03 |

One direct download during this turn averaged **235.48 Mbps**; previous-turn
direct samples were 262–303 Mbps. These short requests include connection and
startup effects, and internet conditions vary. They show repeated improvement
in the observed relayed downloads, not proof that VERZ exceeds direct capacity
or sustains a guaranteed 300 Mbps.

### Upload measurements and remaining gap

Each request posts 10 MiB of generated zeros to Cloudflare, HTTP/1.1, with an
empty `Expect` header. All completed with HTTP 200.

| Condition | Three request averages, Mbps |
| --- | --- |
| Intake-fixed relay, before GSO | 74.37 / 132.97 / 103.44 |
| Direct, VERZ disconnected | 151.12 / 177.63 / 115.79 |
| GSO relay, repeat | 50.95 / 116.95 / 142.39 |

**Upload is still variable and is not established as fixed.** The Mac's upload
send path was not changed. This server egress optimization primarily targets
downloads; it is not evidence that every remaining TCP constraint is resolved.

### Final health and timing

At the final check after approximately 238 MB read from TUN:

- Kernel TUN drops, scheduler queue drops, receive/socket backpressure, intake
  oversize drops and intake queue waits: **0**.
- 199,879 datagrams sent in 9,889 successful GSO batches, plus 96,918 single
  sends. Offload fallbacks, blocked datagrams and failed datagrams: **0**.
- Intake peak occupancy 433/1,024; maximum queue residence **11.75 ms**. After
  the first post-update comparison it was 3.233 ms, versus 74.845 ms observed
  after the intake-only deployment. These are workload-dependent maxima.
- Both paths healthy; outer repairs still present (379 cumulative), with path
  timeout counts 15 and 1. Zero local send errors does not mean zero network
  loss or zero recovery activity.
- A synchronized repeat of three downloads and three uploads sampled
  14–52% gateway CPU during active seconds. This mixed workload is not identical
  to the earlier download-only CPU profile; idle samples are not a performance
  comparison. No exact CPU saving percentage is claimed.

Local repeat evidence: `/tmp/verz-tcp-timing.YaWEX6/repeat.log`,
`after-cpu.log`, `final-health.log`; pre-change Mac counters in `nettop.csv`.
Remote pre-change CPU profile: the deployment staging directory's `cpu.data`.
An intermediate repeat's tool output was not retained; it is not included in
the performance tables above. These paths are diagnostic artifacts, not durable
test infrastructure.

## Deployment and recovery

Remote staging: `/opt/verz-link-lab/tcp-timing.AiD9Lg/`.
`source.tar.gz`, candidate, previous executable, smoke/deploy scripts and smoke
log are retained. The release build was offline, one job, reduced CPU priority.

- Live/candidate TCP SHA-256:
  `a3ccaf02c5291fd57e177a95a8a7f45b2b9b0ff7ab533cba864da041db85331a`.
  PID **26178**, active since 02:13:07 UTC, zero unexpected restarts.
- `previous-verz-bond` rollback SHA-256 (includes the TUN intake fix):
  `72712e6823d176cdfaafb15cd0fcb7426504c2e2dcb97e155f0e383443442e6d`.
- UDP PID **17808**, unchanged since 00:20:22 UTC, zero restarts; executable:
  `1112cef6101e533c79bb944cfd5cb2623b835313f3d245db98e4d1ee41f29507`.
- Installed Mac build **25**, app PID **21113**, bundled TCP executable:
  `06b532733136c0559f7f46046382fb267f4a759eae6c13498c1c3f3e3d519b8c`.
  App is connected at handoff. No local install or Xcode build was needed.

Recovery, if needed: verify the saved previous hash, atomically restore that
TCP executable to `/opt/verz-link-lab/verz-bond`, and restart **only**
`verz-bond.service`. Reconnect the Mac TCP session and verify health. Leave the
separate UDP service intact. No commit or push was requested.

## Acceptance still outstanding

1. Investigate upload variance with matched longer-duration samples and Mac
   upload/remote intake telemetry before selecting another change.
2. Verify real OBS/SRT plus TCP downloads/uploads together.
3. Verify physical LAN removal and reinsertion while streaming, and Wi-Fi
   failure, without claiming software toggles prove physical hotplug behavior.

The working UDP source/process was preserved, but the shared machine and WAN
still warrant a mixed-traffic regression check. This is a measured TCP download
improvement, **not** a declaration of complete speed/failover acceptance.
