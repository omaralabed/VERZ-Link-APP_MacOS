# TCP throughput diagnosis — 2026-09-11

Original investigation status: diagnosis only; the findings below describe the
pre-fix deployment. Follow-up: the TCP-only intake correction was deployed at
2026-09-12 01:07:49 UTC. See `TCP_INTAKE_FIX.md` for implementation, tests,
deployment identities, and the remaining throughput gap. UDP was not redeployed.

## User tests

All use HTTP/1.1 over IPv4, Cloudflare's 25,000,000-byte endpoint. These are
short single-TCP-connection samples, not sustained aggregate-speed benchmarks.

| Condition | Mbps |
| --- | --- |
| VERZ off, OBS off (one earlier run) | 299.14 |
| VERZ on, OBS off (one earlier run) | 187.29 |
| VERZ on, OBS streaming (one earlier run) | 126.61 |
| VERZ LAN only, OBS off (three runs) | 100.70, 150.50, 147.31 |
| VERZ LAN + Wi-Fi, OBS off (three runs) | 104.47, 139.56, 164.17 |

User confirmed both interfaces connect to the same home router/internet
service. They share upstream capacity. This does not excuse reduced throughput,
and a low LAN-only result means two-path striping cannot be the sole cause.

## Confirmed packet loss before Rust admission

The TCP relay uses Linux `verzb0`, MTU 1280, `tx_queue_len=500`.
Kernel: `6.8.0-139-generic`.

At 00:47:32 UTC, `verzb0` TX dropped = 40,649. After one 25 MB download,
at 00:47:42 UTC, it was 41,295: **646 additional dropped packets**. The download
averaged 20,826,651 bytes/s (166.61 Mbps), total 1.200385 s. The Rust scheduler
reported `queue_drops=0`, `receive_backpressure=0`, and `socket_backpressure=0`.
The interface's fq_codel qdisc reported zero drops too: the internal TUN ring
is distinct from that qdisc and from the Rust queues.

A subsequent eight-second `skb:kfree_skb` trace spanning three 25 MB downloads
recorded **1,456 drops at `tun_net_xmit+0x31b`, reason `FULL_RING`**. One unrelated
NETFILTER_DROP event was also recorded. This establishes TUN ring overflow as
an actual loss source, not just an inference from a throughput result.

Linux's corresponding source drops at `ptr_ring_produce(&tfile->tx_ring, skb)`
when the ring is full, before userspace reads the packet:
[Linux v6.8 TUN implementation](https://github.com/torvalds/linux/blob/v6.8/drivers/net/tun.c#L1070).
It is an upstream reference; the live Ubuntu trace supplies the deployed-kernel
evidence.

Remote profiling artifacts (no packet payload capture):

- `/tmp/verz-tcp-profile.6d2UfD/perf.data`: 324 CPU samples, no lost samples.
- `/tmp/verz-tcp-profile.6d2UfD/drops.data`: 1,457 packet-drop trace events.

## Other observations and limits

- `nettop` reported 1.97–6.68 MB out-of-order and 0.57–2.25 MB duplicate TCP
  bytes across four 25 MB transfers via `utun4`. These are receiver counters,
  not a claim that the relay alone duplicated every byte.
- Mac UDP full-socket-buffer drops stayed at 340 during that window. Server
  UDP receive-buffer drops stayed at 13,242. Neither counter rose.
- Mac TCP engine CPU peaked around 33.5% in the first instrumented batch.
  Server relay CPU ranged from low idle usage to 85.9%; many active samples
  were 40–72%, and sampled VM steal time was zero. These samples do not show
  sustained CPU saturation, but do not rule out short scheduling stalls.
- The server downloaded 25 MB directly from Cloudflare in 0.547805 s, averaging
  365.09 Mbps, with first byte at 0.429819 s. This is not a long-term server
  capacity guarantee. The simultaneous Mac request averaged 161.35 Mbps and
  used `utun4`: an initial command label said "Mac direct", but route/process
  inspection confirmed VERZ had been reconnected, so it was NOT a direct test.
- `PacketWriter` resequencing holds gaps for up to 80 ms. That is a candidate
  contributor to loss recovery costs, not proof that removing it is safe.
- Current server intake reads one TUN packet per selected branch of the same
  event loop that runs scheduler, recovery, encryption, and socket processing
  (`Engine/src/bin/verz-bond.rs`, server loop, currently lines 977–1085).

## Targeted next implementation

1. Drain TUN ingress promptly with a bounded dedicated intake/batch mechanism,
   keeping packet order and isolating it from expensive scheduling work.
2. Explicitly size bounded burst capacity for the TUN ring and userspace intake;
   avoid simply making queues unlimited or disabling congestion control.
3. Report kernel-interface drops alongside application queue drops so zero
   Rust drops cannot hide packets lost before admission.
4. Reproduce the same transfer pattern and verify FULL_RING events disappear,
   then compare throughput, duplicate/out-of-order bytes, and latency. Test
   mixed TCP/UDP and failover only after the TCP-only correction passes.

Do not modify the separate UDP gateway or installed UDP extension for this fix.
Ring overflow is a confirmed defect to address, not proof that it accounts for
the entire throughput gap or that one patch will restore all 300 Mbps.

## Unchanged deployment identities

- TCP `verz-bond.service`: PID 12367, SHA-256
  `9aafa60abc75e0c4183bc609c791c015ca15b938d819479da5a25e66c2664155`.
- UDP `verz-udp-gateway.service`: PID 17808, SHA-256
  `1112cef6101e533c79bb944cfd5cb2623b835313f3d245db98e4d1ee41f29507`.
- Both active with zero service restarts during inspection.
- Installed Mac build 25's bundled TCP binary matches `.build/Native/verz-bond`:
  `06b532733136c0559f7f46046382fb267f4a759eae6c13498c1c3f3e3d519b8c`.
  Its root-owned running copy could not be checksummed without administrator
  access. No privilege workaround was attempted.
