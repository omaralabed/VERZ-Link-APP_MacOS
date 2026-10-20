# TCP fast failover — build 75, 2026-10-19

## Purpose

A pulled cable paused every TCP connection for ~240 ms (measured with
`scripts/tcp-failover-test.py`: 242 ms download / 153 ms upload). The tunnel
stopped placing new traffic on the silent path after 60 ms, but the packets
already in flight on it were only resent after the repair deadline, which is
stretched to cover the path's recent pauses (70–300 ms). That rule exists for
a lone surviving Wi-Fi, where early repairs are pure waste. With a sound
second path there is no reason to wait.

## Change (`Engine/src/bond.rs`)

- Every path carries the rhythm-based failure detector shared with the UDP
  lane's Smart Repair (`verz-bonding-core::health::Health`): fed with every
  probe and data send, and with every probe reply and exact ACK. It judges
  silence against the path's own history, so a wired link is suspect tens
  of milliseconds after its last unanswered probe while a link with routine
  long stalls waits for them.
- `data_paths` leaves a suspect path out while another path is sound, so new
  traffic and the repairs of what it carried go to the survivor at once.
- The TCP early-repair deferral keeps giving a path the benefit of the doubt
  only when no sound survivor exists. Alone, nothing changes: the
  pause-stretched deadline and the September lone-Wi-Fi protections stand.
- Both ends run the same code, so download and upload benefit alike.

## Validation

- Unit: with real 20 ms probe timing, a TCP segment on a path that falls
  silent is resent on the survivor after 26 ms; with no survivor answering it
  waits for its deadline. 199 engine tests pass.
- Live before/after with `scripts/tcp-failover-test.py`: before, 242 ms /
  153 ms on the cable pull. After (run `20261020-012918`, both links on one
  ISP as before though a different one from the day before, a speed test
  running through the tunnel at the same time): the cable
  pull itself produced no gap over 100 ms in either direction — largest gap
  in the two seconds around the pull 81 ms download / 98 ms upload, both
  inside the baseline's own maximum (92 ms / 95 ms). The Wi-Fi pull: 54 ms
  download, one 148 ms upload gap while the speed test ran on the LAN.
- The same run shows the next problem, which is not detection: while the
  speed test ran over Wi-Fi alone, the probe saw 29 + 31 gaps of 100–333 ms.
  The server's telemetry explains it: the TCP tunnel's window on the Wi-Fi
  path grew to 2.9 MB (in flight up to 480 KB, response pause 210–220 ms) on
  a link whose bandwidth-delay product is about 30 KB. A full-speed transfer
  therefore stands a queue of hundreds of milliseconds in front of every
  other connection. Fix to follow: a delay-aware cap on each path's window,
  the way the coded sender holds its own queue (`DelayTrack`, Slow state).
- First "after" run (`20261019-161726`) is not comparable: a speed test on the
  same-ISP Wi-Fi, which was delivering only a few Mbit/s, stalled everything
  for 2.3–5 s after the pull; that was the queue above in its worst form.

## Paced TCP flows (build 76, 2026-10-20)

Why: the raw Wi-Fi, measured outside the tunnel with `verz-link-record` on
`en0` while `curl` loaded `en0` alone, holds a 100–400 ms queue about once a
second during a full-speed upload (p99 173–274 ms, 1.4–3% loss; the unloaded
LAN on the same line felt the uplink as a p99 of ~100 ms). The download
direction is nearly clean (p99 109 ms, no stalls). Nothing delivers through a
queue on the only link, but the tunnel had two faults of its own: a 0.5 Mbit/s
flow's 1 KB frames counted as bulk, so they also waited behind the speed
test inside the tunnel, and in Bonded/Smart Repair such a flow got no copy on
the second link while one existed.

Change (`Engine/src/bond.rs`): a TCP flow that stays within the continuity
rate (2 Mbit/s, 80 KB burst, 4 MTU to start) is *paced*. Its packets take the
streaming class ahead of bulk in the tunnel's queue, and outside Data Saver
the flow earns the same second-path copy Continuity gives all TCP, through
the same shared 2 Mbit/s bucket. A flow that overruns its bucket is bulk until
it has stayed under the rate for about 240 ms. Counter `paced_tcp_packets`.
Kill switch: `VERZ_TCP_PACED=0` on either end restores the old behaviour for
that end. UDP is untouched: every rule is gated on an IPv4 TCP flow key.

Validation (run `20261020-021049`, Bonded, speed test running throughout,
Mac telemetry sampled once a second): cable pull 87 / 93 ms, Wi-Fi pull
34 / 59 ms, LAN rejoin 102 / 104 ms; both-links stretches otherwise clean
except one 157 ms upload gap while the speed test's upload saturated the
shared ISP line through both links at once. Wi-Fi alone under the upload:
21 / 27 gaps, worst 179 / 190 ms (the night before: 33 / 41, worst
280 / 333 ms); both ends saw the Wi-Fi's own 181–184 ms response pauses, which
is the link. The Mac's delay-based window control did act on the upload side
(Wi-Fi window 257 KB → 125 KB over 3 s, round trip 124 ms → 9 ms), so no
tightening was needed; the queue sat in the tunnel (up to 421 packets), where
paced packets pass it.

Tests: `paced_tcp_flow_is_served_ahead_of_a_bulk_backlog`,
`paced_tcp_flow_gets_a_copy_on_the_second_link_in_performance_and_smart`,
`bulk_tcp_and_udp_are_not_copied_in_performance`,
`a_flow_returns_to_paced_after_a_quiet_quarter_second`; the TCP scheduler
suite now states that it describes bulk flows (`set_paced_tcp(false)`).

## Deployment

- Server 69.164.213.57: `/opt/verz-link-lab/verz-bond` sha256
  `84a6983e8ea53618…` (serves `verz-bond.service` on 443 and
  `verz-brain.service`), previous binary kept as
  `verz-bond.backup-20261019T201114Z`. Rollback: copy it back and
  `systemctl restart verz-bond.service verz-brain.service`.
- Mac: VERZ Link 0.7.0 build 75 (bundled `verz-bond` rebuilt), build 74
  preserved under `~/Library/Application Support/VERZ Link/tcp75-backup.UXXwXb/`.
- Paced TCP, 2026-10-20 06:08 UTC: server `verz-bond` sha256 `25d0896d5950165b…`
  (previous, the fast-failover build, kept as
  `verz-bond.backup-20261020T060804Z`); Mac build 76 (bundled `verz-bond`
  `dec962030ce79fae…`), build 75 preserved under
  `~/Library/Application Support/VERZ Link/tcp76-backup.J4kh6Q/`, archive
  `dist/tcp-build-76/VERZ Link.zip`. Nobody was connected at deployment.
