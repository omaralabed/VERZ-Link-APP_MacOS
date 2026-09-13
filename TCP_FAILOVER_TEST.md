# TCP delivery-gap test

Run with VERZ connected in **Secure Continuity** and both interfaces enabled:

```sh
python3 "/Users/viewvision/Desktop/VERZ Link MacOS/scripts/tcp-failover-test.py"
```

The test runs for 120 seconds, with 15 seconds of undisturbed baseline first.
Follow the Terminal prompts: unplug LAN at 20 seconds, reconnect at 35 seconds,
disable Wi-Fi at 60 seconds **only if LAN is ready**, restore Wi-Fi at 75 seconds.
The tool never changes an interface for you. Keep one usable path available.
Use independent internet services for an independent-WAN test.

## What it measures

- One bidirectional TCP socket through the private encrypted gateway path.
- New synthetic application frames every 20 ms in each direction (roughly
  0.5 Mbps/direction; about 15 MB total in two minutes before tunnel overhead).
- The Mac measures download `recv()` delivery timestamps; the gateway measures
  upload timestamps. Neither reader is throttled. No HTTP files, cached body,
  application retries, reconnects or a pre-filled finite download are used.
- Payload/sequence checks and verified end markers distinguish complete transfer
  from premature closure. A connection surviving does not mean no pause occurred.
- Baseline p99/maximum gaps, post-baseline maximum gaps, gaps exceeding the chosen
  100 ms budget, any unrecovered silence and sender frame-spacing are reported.
- Live upload notifications travel back over the same connection and may arrive
  late. The final upload measurements come from the independently saved gateway
  receiver report, not from the time the Mac sees those notifications.
- Interface state changes are observed with `ifconfig` polling (~250 ms). They
  are event markers, not precise link-detection or route-switch timing.

Each receiver uses its own monotonic clock; clocks are not assumed synchronized.
Raw receiver times and sender interval differences are saved. OS scheduling,
sender backpressure and pre-existing jitter can contribute to delivery gaps.
This is application-visible continuity evidence, not proof of a network-only
cause, zero interruption, peak throughput or behavior under full TCP/UDP load.
It does not validate public-IP migration of Direct Smart / Hybrid direct flows.

## Safety and files

The client requires existing noninteractive SSH access to `root@69.164.213.57`.
It copies only this test script and a fresh one-use probe token to a mode-700
`/tmp/verz-tcp-failover.*` directory. No app keys, user files or packet captures
are uploaded. The listener binds only to `10.78.0.1` on a temporary kernel-chosen
port, authenticates the token, accepts one test, then exits. The server inserts
a temporary firewall rule restricted to this Mac's current `10.78.*` tunnel
address, destination private tunnel address and random TCP port. It deletes the
exact rule when the one-use listener exits; if unused, the listener expires after
180 seconds. A test is bounded to 300 seconds plus 45 seconds recovery. No routes,
app settings, production binaries or production services are changed.

Local reports: `.build/tcp-failover-reports/<run>/REPORT.txt`, `download.json`,
`upload.json`, `interface-events.json` and setup metadata. Gateway evidence is
retained in that run's private temporary directory. It can be retrieved using
the printed path if the control SSH connection is unavailable after the test.
Ctrl+C saves partial test evidence once the test socket has started.

Local-only regression checks:

```sh
python3 scripts/test_tcp_failover.py
```

These exercise real loopback TCP and an isolated forwarding proxy with a deliberate
500 ms delivery pause. They do not flap a physical interface or validate VERZ.
