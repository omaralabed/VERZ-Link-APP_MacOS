# Corporate-network fallback

## Purpose

Some managed networks permit HTTPS and the first UDP exchange on port 443 but
drop sustained return UDP. A VERZ path on such a network must not slow, reorder,
or disable healthy native-UDP WANs.

## Behavior

- Native encrypted UDP/443 remains the preferred carrier on every interface.
- Failure is decided from authenticated VERZ probes, not from an interface
  name, address range, ping, or a generic internet check.
- After a path remains unresponsive, only that interface opens an outer
  TLS/TCP connection on port 443. The existing Noise-encrypted VERZ packets are
  length-framed inside TLS; the inner protocol and encryption do not change.
- A TCP/TLS fallback path is standby while any native-UDP path is healthy. It
  therefore cannot enter normal bonding or create cross-carrier ordering delay.
- If every native path fails, an already-warmed fallback becomes eligible for
  the main encrypted tunnel. TCP and UDP application packets both remain inside
  the existing VERZ encryption and use that tunnel. Because the outer carrier
  is TCP, UDP applications inherit TCP head-of-line behavior on this path.
- The macOS main tunnel is established before the optional native-UDP
  accelerator. The transparent proxy accepts a UDP flow only while its native
  engine has an authenticated healthy path. If no native path is healthy, it
  declines new flows so macOS routes them through the main encrypted tunnel.
- If the last native-UDP path disappears while flows are already captured, the
  proxy closes those captures so applications can reopen them through the main
  tunnel. New corporate-only flows work immediately; continuity of an existing
  flow during this transition depends on the application's retry behavior.
- The reliable TLS carrier uses bounded batching and the kernel TCP congestion
  controller. VERZ still tracks delivery, but it does not run UDP pacing,
  inferred-loss backoff or datagram repair on top of a live TLS carrier.
- Each fallback interface runs an independent authenticated native-UDP recovery
  check every 30 seconds. The check uses another session and does not move the
  live path. Recovery requires at least 54 of 60 replies, including replies near
  the end of the test. Only then is the interface returned to native UDP.

## What is unchanged

- `UdpEngine` framing, scheduler and native failover are not modified. The
  macOS proxy only decides whether a new flow belongs to that accelerator or
  to the already-running main tunnel.
- Native UDP framing, capacity weighting, repair, reordering, and failover are
  not modified.
- Healthy interfaces continue using UDP while another interface uses fallback.
- The session key and the existing Noise layer remain the security boundary.
  The outer TLS certificate is a compatibility wrapper, not VERZ identity.

## Operations

The relay listens on both UDP/443 and TCP/443. Both protocols must be allowed by
the host and cloud firewalls.

The client fallback is experimental and disabled by default. Explicit test-only
opt-in switch:

```text
VERZ_CORPORATE_FALLBACK=1
```

Relay rollback switch:

```text
verz-bond server --no-corporate-fallback ...
```

Telemetry reports `carrier: "tls-tcp"` and `standby: true` for a fallback path.
The macOS UI labels it `Corporate fallback · TCP 443`.

## Production acceptance

Before enabling this on the public relay:

1. Verify native UDP paths retain their existing throughput, bonding ratios,
   failover time, and packet-repair counters.
2. Verify a restrictive interface changes to `tls-tcp` without changing traffic
   on a healthy native path.
3. Remove or disable all native paths and verify the warmed fallback carries the
   session without changing the public IP. Start a new UDP flow and verify that
   it is delivered through the main tunnel while the native accelerator reports
   `fallback: "main-tunnel"`.
4. Restore sustained UDP and verify the path changes back only after the
   independent recovery check succeeds.
