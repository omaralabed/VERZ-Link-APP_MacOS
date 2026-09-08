# VERZ Link macOS implementation status

This is engineering tracking, not a claim that the product is complete.

Source requirements: `VERZ/VERZ_LINK_V2.md`, September 8, 2026, plus the user's
requirements for native Xcode development, Rust networking, one-CPU relay
support, simultaneous Macs, and at most 100 ms failover in supported tests.

## Implemented baseline

- Native SwiftUI application and shared Xcode scheme, macOS 14+.
- Universal arm64/x86_64 app and Rust executables.
- Authenticated, encrypted IPv4 system tunnel and relay NAT.
- Independent concurrent Mac sessions and unique private IPv4 assignments.
- Credential/profile import and export without bundling credentials.
- Live interface byte counters, actual ICMP/file-transfer diagnostics.
- Automatic discovery of named Wi-Fi/Ethernet interfaces (latest source).

## In progress — required before another bonding handoff

- A single device session spanning independently bound physical uplinks.
- Bidirectional authenticated path probes and health state transitions.
- Bounded queues, cross-path duplicate rejection, acknowledgements and repair.
- Automatic link loss/recovery without removing the device tunnel.
- Traffic-aware scheduling, congestion limits and operating preferences.
- Actual per-path telemetry in the native app, not UI-generated metrics.
- Controlled real TCP/UDP continuity tests, including maximum interruption.

## Additional V2 requirements not complete

- Measured no-regression controller and sum-capacity acceptance gate.
- XOR protection and recovery-budget/capacity validation under impaired links.
- Per-device enrollment, revocation, short-lived key rotation and Hub integration.
- Corporate-VPN underlay coexistence and routing/DNS leak compatibility matrix.
- IPv6 forwarding, release-quality lifecycle, signing/notarization and updates.
- Multiple relay regions, capacity/abuse controls and relay-failure topology.
- 72-hour chaos, security review and the complete V2 acceptance test matrix.

Do not label a baseline connection, a synthetic probe, a predicted timeout, or a
partial feature set as a completed V2 product or a passed 100 ms failover gate.
