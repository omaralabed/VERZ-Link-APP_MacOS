# VERZ Link Cross-Platform Architecture

## Status

This document defines the target architecture for VERZ Link on macOS, iOS,
Android, Windows and Linux-based VERZ routers. It is a product direction, not a
claim that every platform is implemented today. The macOS client and Linux
gateway are the current reference implementation.

## Product model

One customer-owned VERZ server can accept concurrent connections from all
supported VERZ clients:

- macOS
- iOS and iPadOS
- Android
- Windows
- Linux-based VERZ routers

Every device receives its own connection key, tunnel identity and session. A
connection key is individually billable, revocable and replaceable. Devices do
not share a master secret. Several authorized devices may use the same server
and public egress IP at the same time, subject to the server's configured
capacity and the customer's connection-key allowance.

## Architectural rule

The protocol and networking behavior belong in one shared Rust core. Native
platform code is limited to operating-system integration and user interface.

```text
                 VERZ server and protocol
                           |
                    Shared Rust core
        encryption | scheduling | repair | reordering
                           |
       +-----------+-----------+-----------+-----------+
       |           |           |           |           |
     macOS        iOS       Android      Windows      Linux
     adapter      adapter     adapter      adapter      adapter
       |           |           |           |           |
  Network       Packet       VpnService   Wintun/     TUN, routing
  Extension     Tunnel                    WFP         and firewall
```

The same scheduling, encryption, failover, repair and packet-ordering rules
must not be reimplemented independently in Swift, Kotlin, C# or C++. That would
create platform-specific behavior and multiply the risk of networking
regressions.

## Shared Rust core

The shared core owns:

- VERZ wire protocol and protocol-version negotiation
- Authentication using a device-specific connection key
- Tunnel encryption and replay protection
- Packet framing and validation
- Interface measurements and path-health state
- Capacity-aware path scheduling
- TCP and UDP policy decisions
- Failover, repair and selective redundancy
- Receiver-side duplicate removal and reordering
- Session statistics and privacy-safe telemetry
- Compatibility tests shared by every platform

The core exposes a small platform interface for:

- Reading and writing IP packets
- Discovering usable network interfaces
- Opening a socket on a specific interface or operating-system network
- Receiving link, address and route changes
- Securely storing device credentials
- Reporting lifecycle events such as sleep, wake and background suspension
- Providing monotonic time, logging and telemetry transport

Platform adapters must not contain their own alternative bonding algorithm.

## Platform adapters

| Platform | Native integration | Responsibilities |
| --- | --- | --- |
| macOS | Network Extension, Swift UI and privileged helper where required | TUN lifecycle, interface discovery, signing, installation and settings |
| iOS/iPadOS | Packet Tunnel Network Extension | Packet tunnel lifecycle, Wi-Fi/cellular path access, background rules and Keychain storage |
| Android | `VpnService` and Android network APIs | VPN lifecycle, binding carrier sockets to a `Network`, foreground service and Keystore storage |
| Windows | Wintun or Windows Filtering Platform | Virtual adapter, route/DNS management, service lifecycle and Windows credential storage |
| Linux router | TUN, netlink, nftables and system services | WAN discovery, LAN routing, NAT/firewall, DHCP/DNS integration and hardware monitoring |

Feature names may be shared across platforms, but availability must reflect
real operating-system capabilities. In particular, mobile operating systems
can impose restrictions on simultaneous Wi-Fi and cellular use, background
execution and VPN distribution. The product must not claim bonding on a mobile
platform until that behavior passes physical-device testing and store-policy
review.

## Server behavior

The server is platform-neutral. It identifies a device from its connection key
and creates an isolated client session with a unique tunnel IP. It must support:

- Concurrent clients from different operating systems
- Multiple active paths within each client session
- Independent statistics, limits and revocation for each device
- A stable public egress IP for connected clients
- TCP and UDP forwarding through the same authenticated session
- Safe reconnect without allowing two devices to impersonate one another
- Per-device and per-account traffic accounting
- Server-capacity enforcement so one device cannot starve the others

The server protocol must be versioned. A server upgrade should continue to
accept supported older clients during a defined migration window. Unsupported
protocol versions must fail explicitly rather than silently losing bonding or
failover behavior.

## Connection-key lifecycle

1. The customer purchases or is assigned a connection-key allowance.
2. VERZ Hub issues a one-time enrollment credential for a named device.
3. The device creates or receives its own long-lived key in secure storage.
4. The server associates the key with the customer's deployment and device.
5. The customer can view, rename and revoke the device without replacing keys
   on other devices.
6. Lost or replaced devices receive new keys; revoked keys cannot reconnect.

Production keys must never be embedded in application bundles, source code,
logs or downloadable server images.

## Repository direction

The current engines should evolve toward these boundaries without rewriting
working networking behavior:

```text
core/              Shared protocol, crypto, scheduler, repair and reorder logic
platform/apple/    macOS and iOS packet-tunnel adapters
platform/android/  Android VpnService and JNI/UniFFI boundary
platform/windows/  Windows service and virtual-adapter boundary
platform/linux/    Gateway and hardware-router integration
server/            Multi-device relay, leases, accounting and policy
conformance/       Cross-platform protocol and failure-regression tests
```

The exact directory migration can be incremental. Working macOS and gateway
code should first receive stable interfaces and conformance tests; it should
not be replaced merely to match this proposed layout.

## Release requirements for every client

A platform is not considered compatible solely because it connects. Before
release it must pass the same observable requirements:

- Encrypted traffic exits through the assigned VERZ server
- Device keys cannot authenticate another unapproved device
- TCP and UDP survive supported link failures within their defined budgets
- Packets are not duplicated or reordered beyond protocol policy
- A degraded link does not reduce useful traffic below the documented policy
- DNS, IPv4 and any advertised IPv6 behavior are verified
- Sleep, wake, network change and reconnect behavior are deterministic
- Statistics agree with measured payload within a documented tolerance
- Rollback and protocol-version compatibility are tested

Physical multi-network tests remain mandatory. Simulators and namespace tests
are regression gates, not substitutes for Wi-Fi, cellular and Ethernet tests.

## Rollout order

1. Stabilize and version the existing macOS-to-Linux protocol.
2. Extract a platform-neutral Rust API with unchanged packet behavior.
3. Add automated conformance and failure tests around that API.
4. Implement Windows and Linux-router adapters.
5. Implement Android and validate Wi-Fi/cellular behavior on physical devices.
6. Implement iOS/iPadOS after validating Apple entitlement and path-control
   requirements.
7. Add VERZ Hub enrollment, billing, device limits and revocation.

This sequence reuses proven behavior while keeping each new operating-system
integration small, testable and replaceable.
