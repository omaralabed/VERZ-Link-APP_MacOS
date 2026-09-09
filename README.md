# VERZ Link for macOS

Native SwiftUI/Xcode client with a Rust direct multi-flow engine plus an
optional encrypted multipath relay. **Development build; not a completed V3
product.** See [architecture V3](ARCHITECTURE_V3.md) and [implementation
status](IMPLEMENTATION_STATUS.md) for measured results and gaps.
The current throughput investigation and repeatable test command are in
[performance notes](PERFORMANCE.md); do not use the deliberately delayed
continuity stream as a speed benchmark.

## Run from Xcode

Open `VERZ Link.xcodeproj`, choose **VERZ Link → My Mac**, then Run. Requires
macOS 14+, Xcode command-line tools and Rust with Apple arm64/x86_64 targets.
The build phase compiles and bundles the Rust engine automatically.

Direct Smart is the default and needs no relay profile. It sends proxy-aware
IPv4 TCP connections directly to their destinations, assigning each complete
connection to one selected adapter. It does not add VERZ payload encryption;
HTTPS/TLS and other application security remain unchanged.

Secure Continuity retains the encrypted relay tunnel. Import its private
connection profile/key in Settings on each test Mac. Keys are not included in
source or app bundles. The current shared development profile does not
implement production device enrollment or revocation.

Automatic Hybrid keeps Direct Smart and Secure Continuity warm at the same
time. Proxy-aware TCP goes direct unless its domain suffix is listed under
Hybrid Security or every direct path fails. Escalated traffic uses the existing
encrypted relay without reconnecting the Hybrid session. The encrypted server
brain receives path health metadata only and advises weights/cutoffs; the Mac
keeps a safe local policy if that control channel is unavailable.

Connected Wi-Fi and Ethernet links appear automatically. Unplugged ports are
hidden; a cable-connected adapter waiting for DHCP remains visible. Each path
has Use/Metered controls. Multiple Macs get separate tunnel sessions/IP leases.

In Direct Smart, the Rust engine probes every adapter independently and rotates
new flows across eligible links. A path at 75 ms RTT or above receives no new
flows while a faster healthy path exists; it remains under observation. The
current direct path uses the macOS system SOCKS setting, so it covers apps that
honor that setting. Transparent UDP/QUIC and migration of one established
session remain Apple Network Extension gates.

In Secure Continuity, Smart mode schedules bulk traffic across eligible links using RTT and available
congestion-window capacity, not a fixed primary connection. A 40 ms RTT
difference does not exclude a path. At 75 ms smoothed RTT a path becomes standby,
with probes retained and recovery below 65 ms. If all paths exceed the cutoff,
the least-latency responsive path remains a last resort to avoid a blackhole.

The signed app registers its macOS-managed connection helper once. Enable VERZ
Link in System Settings → General → Login Items & Extensions when requested,
then Connect again. Normal connections use authenticated XPC, not AppleScript
or a stored administrator password. The helper verifies the signing team and
executes root-owned copies of the bundled Rust binaries. One-time approval and
password-free reconnect were verified on the development Mac; see the
implementation status for remaining distribution and second-Mac checks.

## Build and verify

```sh
bash scripts/build-app.sh
swift test
cargo test --manifest-path Engine/Cargo.toml --locked --lib --bin verz-bond
cargo clippy --manifest-path Engine/Cargo.toml --locked --all-targets -- -D warnings
```

The universal signed test product is built in Xcode DerivedData outside iCloud
Desktop. The script prints its exact location and creates the distribution ZIP
in `dist/`. Select an Apple signing team in Xcode: the managed helper refuses
ad-hoc clients. Apple Development signing is not Developer ID/notarized release
distribution; release packaging and a Network Extension remain outstanding.

`Engine/scripts/check-linux-continuity.sh` runs as root on the Linux test relay.
It creates two isolated network namespaces, two shaped virtual WAN links and a
private HTTP endpoint. It never changes the host default route or shapes SSH.
Modes: `cuts`, `low`, `high`, `both`. It removes only its temporary namespaces
and leaves private test logs for inspection. These are controlled virtual-link
tests, not proof of the physical Mac 100 ms failure-recovery requirement.
