# VERZ Link for macOS

Native SwiftUI/Xcode client with a Rust encrypted multipath IPv4 engine and a
Linux relay. **Development build; not a completed V2 product.** See
[implementation status](IMPLEMENTATION_STATUS.md) for measured results and gaps.

## Run from Xcode

Open `VERZ Link.xcodeproj`, choose **VERZ Link → My Mac**, then Run. Requires
macOS 14+, Xcode command-line tools and Rust with Apple arm64/x86_64 targets.
The build phase compiles and bundles the Rust engine automatically.

Import the private connection profile/key in Settings on each test Mac. Keys are
not included in source or app bundles. The current shared development profile
does not implement production device enrollment or revocation.

Connected Wi-Fi and Ethernet links appear automatically. Unplugged ports are
hidden; a cable-connected adapter waiting for DHCP remains visible. Each path
has Use/Metered controls. Multiple Macs get separate tunnel sessions/IP leases.

Smart mode schedules bulk traffic across eligible links using RTT and available
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
