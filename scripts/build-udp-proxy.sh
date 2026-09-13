#!/bin/bash
set -euo pipefail
export PATH="$HOME/.cargo/bin:$PATH"
cd "$SRCROOT/UdpEngine"
archives=()
for architecture in $ARCHS; do
    case "$architecture" in
        arm64) triple=aarch64-apple-darwin ;;
        x86_64) triple=x86_64-apple-darwin ;;
        *) exit 1 ;;
    esac
    cargo build --locked --release --lib --target "$triple"
    archives+=("target/$triple/release/libverz_udp_proxy.a")
done
mkdir -p "$DERIVED_FILE_DIR"
xcrun lipo -create "${archives[@]}" -output "$DERIVED_FILE_DIR/libverz_udp_proxy.a"
