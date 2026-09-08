#!/bin/bash
set -euo pipefail
PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_DIR"
export PATH="${CARGO_HOME:-$HOME/.cargo}/bin:$PATH"
export MACOSX_DEPLOYMENT_TARGET=14.0
OUTPUT="$PROJECT_DIR/.build/Native"
mkdir -p "$OUTPUT"
for target in aarch64-apple-darwin x86_64-apple-darwin; do
    rustup target add "$target"
    cargo build --manifest-path Engine/Cargo.toml --locked --release --bin verz-bond --target "$target"
    cargo build --manifest-path Helper/Cargo.toml --locked --release --target "$target"
done
for component in verz-bond verz-app-helper; do
    package=Engine
    if [ "$component" = verz-app-helper ]; then package=Helper; fi
    lipo -create "$package/target/aarch64-apple-darwin/release/$component" \
        "$package/target/x86_64-apple-darwin/release/$component" -output "$OUTPUT/$component"
    codesign --force --sign - "$OUTPUT/$component"
done
swift scripts/GenerateIcon.swift .build/AppIcon.iconset
iconutil -c icns .build/AppIcon.iconset -o "$OUTPUT/AppIcon.icns"
