#!/bin/bash
set -euo pipefail
PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_DIR"
swift scripts/verify-udp-signing.swift --source "$PROJECT_DIR"
export PATH="${CARGO_HOME:-$HOME/.cargo}/bin:$PATH"
export MACOSX_DEPLOYMENT_TARGET=14.0
OUTPUT="$PROJECT_DIR/.build/Native"
VERZ_SIGN_IDENTITY="${EXPANDED_CODE_SIGN_IDENTITY:--}"
if [ -z "$VERZ_SIGN_IDENTITY" ]; then VERZ_SIGN_IDENTITY=-; fi
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
    component_identifier=com.verz.link.engine
    if [ "$component" = verz-app-helper ]; then component_identifier=com.verz.link.helper; fi
    codesign --force --sign "$VERZ_SIGN_IDENTITY" --identifier "$component_identifier" "$OUTPUT/$component"
done
for arch in arm64 x86_64; do
    xcrun swiftc -swift-version 5 -O -target "$arch-apple-macos14.0" HelperService/main.swift -o "$OUTPUT/verz-session-service-$arch"
done
lipo -create "$OUTPUT/verz-session-service-arm64" "$OUTPUT/verz-session-service-x86_64" -output "$OUTPUT/verz-session-service"
codesign --force --sign "$VERZ_SIGN_IDENTITY" --identifier com.omaralabed.verzlink.classic.session-service "$OUTPUT/verz-session-service"
if [ -n "${TARGET_BUILD_DIR:-}" ] && [ -n "${CONTENTS_FOLDER_PATH:-}" ]; then
    mkdir -p "$TARGET_BUILD_DIR/$CONTENTS_FOLDER_PATH/Library/LaunchDaemons"
    install -m 644 Resources/com.omaralabed.verzlink.classic.session-service.plist "$TARGET_BUILD_DIR/$CONTENTS_FOLDER_PATH/Library/LaunchDaemons/com.omaralabed.verzlink.classic.session-service.plist"
fi
if [ -f "Resources/AppIcon.icns" ]; then
    cp "Resources/AppIcon.icns" "$OUTPUT/AppIcon.icns"
else
    swift scripts/GenerateIcon.swift .build/AppIcon.iconset
    iconutil -c icns .build/AppIcon.iconset -o "$OUTPUT/AppIcon.icns"
fi
