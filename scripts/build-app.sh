#!/bin/bash
set -euo pipefail
PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_DIR"
DERIVED_DATA="${VERZ_DERIVED_DATA:-$HOME/Library/Developer/Xcode/DerivedData/VERZLink-Local}"
xcodebuild -project "VERZ Link.xcodeproj" -scheme "VERZ Link" -configuration Release \
    -derivedDataPath "$DERIVED_DATA" -destination 'generic/platform=macOS' -quiet build
APP="$DERIVED_DATA/Build/Products/Release/VERZ Link.app"
mkdir -p "$PROJECT_DIR/dist"
# Verify and archive the signed Xcode product outside iCloud Desktop. File
# Provider can re-add FinderInfo to a Desktop .app immediately after removal.
codesign --verify --deep --strict --verbose=2 "$APP"
swift scripts/verify-udp-signing.swift "$APP"
lipo -archs "$APP/Contents/MacOS/VERZLink"
ditto -c -k --sequesterRsrc --keepParent "$APP" "$PROJECT_DIR/dist/VERZ Link Mac Universal.zip"
DIST_APP="$PROJECT_DIR/dist/VERZ Link.app"
if [ -d "$DIST_APP" ]; then
    PREVIOUS_APP_DIR=$(mktemp -d "$PROJECT_DIR/dist/previous-build.XXXXXX")
    mv "$DIST_APP" "$PREVIOUS_APP_DIR/VERZ Link.app"
fi
ditto --norsrc "$APP" "$DIST_APP"
echo "Built: $APP"
