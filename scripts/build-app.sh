#!/bin/bash
set -euo pipefail
PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_DIR"
DERIVED_DATA="${VERZ_DERIVED_DATA:-$HOME/Library/Developer/Xcode/DerivedData/VERZLink-Local}"
xcodebuild -project "VERZ Link.xcodeproj" -scheme "VERZ Link" -configuration Release \
    -derivedDataPath "$DERIVED_DATA" -destination 'generic/platform=macOS' -quiet build
APP="$PROJECT_DIR/dist/VERZ Link.app"
mkdir -p "$PROJECT_DIR/dist"
ditto --norsrc "$DERIVED_DATA/Build/Products/Release/VERZ Link.app" "$APP"
# Remove only generated bundle metadata that prevents code signing.
xattr -dr com.apple.FinderInfo "$APP" 2>/dev/null || true
xattr -dr com.apple.ResourceFork "$APP" 2>/dev/null || true
codesign --force --sign - "$APP"
codesign --verify --deep --strict --verbose=2 "$APP"
lipo -archs "$APP/Contents/MacOS/VERZLink"
ditto -c -k --sequesterRsrc --keepParent "$APP" "$PROJECT_DIR/dist/VERZ Link Mac Universal.zip"
echo "Built: $APP"
