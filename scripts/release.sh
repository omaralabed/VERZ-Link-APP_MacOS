#!/bin/bash
# Produces a Developer ID signed, notarized and stapled VERZ Link.app for
# customers, as dist/release-<stamp>/VERZ-Link-<build>.zip.
#
# One-time prerequisites (Apple Developer account holder for team H7728UD4B3):
#   1. A "Developer ID Application" certificate in the login keychain
#      (Xcode > Settings > Accounts > Manage Certificates > + > Developer ID Application).
#   2. The Network Extension entitlement approved for Developer ID distribution
#      (developer.apple.com > Contact Us > Network Extension Entitlement Request;
#      macOS, App Proxy Provider). Without it the export fails on the entitlement.
#   3. Notarization credentials stored once in the keychain:
#        xcrun notarytool store-credentials verz-notary \
#            --key AuthKey_XXXX.p8 --key-id XXXX --issuer <issuer id>
#      (App Store Connect > Users and Access > Integrations > Team Keys, role Developer.)
set -euo pipefail
PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_DIR"
PROFILE="${VERZ_NOTARY_PROFILE:-verz-notary}"
DERIVED_DATA="${VERZ_DERIVED_DATA:-$HOME/Library/Developer/Xcode/DerivedData/VERZLink-Release}"
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
OUT="$PROJECT_DIR/dist/release-$STAMP"
ARCHIVE="$OUT/VERZ Link.xcarchive"
mkdir -p "$OUT"

if ! security find-identity -v -p codesigning | grep -q "Developer ID Application"; then
    echo "No Developer ID Application certificate in the keychain; see the prerequisites at the top of this script." >&2
    exit 1
fi

# VERZ_RELEASE=1 makes build-native.sh timestamp the native executables.
export VERZ_RELEASE=1
xcodebuild -project "VERZ Link.xcodeproj" -scheme "VERZ Link" -configuration Release \
    -derivedDataPath "$DERIVED_DATA" -destination 'generic/platform=macOS' \
    -archivePath "$ARCHIVE" -quiet archive
xcodebuild -exportArchive -archivePath "$ARCHIVE" \
    -exportOptionsPlist scripts/ExportOptions.plist -exportPath "$OUT/export" -quiet
APP="$OUT/export/VERZ Link.app"
VERSION=$(/usr/libexec/PlistBuddy -c "Print CFBundleVersion" "$APP/Contents/Info.plist")

codesign --verify --deep --strict --verbose=2 "$APP"
swift scripts/verify-udp-signing.swift "$APP"
for executable in "$APP/Contents/MacOS/VERZLink" "$APP/Contents/Resources/verz-bond" \
    "$APP/Contents/Resources/verz-app-helper" "$APP/Contents/Resources/verz-session-service"; do
    codesign -d --verbose=2 "$executable" 2>&1 | grep -q "flags=.*runtime" \
        || { echo "Hardened runtime missing on $executable" >&2; exit 1; }
done

ZIP="$OUT/VERZ-Link-$VERSION.zip"
ditto -c -k --sequesterRsrc --keepParent "$APP" "$ZIP"
xcrun notarytool submit "$ZIP" --keychain-profile "$PROFILE" --wait
xcrun stapler staple "$APP"
rm -f "$ZIP"
ditto -c -k --sequesterRsrc --keepParent "$APP" "$ZIP"
spctl --assess --type execute --verbose=2 "$APP"
echo "Notarized build $VERSION: $ZIP"
