#!/usr/bin/env bash
set -euo pipefail

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
bundle_root="${VEXA_MAC_BUNDLE_DIR:-$project_root/target/Vexa.app}"
binary="$project_root/target/release/vexa-mac"

cargo build --manifest-path "$project_root/Cargo.toml" --release
rm -rf "$bundle_root"
mkdir -p "$bundle_root/Contents/MacOS"
cp "$binary" "$bundle_root/Contents/MacOS/Vexa"

cat > "$bundle_root/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleExecutable</key>
  <string>Vexa</string>
  <key>CFBundleIdentifier</key>
  <string>ai.vexa.local</string>
  <key>CFBundleName</key>
  <string>Vexa</string>
  <key>CFBundlePackageType</key>
  <string>APPL</string>
  <key>CFBundleShortVersionString</key>
  <string>0.1.0</string>
</dict>
</plist>
PLIST

echo "Created $bundle_root"
