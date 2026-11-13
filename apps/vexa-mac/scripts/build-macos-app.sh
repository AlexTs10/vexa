#!/usr/bin/env bash
set -euo pipefail

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
bundle_root="${VEXA_MAC_BUNDLE_DIR:-$project_root/target/Vexa.app}"
binary="$project_root/target/release/vexa-mac"
daemon_project_root="$project_root/../vexa-daemon"
daemon_binary="$daemon_project_root/target/release/vexa-daemon"
stt_project_root="$project_root/../vexa-stt"
stt_binary="$stt_project_root/target/release/vexa-stt"

cargo build --manifest-path "$project_root/Cargo.toml" --release
cargo build --manifest-path "$daemon_project_root/Cargo.toml" --release
cargo build --manifest-path "$stt_project_root/Cargo.toml" --release
rm -rf "$bundle_root"
mkdir -p "$bundle_root/Contents/MacOS"
cp "$binary" "$bundle_root/Contents/MacOS/Vexa"
cp "$daemon_binary" "$bundle_root/Contents/MacOS/vexa-daemon"
cp "$stt_binary" "$bundle_root/Contents/MacOS/vexa-stt"

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
