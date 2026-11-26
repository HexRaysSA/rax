#!/bin/bash
set -euo pipefail

scratch=${1:?an output directory is required}
source="$(cd "$(dirname "$0")" && pwd -P)/src/closed_xpc_service.c"
app="$scratch/GuestEcho.app/Contents"
service="$app/XPCServices/Worker.xpc/Contents"
mkdir -p "$scratch/tmp" "$app/MacOS" "$service/MacOS"
export TMPDIR="$scratch/tmp" TMP="$scratch/tmp" TEMP="$scratch/tmp"

cat >"$app/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
    <key>CFBundleExecutable</key><string>GuestEcho</string>
    <key>CFBundleIdentifier</key><string>org.rax.validation.GuestEchoApp</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>CFBundleVersion</key><string>1</string>
</dict></plist>
PLIST
cat >"$service/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
    <key>CFBundleExecutable</key><string>GuestService</string>
    <key>CFBundleIdentifier</key><string>org.rax.validation.GuestEcho</string>
    <key>CFBundlePackageType</key><string>XPC!</string>
    <key>CFBundleVersion</key><string>1</string>
    <key>XPCService</key><dict>
        <key>ServiceType</key><string>Application</string>
        <key>EnvironmentVariables</key><dict>
            <key>RAX_XPC_FIXTURE_VALUE</key><string>supplied by service manifest</string>
        </dict>
    </dict>
</dict></plist>
PLIST
/usr/bin/plutil -convert binary1 "$service/Info.plist"

sdk=$(xcrun --sdk macosx --show-sdk-path)
flags=(-isysroot "$sdk" -O2 -Wall -Wextra -Werror -arch arm64 -arch x86_64 -fblocks)
xcrun --sdk macosx clang "${flags[@]}" -DRAX_XPC_SERVICE=0 "$source" -o "$app/MacOS/GuestEcho"
xcrun --sdk macosx clang "${flags[@]}" -DRAX_XPC_SERVICE=1 "$source" -o "$service/MacOS/GuestService"
/usr/bin/codesign --sign - --force "$app/XPCServices/Worker.xpc"
/usr/bin/codesign --sign - --force "$scratch/GuestEcho.app"
/usr/bin/codesign --verify --deep --strict "$scratch/GuestEcho.app"
