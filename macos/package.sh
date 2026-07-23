#!/bin/sh
set -eu

profile=${1:?usage: macos/package.sh PROFILE [OUTPUT.app]}
app=${2:-target/release/Hellas.app}
identity=${SIGN_IDENTITY:-}
contents="$app/Contents"
entitlements="$app.entitlements"
sdk=$(DEVELOPER_DIR=/Library/Developer/CommandLineTools /usr/bin/xcrun --sdk macosx --show-sdk-path)
linker=$(DEVELOPER_DIR=/Library/Developer/CommandLineTools /usr/bin/xcrun -f clang)

if [ -z "$identity" ]; then
    identity=$(security find-identity -v -p codesigning \
        | sed -n 's/.*"\(Developer ID Application:[^"]*\)".*/\1/p' \
        | head -n 1)
fi
test -n "$identity"
test ! -e "$app"
security cms -D -i "$profile" | plutil -extract Entitlements xml1 -o "$entitlements" -
for entitlement in \
    com.apple.security.get-task-allow \
    com.apple.security.cs.allow-jit \
    com.apple.security.cs.allow-dyld-environment-variables \
    com.apple.security.cs.disable-library-validation \
    com.apple.security.cs.allow-unsigned-executable-memory \
    com.apple.security.cs.disable-executable-page-protection \
    com.apple.security.cs.debugger
do
    if /usr/libexec/PlistBuddy -c "Print :$entitlement" "$entitlements" >/dev/null 2>&1; then
        echo "error: forbidden runtime-relaxation entitlement: $entitlement" >&2
        exit 1
    fi
done
test "$(/usr/libexec/PlistBuddy -c 'Print :com.apple.developer.devicecheck.app-attest-opt-in:0' "$entitlements")" = CDhash
application_id=$(/usr/libexec/PlistBuddy -c 'Print :com.apple.application-identifier' "$entitlements")
bundle_id=${application_id#*.}

MACOSX_DEPLOYMENT_TARGET=27.0 cargo rustc --release -p hellas-cli --features apple-app-attest,node,gateway,evaluate,candle-metal -- \
    -C linker="$linker" -C link-arg=-isysroot -C link-arg="$sdk"
mkdir -p "$contents/MacOS"
cp macos/Info.plist "$contents/Info.plist"
/usr/libexec/PlistBuddy -c "Set :CFBundleIdentifier $bundle_id" "$contents/Info.plist"
cp target/release/hellas-cli "$contents/MacOS/hellas"
cp "$profile" "$contents/embedded.provisionprofile"
codesign --force --options runtime --timestamp --entitlements "$entitlements" --sign "$identity" "$app"
codesign --verify --deep --strict --verbose=2 "$app"
codesign -d --entitlements :- "$app" 2>/dev/null
