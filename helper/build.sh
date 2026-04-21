#!/bin/sh
set -e
cd "$(dirname "$0")"

if ! command -v ldid >/dev/null 2>&1; then
    echo "ldid not found. Install via: brew install ldid" >&2
    exit 1
fi

SDK="$(xcrun --sdk iphoneos --show-sdk-path)"
CC="$(xcrun --sdk iphoneos -f clang)"

mkdir -p dist

echo "==> compiling helper.arm64"
"$CC" -arch arm64 -isysroot "$SDK" \
    -mios-version-min=14.0 \
    -O2 -fno-stack-protector -Wno-deprecated-declarations \
    -o dist/helper.arm64 helper.c

echo "==> signing helper.arm64"
ldid -Sentitlements.plist dist/helper.arm64

echo "ok: dist/helper.arm64"
