#!/bin/sh
# Build ipadecrypt-helper-arm64 inside the pinned Docker toolchain to ensure
# consistent build across platforms.
# To build the toolchain locally set IPADECRYPT_TOOLCHAIN_IMAGE=build.

set -e
cd "$(dirname "$0")/.."

if ! command -v docker >/dev/null 2>&1; then
    echo "docker is required" >&2
    exit 1
fi

IMAGE="${IPADECRYPT_TOOLCHAIN_IMAGE:-ghcr.io/londek/ipadecrypt-toolchain:latest}"

if [ "$IMAGE" = "build" ]; then
    IMAGE="ipadecrypt-toolchain:local"
    echo "==> building toolchain locally from helper/Dockerfile"
    docker build \
        --load \
        --platform linux/amd64 \
        --provenance=false \
        --sbom=false \
        -t "$IMAGE" \
        helper/
elif docker image inspect --format '{{.Id}}' "$IMAGE" >/dev/null 2>&1; then
    echo "==> toolchain image already present locally ($IMAGE)"
else
    echo "==> pulling toolchain image ($IMAGE)"
    docker pull --platform linux/amd64 "$IMAGE"
fi

mkdir -p helper/dist

echo "==> compiling ipadecrypt-helper-arm64 in container"
docker run --rm \
    --platform linux/amd64 \
    -v "$PWD:/workspace" \
    -w /workspace \
    "$IMAGE" \
    /bin/sh -c '
        set -e
        clang \
            -target "arm64-apple-ios${IPHONEOS_DEPLOYMENT_TARGET}" \
            -isysroot "$IPHONEOS_SDK" \
            -isystem "$IPHONEOS_SDK/usr/include" \
            -L "$IPHONEOS_SDK/usr/lib" \
            -fuse-ld=lld \
            -Wl,-arch,arm64 \
            -Wl,-platform_version,ios,"$IPHONEOS_DEPLOYMENT_TARGET","$IPHONEOS_SDK_VERSION" \
            -Wno-incompatible-sysroot \
            -O2 -fno-stack-protector -Wno-deprecated-declarations \
            -no-canonical-prefixes \
            -o helper/dist/ipadecrypt-helper-arm64 helper/helper.c
        ldid -S"helper/entitlements.plist" helper/dist/ipadecrypt-helper-arm64
    '

echo "ok: helper/dist/ipadecrypt-helper-arm64"
