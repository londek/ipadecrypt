#!/bin/sh
# Build the signed arm64 iOS credential-mint programs inside the pinned Docker
# toolchain and drop them (plus the data blobs) into internal/credmint/bundle/,
# replacing the committed placeholders. Reproducible on any Linux/macOS host
# with Docker - no Xcode or macOS SDK required.
#
# Usage:
#   build.sh [path-to-fairplay-decrypt/credential-retrieval]
#
# With no argument the fairplay-decrypt sources are cloned at a pinned commit.
# Set IPADECRYPT_CREDMINT_IMAGE=build to build the toolchain image locally.

set -e

here="$(cd "$(dirname "$0")" && pwd)"
bundle_dst="$here/../bundle"

FP_REPO="https://github.com/EthanArbuckle/fairplay-decrypt"
FP_COMMIT="7f80db2ef37634073fab06b3aad1aa0cf24561a1"

if ! command -v docker >/dev/null 2>&1; then
    echo "docker is required" >&2
    exit 1
fi

# --- resolve the credential-retrieval source tree -------------------------
cleanup=""
if [ -n "$1" ]; then
    src="$1"
else
    tmp="$(mktemp -d)"
    cleanup="$tmp"
    echo "==> cloning fairplay-decrypt @ $FP_COMMIT"
    git clone --quiet "$FP_REPO" "$tmp/fp"
    git -C "$tmp/fp" checkout --quiet "$FP_COMMIT"
    src="$tmp/fp/credential-retrieval"
fi

if [ ! -f "$src/Makefile" ]; then
    echo "credential-retrieval sources not found at: $src" >&2
    [ -n "$cleanup" ] && rm -rf "$cleanup"
    exit 1
fi

# --- toolchain image ------------------------------------------------------
IMAGE="${IPADECRYPT_CREDMINT_IMAGE:-ghcr.io/londek/ipadecrypt-credmint-toolchain:latest}"
if [ "$IMAGE" = "build" ]; then
    IMAGE="ipadecrypt-credmint-toolchain:local"
    echo "==> building toolchain image from Dockerfile"
    docker build --load --platform linux/amd64 --provenance=false --sbom=false \
        -t "$IMAGE" "$here"
elif docker image inspect --format '{{.Id}}' "$IMAGE" >/dev/null 2>&1; then
    echo "==> toolchain image present locally ($IMAGE)"
else
    echo "==> pulling toolchain image ($IMAGE)"
    docker pull --platform linux/amd64 "$IMAGE"
fi

# --- compile + sign in the container --------------------------------------
echo "==> compiling credential.ios / driver.ios / trigger.ios"
docker run --rm --platform linux/amd64 \
    -v "$src:/src:ro" -v "$bundle_dst:/out" \
    "$IMAGE" /bin/sh -c '
        set -e
        common="-target arm64-apple-ios${IPHONEOS_DEPLOYMENT_TARGET} \
            -isysroot ${IPHONEOS_SDK} -fuse-ld=lld -Wl,-arch,arm64 \
            -Wl,-platform_version,ios,${IPHONEOS_DEPLOYMENT_TARGET},${IPHONEOS_SDK_VERSION} \
            -Wno-incompatible-sysroot -Wno-deprecated-declarations -no-canonical-prefixes -O2"
        cstd="-std=c11 -fwrapv -fno-strict-aliasing -Wno-bitwise-op-parentheses -Wno-shift-op-parentheses"

        # shellcheck disable=SC2086
        clang $common $cstd \
            /src/credential/credential.c /src/credential/observer.c \
            /src/credential/finalizer.c /src/credential/selector_native.c \
            /src/credential/core4_native.c /src/credential/core4_digest.c \
            /src/credential/core4_aes.c /src/credential/core4_finish.c \
            /src/credential/core4_contexts.c \
            -framework CoreFoundation -framework IOKit \
            -o /out/credential.ios
        ldid -S/src/credential/credential.entitlements.plist /out/credential.ios

        # shellcheck disable=SC2086
        clang $common /src/driver/driver.c -framework IOKit -o /out/driver.ios
        ldid -S/src/driver/driver.entitlements.plist /out/driver.ios

        # shellcheck disable=SC2086
        clang $common -std=c11 /src/trigger/trigger.c -o /out/trigger.ios
        ldid -S/src/trigger/trigger.entitlements.plist /out/trigger.ios

        cp /src/credential/static-key-table.bin /out/static-key-table.bin
        cp /src/credential/core4-word-table.bin /out/core4-word-table.bin
    '

[ -n "$cleanup" ] && rm -rf "$cleanup"

# --- sanity: no placeholders left -----------------------------------------
for f in credential.ios driver.ios trigger.ios; do
    if head -c 31 "$bundle_dst/$f" | grep -q 'IPADECRYPT_CREDMINT_PLACEHOLDER'; then
        echo "error: $f is still a placeholder after build" >&2
        exit 1
    fi
done

echo "ok: device bundle refreshed in $bundle_dst"
