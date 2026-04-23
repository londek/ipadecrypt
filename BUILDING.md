# Building ipadecrypt

ipadecrypt has two parts:

- **`ipadecrypt` CLI** - Go binary that runs on your computer.
- **Helper** - a small arm64 iOS binary (`ipadecrypt-helper-arm64`) that runs on the jailbroken device. Consumed by the CLI using `go:embed`.

For regular development you only need the CLI; the prebuilt helper is committed at `internal/device/ipadecrypt-helper-arm64`. Rebuilding the helper requires Docker.

## Prerequisites

### CLI only (cross-platform)

- Go 1.25+

### Helper

The helper is built inside a prebuilt Docker image published at `ghcr.io/londek/ipadecrypt-toolchain:latest` (~750 MB). The image is defined by [`helper/Dockerfile`](helper/Dockerfile) and pushed by the `toolchain` job in [`.github/workflows/ci.yml`](.github/workflows/ci.yml) on every CI run - tagged by the Dockerfile's hash, plus `:latest` on `main`.

What's inside:

- `clang` + `lld` (from [apt.llvm.org](https://apt.llvm.org))
- [`ldid`](https://github.com/ProcursusTeam/ldid) (Procursus fork) for ad-hoc iOS code signing
- iPhoneOS SDK from [`xybp888/iOS-SDKs`](https://github.com/xybp888/iOS-SDKs), trimmed to what this project needs

The image is version-pinned via `ARG`s at the top of the Dockerfile (`LLVM_VERSION`, `LDID_REV`, `SDKS_COMMIT`, `SDK_VERSION`, `IOS_DEPLOYMENT_TARGET`). Because the build always runs on `linux/amd64` - via Rosetta / QEMU on Apple Silicon, natively on Linux - the compiler binary is the same bytes everywhere, and so is its output. That's what makes the drift check meaningful.

## Build the CLI

```sh
go build -o ipadecrypt ./cmd/ipadecrypt
```

For an optimized release-style build:

```sh
go build -trimpath -ldflags="-s -w" -o ipadecrypt ./cmd/ipadecrypt
```

This reuses `internal/device/ipadecrypt-helper-arm64` from the repo - no iOS toolchain needed.

## Build the helper

Only needed when you change `helper/helper.c` or `helper/entitlements.plist`.

```sh
./helper/build.sh
```

Produces `helper/dist/ipadecrypt-helper-arm64`. Copy it into place for `go:embed`:

```sh
cp helper/dist/ipadecrypt-helper-arm64 internal/device/ipadecrypt-helper-arm64
```

## The drift check

CI (see [`.github/workflows/ci.yml`](.github/workflows/ci.yml)) runs the exact same `./helper/build.sh` - same Dockerfile, same pinned toolchain, same container - and byte-compares the fresh output against the committed `internal/device/ipadecrypt-helper-arm64`. If they don't match, the PR fails with `ipadecrypt-helper-arm64 drift detected`.

In practice this means: **if you touch `helper.c` or `entitlements.plist`, rebuild and commit the new `internal/device/ipadecrypt-helper-arm64` in the same PR**. If you don't, CI catches it.

The drift is meaningful because the canonical build environment is reproducible, not because we got lucky - the whole point of the container is that there's no difference between your build and CI's.