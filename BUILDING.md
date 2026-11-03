# Building ipadecrypt

ipadecrypt has three parts:

- **`ipadecrypt` CLI** - Go binary that runs on your computer. This is all you
  need for everyday development and for decrypting apps.
- **Device mint bundle** - three small signed arm64 iOS programs
  (`credential.ios`, `driver.ios`, `trigger.ios`) plus two data blobs, embedded
  into the CLI with `go:embed` and pushed to a jailbroken device only during the
  one-time `bootstrap` credential mint.
- **On-device decrypt helper** - a signed arm64 iOS program
  (`internal/device/ipadecrypt-helper-arm64`, `go:embed`ed from the C sources in
  `helper/`). Pushed to a jailbroken device only for the on-device fallback that
  decrypts old apps still shipping a 32-bit slice, which the arm64-only offline
  decryptor can't handle.

## Prerequisites

### CLI (cross-platform)

- Go 1.25+

That's it. The mint bundle lives under `internal/credmint/bundle/` - data blobs
and the three signed `*.ios` programs are committed and embedded via `go:embed`,
so a plain build is fully mint-capable. (If the `*.ios` files are ever stripped
to the placeholder marker, the CLI still decrypts but `credmint.Mint` returns
`ErrBinariesUnavailable`.)

The App Store engine (`internal/apphttp`, `internal/store`, `internal/sap`) is a
vendored port of [ipatool](https://github.com/majd/ipatool); it emulates Apple's
AppleMediaServices framework to attest download requests. No build step is
needed, but the **first** App Store action at runtime downloads and caches the
Apple frameworks it emulates (~tens of MB, range-extracted from a pinned macOS
image) under `~/.cache/ipadecrypt/`. The build stays pure Go (`CGO_ENABLED=0`
cross-compiles for all release targets).

## Build the CLI

```sh
go build -o ipadecrypt ./cmd/ipadecrypt
```

For an optimized release-style build:

```sh
go build -trimpath -ldflags="-s -w" -o ipadecrypt ./cmd/ipadecrypt
```

## Rebuild the device mint bundle

Only needed when the device programs change. They build on **Linux or macOS via
Docker** (no Xcode) in a pinned toolchain image - `clang` targeting
`arm64-apple-ios`, an iPhoneOS SDK, and `ldid` for ad-hoc signing - the same
approach the old on-device helper used. Sources come from the upstream
[fairplay-decrypt](https://github.com/EthanArbuckle/fairplay-decrypt)
`credential-retrieval/` tree, which is not vendored here.

```sh
# clone fairplay-decrypt at the pinned commit and build the image from scratch:
IPADECRYPT_CREDMINT_IMAGE=build ./internal/credmint/toolchain/build.sh

# or point at a local checkout (uses/pulls the published toolchain image):
./internal/credmint/toolchain/build.sh /path/to/fairplay-decrypt/credential-retrieval
```

This compiles the three `*.ios` programs, signs them, copies them and the data
blobs into `internal/credmint/bundle/`, and fails if any program is still a
placeholder. Commit the refreshed bundle. The build is byte-reproducible, and
the [`credmint bundle drift`](.github/workflows/credmint-bundle.yml) CI job
rebuilds from the pinned sources and byte-compares against the committed bundle.

## Rebuild the on-device decrypt helper

Only needed when the C sources under `helper/` change. Like the mint bundle it
builds on **Linux or macOS via Docker** (no Xcode) in a pinned toolchain image -
`clang` targeting `arm64-apple-ios`, an iPhoneOS SDK, and `ldid` for ad-hoc
signing with `helper/entitlements.plist`.

```sh
# uses/pulls the published toolchain image:
./helper/build.sh

# or build the toolchain image locally from helper/Dockerfile first:
IPADECRYPT_TOOLCHAIN_IMAGE=build ./helper/build.sh
```

This writes `helper/dist/ipadecrypt-helper-arm64`. Copy it over the embedded
copy and commit it:

```sh
cp helper/dist/ipadecrypt-helper-arm64 internal/device/ipadecrypt-helper-arm64
```

The committed binary matches the `helper/` sources, so a plain `go build` is
fully decrypt-capable without this step.
