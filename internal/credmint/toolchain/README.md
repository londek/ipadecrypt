# credmint device toolchain

`internal/credmint/bundle/` holds the five files pushed to the jailbroken
device during one-time credential minting, embedded into the CLI via `go:embed`:

- `credential.ios`, `driver.ios`, `trigger.ios` — signed arm64 iOS programs
- `static-key-table.bin`, `core4-word-table.bin` — data blobs

All five are committed, so a plain `go build` is mint-capable.

## Rebuilding

The `*.ios` programs build on **Linux or macOS via Docker** - no Xcode. The
[`Dockerfile`](Dockerfile) pins a toolchain image (`clang` →
`arm64-apple-ios`, an iPhoneOS SDK with frameworks, and `ldid`), and
[`build.sh`](build.sh) compiles the programs from the upstream
`fairplay-decrypt/credential-retrieval` sources (cloned at a pinned commit),
signs them with their entitlements, and installs them into `../bundle/`.

```sh
# build the toolchain image locally and the bundle from pinned sources:
IPADECRYPT_CREDMINT_IMAGE=build ./build.sh

# or use a local fairplay-decrypt checkout:
./build.sh /path/to/fairplay-decrypt/credential-retrieval
```

The build is byte-reproducible; the `credmint bundle drift` CI workflow enforces
that the committed bundle matches its pinned sources.
