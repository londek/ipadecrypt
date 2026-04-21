# Building ipadecrypt

ipadecrypt has two parts:

- **`ipadecrypt` CLI** - Go binary that runs on your computer. Cross-platform (macOS / Linux / Windows).
- **Helper** - a small arm64 iOS binary (`helper.arm64`) that runs on the jailbroken device. Written in C, signed with custom entitlements. Consumed by the CLI using `go:embed`.

For regular development you only need the CLI. Rebuilding the helper requires macOS + Xcode.

## Prerequisites

### CLI only (cross-platform)

- Go 1.25+

### Helper (macOS only)

- Xcode or the Xcode Command Line Tools (`xcode-select --install`)
- `ldid` (`brew install ldid`)

## Build the CLI

```sh
go build -o ipadecrypt ./cmd/ipadecrypt
```

This reuses the `internal/device/helper.arm64` that's provided in the repo. You don't need an iOS toolchain to build the CLI.

For an optimized release-style build:

```sh
go build -trimpath -ldflags="-s -w" -o ipadecrypt ./cmd/ipadecrypt
```

Cross-compile for another OS/arch:

```sh
GOOS=linux GOARCH=arm64 go build -o ipadecrypt-linux-arm64 ./cmd/ipadecrypt
```

## Build the helper

Only needed when you change `helper/helper.c` or `helper/entitlements.plist`.

```sh
./helper/build.sh
```

That produces `helper/dist/helper.arm64`. Copy it into place so the Go build picks it up:

```sh
cp helper/dist/helper.arm64 internal/device/helper.arm64
```

Then rebuild the CLI.

The script uses `xcrun --sdk iphoneos` to find clang and the iPhoneOS SDK, compiles `helper.c` for `-arch arm64` with `-mios-version-min=14.0`, and signs with `ldid -Sentitlements.plist`. The entitlements give the helper `task_for_pid-allow` and `get-task-allow`, which is how it's able to grab the target's task port.