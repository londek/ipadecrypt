<div align="center">

<img height="50px" src="https://readme-typing-svg.herokuapp.com?font=Inter&weight=700&size=36&color=FFFFFF&center=true&vCenter=true&width=300&lines=ipadecrypt&repeat=false&duration=2500" alt="ipadecrypt">

**End-to-end FairPlay decrypter for App Store apps.**
*Give it a bundle ID, get a decrypted `.ipa`. And yes - it happily decrypts iOS 26 apps.*

[![Go Version](https://img.shields.io/badge/Go-1.25%2B-00ADD8?style=flat-square&logo=go)](https://golang.org/)
[![macOS](https://img.shields.io/badge/macOS-000?style=flat-square&logo=apple&logoColor=white)](#install)
[![Linux](https://img.shields.io/badge/Linux-000?style=flat-square&logo=linux&logoColor=white)](#install)
[![Windows](https://img.shields.io/badge/Windows-000?style=flat-square&logo=data:image/svg%2Bxml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCI+PHBhdGggZmlsbD0id2hpdGUiIGQ9Ik0wIDBoMTF2MTFIMHpNMTMgMGgxMXYxMUgxM3pNMCAxM2gxMXYxMUgwek0xMyAxM2gxMXYxMUgxM3oiLz48L3N2Zz4=)](#install)
[![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)](#license)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen?style=flat-square)](https://github.com/londek/ipadecrypt/pulls)

<img width="90%" src="https://github.com/user-attachments/assets/ba8dbd32-a2fb-49cc-afee-3aa88050718e" />

</div>

## How it works

ipadecrypt decrypts FairPlay apps **on your computer** - no device in the loop
for day-to-day use. A jailbroken device is needed exactly **once per Apple
account**, during `bootstrap`, to mint a reusable 16-byte account credential.
After that, downloading and decrypting any app for that account is fully
offline.

The offline decryptor handles **arm64** slices (everything the modern App Store
ships). A few old builds still ship a **32-bit (armv7) slice** - those can't be
decrypted offline, so ipadecrypt automatically falls back to decrypting them
**on your jailbroken device** when one is configured (the same device used for
minting). Pass `--no-on-device` to disable the fallback, or `--on-device` to go
straight to the device.

## Requirements

### On your computer
- Nothing special for everyday (arm64) decrypting. A jailbroken iPhone reachable
  over the network (or over USB with `iproxy`) is needed for the one-time mint,
  and again only for the on-device fallback on old 32-bit apps.

### On the jailbroken iPhone
| Requirement | Purpose |
|---|---|
| **OpenSSH with root access** | The mint and the on-device fallback connect over root SSH (install OpenSSH from Sileo) |
| **≥1 owned App Store app installed** | Bought with the same Apple ID; used to trigger FairPlay once during the mint |
| **AppSync Unified + `appinst`** | Only for the on-device fallback: installs the app on the device so it can be decrypted |

> Tested on iOS 16.7.11 with palera1n rootless and Dopamine on iPhone 8 Plus. iOS 10+ is expected to work for minting; decryption itself runs anywhere.

## Install

Download a prebuilt binary from the [releases page](https://github.com/londek/ipadecrypt/releases/latest).

Using go install:

```sh
go install github.com/londek/ipadecrypt/cmd/ipadecrypt@latest
```

From source (refer to [BUILDING.md](BUILDING.md) for detailed instructions):

```sh
git clone https://github.com/londek/ipadecrypt
cd ipadecrypt
go build ./cmd/ipadecrypt
```

## Usage

### First-time setup

```sh
ipadecrypt bootstrap
```

A three-step interactive wizard:

1. **App Store sign-in** - Logs into the App Store. Credentials stay local in `~/.ipadecrypt/config.json`. The first sign-in downloads and caches the Apple frameworks the App Store engine emulates (~tens of MB, range-extracted from a pinned macOS image) under `~/.cache/ipadecrypt/`; later runs reuse the cache.
2. **Credential mint** - Connects once to your jailbroken device over root SSH and extracts the reusable account credential, cached under `~/.ipadecrypt/credentials/`.
3. **On-device fallback check** - Verifies the device is ready to decrypt old apps that still ship a 32-bit slice (AppSync Unified + `appinst` present, helper uploads and execs). Best-effort: a missing prerequisite only disables that fallback and is reported, not fatal.

Run it again anytime; it skips minting if a credential is already cached (pass
`--remint` to force). After bootstrap, decrypting modern (arm64) apps is fully
offline - the device is only needed again for the on-device fallback on old
32-bit apps.

### Decrypt an app

```sh
ipadecrypt decrypt <bundle-id|app-store-id|app-store-url|path-to-local-ipa>
```

This decrypts offline. If the app ships a 32-bit slice the offline path can't
handle and a jailbroken device is configured, ipadecrypt automatically falls
back to decrypting it on the device. Useful flags:

- `--on-device` - skip the offline attempt and decrypt on the device directly.
- `--no-on-device` - never touch the device; fail if offline can't fully decrypt.
- `--patch-device-type` - expand `UIDeviceFamily` so an app built for a different device type still installs during the on-device fallback.
- `--no-uninstall` / `--force-uninstall` - control whether the app is removed from the device after an on-device decrypt (default: removed only if this run installed it).

### List versions of an app

```sh
ipadecrypt versions <bundle-id|app-store-id|app-store-url>
```

## Known issues

- Only the supported SINF/SUPF license formats decrypt offline; apps shipping a newer, unsupported `SC_Info` format fall back to the on-device path when a device is configured.
- The credential is per Apple account: decrypting an app requires signing in with (and having minted from) the account that owns it.
- Old builds that still ship a 32-bit (armv7) slice can't be decrypted offline (the offline decryptor is arm64-only) - they need the on-device fallback, so a jailbroken device must be configured.
- Minting is known to fail on **iOS 12.5.7 / A8** (e.g. iPhone 6) with `IOKit function is not mapped at the same address in fairplayd`. This is in the upstream [fairplay-decrypt](https://github.com/EthanArbuckle/fairplay-decrypt) device code and is tracked upstream.

## License

MIT.

## Prior art

- [EthanArbuckle/fairplay-decrypt](https://github.com/EthanArbuckle/fairplay-decrypt) - the offline FairPlay decryptor and credential-minting approach this release is a Go port of.
- [majd/ipatool](https://github.com/majd/ipatool) - the Apple Configurator impersonation the App Store client is based on.
- [34306/TrollDecryptJB](https://github.com/34306/TrollDecryptJB) - `task_for_pid` + `mach_vm_read` from a suspended spawn, entitlement set.
- [JohnCoates/flexdecrypt](https://github.com/JohnCoates/flexdecrypt) - the pre-iOS-16 approach that stopped working and prompted the pivot.

## AI Disclaimer

This project was developed with the assistance of AI tools. While I can't guarantee the accuracy of all AI-generated content, I have overviewed creation process and then reviewed, tested the code to ensure it meets the project's requirements.

<a href="https://star-history.dera.page/#londek/ipadecrypt&type=date&legend=top-left">
 <picture>
   <source media="(prefers-color-scheme: dark)" srcset="https://star-history.dera.page/svg?repos=londek/ipadecrypt&type=date&theme=dark&legend=top-left" />
   <source media="(prefers-color-scheme: light)" srcset="https://star-history.dera.page/svg?repos=londek/ipadecrypt&type=date&legend=top-left" />
   <img alt="Star History Chart" src="https://star-history.dera.page/svg?repos=londek/ipadecrypt&type=date&legend=top-left" />
 </picture>
</a>
