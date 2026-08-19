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

## Requirements

### On your computer
- Jailbroken iPhone reachable over the network

### On the jailbroken iPhone
All installable through Sileo:

| Package | Purpose |
|---|---|
| **OpenSSH** | SSH server - ipadecrypt drives the device over SSH |
| **AppSync Unified** | Bypasses installd's signature check (add repo `https://lukezgd.github.io/repo`) |
| **appinst** | Installs modified IPAs on the device (add repo `https://lukezgd.github.io/repo`) |

> Tested on iOS 16.7.11 with palera1n rootless and Dopamine on iPhone 8 Plus. iOS 14 through 17 on A10–A14 devices are expected to work.

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

A four-step interactive wizard:

1. **App Store sign-in** - Logs into App Store. Credentials stay local in `~/.ipadecrypt/config.json`.
2. **Device connect** - SSH host / user / password; probes iOS version + arch.
3. **Prerequisites** - verifies whether deps are installed.
4. **Helper install** - uploads helper binary and verifies whether it runs.

### Decrypt an app

```sh
ipadecrypt decrypt <bundle-id|app-store-id|app-store-url|path-to-local-ipa>
```

### List versions of an app

```sh
ipadecrypt versions <bundle-id|app-store-id|app-store-url>
```

## Known issues

- [New, unsupported SC_Info format is shipped with some apps, ipadecrypt will fail to decrypt them.](https://github.com/londek/ipadecrypt/issues/34)
- Due to arm64e PPL guards on A12+, some apps such as Apple's are not expected to work.

## License

MIT.

## Prior art

- [majd/ipatool](https://github.com/majd/ipatool) - the Apple Configurator impersonation the App Store client is based on.
- [34306/TrollDecryptJB](https://github.com/34306/TrollDecryptJB) - `task_for_pid` + `mach_vm_read` from a suspended spawn, entitlement set.
- [akemin-dayo/AppSync](https://github.com/akemin-dayo/AppSync) - installd signature-bypass tweak + `appinst`.
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
