package credmint

import (
	"bytes"
	_ "embed"
	"errors"
)

//go:embed bundle/credential.ios
var credentialBinary []byte

//go:embed bundle/driver.ios
var driverBinary []byte

//go:embed bundle/trigger.ios
var triggerBinary []byte

//go:embed bundle/static-key-table.bin
var staticKeyTable []byte

//go:embed bundle/core4-word-table.bin
var core4WordTable []byte

// placeholderMarker tags device-binary stubs. The real signed arm64 iOS
// programs are committed and reproducibly rebuilt in CI (see
// internal/credmint/toolchain); this guard is a safety net for a tree where
// they were stripped or never built.
var placeholderMarker = []byte("IPADECRYPT_CREDMINT_PLACEHOLDER")

// ErrBinariesUnavailable reports that this build was compiled without the
// signed device binaries, so credential minting is not possible here.
var ErrBinariesUnavailable = errors.New("credential-mint device binaries are not built into this binary; use an official release")

type bundleFile struct {
	name       string
	data       []byte
	executable bool
}

// bundleFiles returns the five files pushed to the device, in the order
// retrieve.py uploads them, or ErrBinariesUnavailable when the device
// binaries are still placeholders.
func bundleFiles() ([]bundleFile, error) {
	for _, b := range [][]byte{credentialBinary, driverBinary, triggerBinary} {
		if bytes.HasPrefix(b, placeholderMarker) {
			return nil, ErrBinariesUnavailable
		}
	}

	return []bundleFile{
		{name: "credential.ios", data: credentialBinary, executable: true},
		{name: "driver.ios", data: driverBinary, executable: true},
		{name: "trigger.ios", data: triggerBinary, executable: true},
		{name: "static-key-table.bin", data: staticKeyTable},
		{name: "core4-word-table.bin", data: core4WordTable},
	}, nil
}
