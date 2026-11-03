package credmint

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

const maxSinfBytes = 1 << 20

var udidRe = regexp.MustCompile(`^(?:[0-9a-f]{40}|[0-9a-f]{8}-[0-9a-f]{16})$`)

type sinfAtom struct {
	tag        string
	start, end int
}

// sinfChildren parses the atoms in data[start:end]. Mirrors retrieve.py children.
func sinfChildren(data []byte, start, end int) ([]sinfAtom, error) {
	var out []sinfAtom

	at := start
	for at < end {
		if at+8 > end {
			return nil, errors.New("truncated SINF atom")
		}

		size := int(binary.BigEndian.Uint32(data[at : at+4]))
		if size < 8 || at+size > end {
			return nil, errors.New("invalid SINF atom size")
		}

		out = append(out, sinfAtom{tag: string(data[at+4 : at+8]), start: at + 8, end: at + size})
		at += size
	}

	return out, nil
}

// sinfField returns the bytes of the one schi field tagged tag. Mirrors
// retrieve.py sinf_field.
func sinfField(sinf []byte, tag string) ([]byte, error) {
	root, err := sinfChildren(sinf, 0, len(sinf))
	if err != nil {
		return nil, err
	}

	if len(root) != 1 || root[0].tag != "sinf" {
		return nil, errors.New("expected one complete SINF atom")
	}

	inner, err := sinfChildren(sinf, root[0].start, root[0].end)
	if err != nil {
		return nil, err
	}

	var schi *sinfAtom

	for i := range inner {
		if inner[i].tag == "schi" {
			if schi != nil {
				return nil, errors.New("expected one SINF schi container")
			}

			schi = &inner[i]
		}
	}

	if schi == nil {
		return nil, errors.New("expected one SINF schi container")
	}

	fields, err := sinfChildren(sinf, schi.start, schi.end)
	if err != nil {
		return nil, err
	}

	var match *sinfAtom

	for i := range fields {
		if fields[i].tag == tag {
			if match != nil {
				return nil, fmt.Errorf("expected one SINF %q field", tag)
			}

			match = &fields[i]
		}
	}

	if match == nil {
		return nil, fmt.Errorf("expected one SINF %q field", tag)
	}

	return sinf[match.start:match.end], nil
}

// supportedSinf reports whether sinf is a license format the retriever
// handles. Mirrors retrieve.py supported_sinf.
func supportedSinf(sinf []byte) bool {
	priv, err := sinfField(sinf, "priv")
	if err != nil {
		return false
	}

	if _, err := sinfField(sinf, "name"); err != nil {
		return false
	}

	user, err := sinfField(sinf, "user")
	if err != nil {
		return false
	}

	key, err := sinfField(sinf, "key ")
	if err != nil {
		return false
	}

	iviv, err := sinfField(sinf, "iviv")
	if err != nil {
		return false
	}

	privOK := len(priv) == 448 || (len(priv) == 440 && allZero(priv[len(priv)-8:]))

	return len(user) == 4 && len(key) == 4 && len(iviv) == 16 && privOK
}

// validLicense checks that sinf is one complete, supported SINF atom, as
// retrieve.py license_sinf does before use.
func validLicense(sinf []byte) error {
	if len(sinf) > maxSinfBytes {
		return errors.New("SINF is too large")
	}

	if _, err := sinfChildren(sinf, 0, len(sinf)); err != nil {
		return err
	}

	if len(sinf) < 8 || string(sinf[4:8]) != "sinf" || int(binary.BigEndian.Uint32(sinf[:4])) != len(sinf) {
		return errors.New("expected one complete SINF atom")
	}

	if !supportedSinf(sinf) {
		return errors.New("license format is not supported")
	}

	return nil
}

func normalizeUDID(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if !udidRe.MatchString(value) {
		return "", errors.New("device UDID must be 40 hex digits or 8-16 hex digits")
	}

	return value, nil
}

// fairplayDeviceID maps a USB UDID to the device's 20/8-byte FairPlay
// identity. Mirrors retrieve.py fairplay_device_id.
func fairplayDeviceID(value string) ([]byte, error) {
	value, err := normalizeUDID(value)
	if err != nil {
		return nil, err
	}

	if strings.Contains(value, "-") {
		return hex.DecodeString("6097a4b0c20a0a9f" + strings.ReplaceAll(value, "-", ""))
	}

	return hex.DecodeString(value)
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}

	return true
}
