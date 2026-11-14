package maccredential

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"time"

	"howett.net/plist"
)

func localHardwareMAC(ctx context.Context, name string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	data, err := exec.CommandContext(ctx, "/usr/sbin/ioreg", "-a", "-l", "-r", "-k", "IOMACAddress", "-p", "IOService").Output()
	if err != nil {
		return nil, errors.New("could not read hardware identity from IORegistry")
	}

	return hardwareFromRegistry(data, name)
}

// FairPlay needs the controller's raw IOMACAddress for the built-in interface.
// Network interface addresses may be randomized and cannot substitute for it.
func hardwareFromRegistry(data []byte, name string) ([]byte, error) {
	var document any
	if _, err := plist.Unmarshal(data, &document); err != nil {
		return nil, errors.New("invalid IORegistry property list")
	}

	var (
		found     []byte
		ambiguous bool
		walk      func(any, map[string]any)
	)

	walk = func(value any, parent map[string]any) {
		switch node := value.(type) {
		case []any:
			for _, child := range node {
				walk(child, parent)
			}
		case map[string]any:
			if node["BSD Name"] == name && node["IOBuiltin"] == true {
				if mac, ok := parent["IOMACAddress"].([]byte); ok && len(mac) == 6 {
					if found != nil && !bytes.Equal(found, mac) {
						ambiguous = true
					}

					found = append([]byte(nil), mac...)
				}
			}

			walk(node["IORegistryEntryChildren"], node)
		}
	}
	walk(document, nil)

	if found == nil || ambiguous {
		return nil, errors.New("no unambiguous built-in interface hardware identity")
	}

	return found, nil
}
