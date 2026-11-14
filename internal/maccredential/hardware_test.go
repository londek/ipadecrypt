package maccredential

import (
	"bytes"
	"testing"

	"howett.net/plist"
)

func TestHardwareIdentityRequiresBuiltinParentAndUniqueness(t *testing.T) {
	mac := []byte{1, 2, 3, 4, 5, 6}

	node := func(name string, builtin bool, value []byte) map[string]any {
		return map[string]any{"IOMACAddress": value, "IORegistryEntryChildren": []any{map[string]any{"BSD Name": name, "IOBuiltin": builtin}}}
	}
	for _, tc := range []struct {
		name     string
		registry any
		ok       bool
	}{
		{"array", []any{node("en0", true, mac)}, true},
		{"dictionary", node("en0", true, mac), true},
		{"external", node("en0", false, mac), false},
		{"other interface", node("en1", true, mac), false},
		{"short", node("en0", true, mac[:5]), false},
		{"ambiguous", []any{node("en0", true, mac), node("en0", true, []byte{6, 5, 4, 3, 2, 1})}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data, err := plist.Marshal(tc.registry, plist.XMLFormat)
			if err != nil {
				t.Fatal(err)
			}

			got, err := hardwareFromRegistry(data, "en0")
			if (err == nil) != tc.ok || tc.ok && !bytes.Equal(got, mac) {
				t.Fatalf("identity selection: %v", err)
			}
		})
	}
}
