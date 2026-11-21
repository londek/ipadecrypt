package config

import (
	"path/filepath"
	"testing"
)

func TestCachedTestFlightIPA(t *testing.T) {
	paths, err := NewPaths(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	got, err := paths.CachedTestFlightIPA("100", "2.3.0", 42, 123456)
	if err != nil {
		t.Fatal(err)
	}

	wantSuffix := filepath.Join("cache", "testflight", "accounts", "100", "42", "2.3.0", "123456", "package.ipa")
	if filepath.Clean(got) != filepath.Join(paths.Root, wantSuffix) {
		t.Fatalf("path = %q", got)
	}

	for _, test := range []struct {
		dsid    string
		version string
		build   int64
	}{
		{dsid: "../escape", version: "2.3.0", build: 1},
		{dsid: "100", version: "../../escape", build: 1},
		{dsid: "100", version: "2.3.0", build: 0},
	} {
		if _, err := paths.CachedTestFlightIPA(test.dsid, test.version, 42, test.build); err == nil {
			t.Fatalf("accepted cache identity %#v", test)
		}
	}
}
