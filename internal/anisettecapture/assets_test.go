package anisettecapture

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestExtractAssets(t *testing.T) {
	cache := t.TempDir()

	assets, err := extractAssets(cache)
	if err != nil {
		t.Fatal(err)
	}

	for _, path := range []string{assets.dumpAgent, assets.triggerAgent, assets.mescalAgent, assets.purchaseAgent} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}

		if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode = %o, want 600", path, info.Mode().Perm())
		}
	}

	again, err := extractAssets(cache)
	if err != nil {
		t.Fatal(err)
	}

	if again != assets {
		t.Fatalf("second extraction returned %+v, want %+v", again, assets)
	}
}

func TestInstallSnapshot(t *testing.T) {
	root := t.TempDir()

	staging := filepath.Join(root, "staging")
	if err := os.Mkdir(staging, 0o700); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(staging, "manifest.json"), []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}

	destination := filepath.Join(root, "snapshot")
	if err := os.Mkdir(destination, 0o700); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(destination, "manifest.json"), []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := installSnapshot(staging, destination); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(filepath.Join(destination, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}

	if string(data) != "new" {
		t.Fatalf("installed manifest = %q, want new", data)
	}

	if _, err := os.Stat(destination + ".previous"); !os.IsNotExist(err) {
		t.Fatalf("previous snapshot was not removed: %v", err)
	}
}
