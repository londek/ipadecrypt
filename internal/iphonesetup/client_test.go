package iphonesetup

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/londek/ipadecrypt/internal/config"
)

func TestConfiguredAnisetteProviderFramework(t *testing.T) {
	provider, err := Provider(config.Anisette{Mode: config.AnisetteModeFramework})
	if err != nil {
		t.Fatal(err)
	}

	if provider != nil {
		t.Fatal("framework mode must not install an anisette provider")
	}
}

func TestValidateOfflineAnisetteConfig(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission check")
	}

	root := t.TempDir()

	snapshot := filepath.Join(root, "snapshot")
	if err := os.Mkdir(snapshot, 0o700); err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{"manifest.json", "ctx.json", "stack.bin", "adidmem.bin", "fetched_pages.json"} {
		if err := os.WriteFile(filepath.Join(snapshot, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	static := filepath.Join(snapshot, "static.json")
	if err := os.WriteFile(static, nil, 0o644); err != nil {
		t.Fatal(err)
	}

	settings := config.Anisette{
		Mode:       config.AnisetteModeOffline,
		Snapshot:   snapshot,
		StaticFile: static,
	}
	if err := validateOfflineAnisetteConfig(settings); err == nil {
		t.Fatal("expected group-readable static headers to be rejected")
	}

	if err := os.Chmod(static, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := validateOfflineAnisetteConfig(settings); err != nil {
		t.Fatal(err)
	}
}
