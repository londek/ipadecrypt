package iphonesetup

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/londek/ipadecrypt/internal/config"
)

func TestDefaultSnapshotPathPreservesExistingData(t *testing.T) {
	for _, kind := range []string{"absent", "file", "directory"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			legacy := filepath.Join(root, "anisette")
			want := filepath.Join(root, "iphone-anisette", "snapshot")

			switch kind {
			case "file":
				if err := os.WriteFile(legacy, []byte("main state"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "directory":
				if err := os.Mkdir(legacy, 0o700); err != nil {
					t.Fatal(err)
				}

				want = filepath.Join(legacy, "snapshot")
			}

			if got := defaultSnapshotPath(root); got != want {
				t.Fatalf("snapshot = %q, want %q", got, want)
			}
		})
	}
}

// Offline control: this test never connects to a device or signs in.
func TestCaptureReferenceOffline(t *testing.T) {
	dir := os.Getenv("IPADECRYPT_TEST_REFERENCE_SNAPSHOT")
	if dir == "" {
		t.Skip("requires explicit local snapshot")
	}

	dir, err := filepath.Abs(dir)
	if err != nil {
		t.Fatal(err)
	}

	settings := config.Anisette{Mode: config.AnisetteModeOffline, Snapshot: dir}
	if err := verifyOfflineAnisette(settings); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "ctx.json"))
	if err != nil {
		t.Fatal(err)
	}

	var ctx map[string]any
	if err := json.Unmarshal(data, &ctx); err != nil {
		t.Fatal(err)
	}

	if ctx["refMidB64"] == nil {
		t.Skip("snapshot has no MID reference")
	}

	copyDir := t.TempDir()

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	for _, entry := range entries {
		if entry.Name() == "ctx.json" {
			continue
		}

		if err := os.Symlink(filepath.Join(dir, entry.Name()), filepath.Join(copyDir, entry.Name())); err != nil {
			t.Fatal(err)
		}
	}

	ctx["refMidB64"] = base64.StdEncoding.EncodeToString(make([]byte, 60))

	data, err = json.Marshal(ctx)
	if err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(copyDir, "ctx.json"), data, 0600); err != nil {
		t.Fatal(err)
	}

	settings.Snapshot = copyDir
	if err := verifyOfflineAnisette(settings); err == nil || !strings.Contains(err.Error(), "MID does not match") {
		t.Fatalf("tampered MID was not rejected: %v", err)
	}
}

func TestSnapshotComplete(t *testing.T) {
	directory := t.TempDir()
	if snapshotComplete(directory) {
		t.Fatal("empty directory must not be a complete snapshot")
	}

	for _, name := range []string{"manifest.json", "ctx.json", "stack.bin", "adidmem.bin", "fetched_pages.json"} {
		if err := os.WriteFile(filepath.Join(directory, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	if !snapshotComplete(directory) {
		t.Fatal("snapshot with all required files must be complete")
	}
}

func TestUpdateStaticHeadersPrefersCaptured(t *testing.T) {
	root := t.TempDir()
	snapshot := filepath.Join(root, "anisette", "snapshot")
	captured := filepath.Join(root, "anisette", "capture", "static.json")

	if err := os.MkdirAll(snapshot, 0o700); err != nil {
		t.Fatal(err)
	}

	if err := os.MkdirAll(filepath.Dir(captured), 0o700); err != nil {
		t.Fatal(err)
	}

	snapshotStatic := filepath.Join(snapshot, "static.json")
	if err := os.WriteFile(snapshotStatic, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(captured, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}

	settings := config.Anisette{Snapshot: snapshot}
	updateStaticHeaders(&settings, root)

	if settings.StaticFile != captured {
		t.Fatalf("static file = %q, want captured %q", settings.StaticFile, captured)
	}

	if err := os.Remove(captured); err != nil {
		t.Fatal(err)
	}

	updateStaticHeaders(&settings, root)

	if settings.StaticFile != snapshotStatic {
		t.Fatalf("static file = %q, want snapshot %q", settings.StaticFile, snapshotStatic)
	}
}
