package appstore

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAnisetteStateCoexistsWithSnapshots(t *testing.T) {
	for _, legacyDir := range []bool{false, true} {
		t.Run(map[bool]string{false: "main state file", true: "snapshot directory"}[legacyDir], func(t *testing.T) {
			root := t.TempDir()

			legacy := filepath.Join(root, "anisette")
			if legacyDir {
				if err := os.Mkdir(legacy, 0o700); err != nil {
					t.Fatal(err)
				}

				legacy = filepath.Join(legacy, "snapshot-marker")
			}

			if err := os.WriteFile(legacy, []byte("previous"), 0o600); err != nil {
				t.Fatal(err)
			}

			client, err := New(filepath.Join(root, "cookies"), nil)
			if err != nil {
				t.Fatal(err)
			}

			client.loadAnisette()

			want := "previous"
			if legacyDir {
				want = ""
			}

			if string(client.anisetteState) != want {
				t.Fatalf("loaded state = %q, want %q", client.anisetteState, want)
			}

			if err := client.saveAnisette([]byte("rotated")); err != nil {
				t.Fatal(err)
			}

			client.anisetteState = nil
			client.loadAnisette()

			if string(client.anisetteState) != "rotated" {
				t.Fatalf("rotated state was not reloaded: %q", client.anisetteState)
			}

			if data, err := os.ReadFile(legacy); err != nil || string(data) != "previous" {
				t.Fatalf("legacy data changed: %q, %v", data, err)
			}
		})
	}
}
