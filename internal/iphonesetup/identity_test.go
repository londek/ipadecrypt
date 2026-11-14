package iphonesetup

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/londek/ipadecrypt/internal/anisettecapture"
	"github.com/londek/ipadecrypt/internal/config"
)

func TestRepairOfflineIdentityPreservesSnapshotAndRouting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "static.json")

	prior := []byte(`{"X-Apple-I-MD-RINFO":"33883392"}`)
	if err := os.WriteFile(path, prior, 0600); err != nil {
		t.Fatal(err)
	}

	settings := config.Anisette{Snapshot: dir, StaticFile: path}

	identity := map[string]string{}
	for _, key := range anisettecapture.RequiredIdentityHeaders {
		identity[key] = "fixture"
	}

	calls := 0
	capture := func() (map[string]string, error) { calls++; return identity, nil }

	repaired, err := repairOfflineIdentity(&settings, capture)
	if err != nil || !repaired {
		t.Fatalf("repair failed: %v", err)
	}

	saved, err := loadStaticHeaders(path)
	if err != nil {
		t.Fatal(err)
	}

	if saved["X-Apple-I-MD-RINFO"] != "33883392" || len(missingIdentityHeaders(saved)) != 0 {
		t.Fatal("incomplete merged metadata")
	}

	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("metadata is not private")
	}

	backups, _ := filepath.Glob(filepath.Join(dir, ".static-before-identity-*.json"))
	if len(backups) != 1 {
		t.Fatal("prior metadata not backed up")
	}

	data, _ := os.ReadFile(backups[0])
	if string(data) != string(prior) {
		t.Fatal("backup changed")
	}

	if repaired, err := repairOfflineIdentity(&settings, capture); err != nil || repaired || calls != 1 {
		t.Fatal("complete metadata recaptured")
	}
	// A stale legacy file must not override the complete snapshot metadata.
	root := t.TempDir()

	legacy := filepath.Join(root, "anisette/capture")
	if err := os.MkdirAll(legacy, 0700); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(legacy, "static.json"), prior, 0600); err != nil {
		t.Fatal(err)
	}

	updateStaticHeaders(&settings, root)

	if settings.StaticFile != path {
		t.Fatal("legacy metadata displaced complete snapshot identity")
	}
}

func TestRepairOfflineIdentityFailureKeepsExistingFile(t *testing.T) {
	for _, fails := range []bool{false, true} {
		dir := t.TempDir()
		path := filepath.Join(dir, "static.json")

		prior := []byte(`{"X-Apple-I-MD-RINFO":"old-routing"}`)
		if err := os.WriteFile(path, prior, 0600); err != nil {
			t.Fatal(err)
		}

		settings := config.Anisette{Snapshot: dir, StaticFile: path}

		_, err := repairOfflineIdentity(&settings, func() (map[string]string, error) {
			if fails {
				return nil, errors.New("device unavailable")
			}

			return map[string]string{"X-Apple-Locale": "en_US"}, nil
		})
		if err == nil {
			t.Fatal("accepted incomplete capture")
		}

		data, _ := os.ReadFile(path)
		if string(data) != string(prior) {
			t.Fatal("failed repair modified existing metadata")
		}
	}
}

// Applies explicitly supplied, locally captured metadata, never sends login requests.
func TestApplyCapturedIdentity(t *testing.T) {
	path := os.Getenv("IPADECRYPT_TEST_IDENTITY_APPLY_CONFIG")
	if path == "" {
		t.Skip("requires explicit local config and captured metadata")
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(os.Getenv("IPADECRYPT_TEST_IDENTITY_APPLY_SOURCE"))
	if err != nil {
		t.Fatal(err)
	}

	var identity map[string]string
	if err := json.Unmarshal(data, &identity); err != nil {
		t.Fatal(err)
	}

	if _, err := repairOfflineIdentity(&cfg.Anisette, func() (map[string]string, error) { return identity, nil }); err != nil {
		t.Fatal(err)
	}

	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
}
