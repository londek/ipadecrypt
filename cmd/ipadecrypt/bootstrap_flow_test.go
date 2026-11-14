package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/londek/ipadecrypt/internal/appstore"
	"github.com/londek/ipadecrypt/internal/config"
	"github.com/londek/ipadecrypt/internal/iphonesetup"
	"github.com/londek/ipadecrypt/internal/maccredential"
	"github.com/londek/ipadecrypt/internal/macstore"
	store "github.com/majd/ipatool/v2/pkg/appstore"
	"github.com/spf13/cobra"
)

func TestFrameworkResetPreservesSnapshotDirectory(t *testing.T) {
	for _, legacyDir := range []bool{false, true} {
		root := t.TempDir()

		legacy := filepath.Join(root, "anisette")
		if legacyDir {
			if err := os.Mkdir(legacy, 0o700); err != nil {
				t.Fatal(err)
			}

			legacy = filepath.Join(legacy, "snapshot-marker")
		}

		for _, path := range []string{legacy, filepath.Join(root, appstore.AnisetteFile)} {
			if err := os.WriteFile(path, []byte("preserve snapshots"), 0o600); err != nil {
				t.Fatal(err)
			}
		}

		for range 2 {
			if err := resetFrameworkAuthentication(root); err != nil {
				t.Fatal(err)
			}
		}

		if _, err := os.Stat(filepath.Join(root, appstore.AnisetteFile)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("authentication state was not removed: %v", err)
		}

		data, err := os.ReadFile(legacy)
		if legacyDir {
			if err != nil || string(data) != "preserve snapshots" {
				t.Fatalf("snapshot changed: %q, %v", data, err)
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("legacy authentication state was not removed: %v", err)
		}
	}
}

func TestUnknownFlowFailsBeforeCommandExecution(t *testing.T) {
	previous := rootDirOverride

	t.Cleanup(func() { rootDirOverride = previous })
	rootDirOverride = t.TempDir()
	cfg := config.New(filepath.Join(rootDirOverride, "config.json"))

	cfg.Flow = "unknown"
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}

	for _, run := range []func(*cobra.Command, []string) error{bootstrapHandler, decryptSelectedFlow, versionsSelectedFlow} {
		if err := run(&cobra.Command{}, nil); err == nil || !strings.Contains(err.Error(), "unknown flow") {
			t.Fatalf("invalid flow was not rejected before execution: %v", err)
		}
	}
}

func TestSavedThreeFlowsAndOldConfigMigration(t *testing.T) {
	for _, tc := range []struct{ flow, mode, want string }{
		{"", "", "original"}, {"", "framework", "original"}, {"", "offline", "snapshot"},
		{"legacy", "framework", "original"}, {"legacy", "offline", "snapshot"},
		{"original", "offline", "original"}, {"snapshot", "framework", "snapshot"},
		{"mac", "offline", "mac"},
	} {
		cfg := &config.Config{Flow: tc.flow, Anisette: config.Anisette{Mode: tc.mode}}

		got, err := savedFlow(cfg)
		if err != nil || got != tc.want {
			t.Fatalf("%+v: %s, %v", tc, got, err)
		}
	}
}

func TestDeviceFlowSwitchKeepsSnapshotAndControlsLoadedProvider(t *testing.T) {
	oldRoot := rootDirOverride

	t.Cleanup(func() { rootDirOverride = oldRoot })
	rootDirOverride = t.TempDir()
	cfg := config.New(filepath.Join(rootDirOverride, "config.json"))
	cfg.Anisette = config.Anisette{Mode: config.AnisetteModeOffline, Snapshot: "saved-snapshot", StaticFile: "saved-static"}

	cfg.Device.User = "saved-user"
	for _, flow := range []string{flowOriginal, flowSnapshot, flowOriginal} {
		cfg.Flow = flow
		if err := applyDeviceFlow(cfg, flow); err != nil {
			t.Fatal(err)
		}

		if cfg.Anisette.Snapshot != "saved-snapshot" || cfg.Anisette.StaticFile != "saved-static" || cfg.Device.User != "saved-user" {
			t.Fatal("switch discarded settings")
		}
		// A stale mode on disk must not override an explicit selection.
		cfg.Anisette.Mode = config.AnisetteModeOffline
		if flow == flowSnapshot {
			cfg.Anisette.Mode = config.AnisetteModeFramework
		}

		if err := cfg.Save(); err != nil {
			t.Fatal(err)
		}

		loaded, _, err := loadConfigOrDefault(rootDirOverride)
		if err != nil {
			t.Fatal(err)
		}

		if flow == flowOriginal {
			provider, err := iphonesetup.Provider(loaded.Anisette)
			if err != nil || provider != nil {
				t.Fatal("original flow enabled snapshot provider", err)
			}

			signing, err := (iphonesetup.Setup{PromptDevice: promptMintDevice}).PrepareSigning(loaded)
			if err != nil {
				t.Fatal("original flow tried native device signing", err)
			}

			signing.Close()
		} else if loaded.Anisette.Mode != config.AnisetteModeOffline {
			t.Fatal("snapshot flow lost offline provider")
		}
	}
}

func writeBootstrapCredential(t *testing.T, path string, value byte) []byte {
	t.Helper()

	b := bytes.Repeat([]byte{value}, 16)

	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}

	report := maccredential.Report{PlaintextVerified: true, EncryptedImages: 1, MachOScanned: 1, MachOCompared: 1, CredentialHash: fmt.Sprintf("%x", sha256.Sum256(b))}

	data, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(path+".json", data, 0600); err != nil {
		t.Fatal(err)
	}

	return b
}

func TestMacCredentialReportMustMatchKey(t *testing.T) {
	p := filepath.Join(t.TempDir(), "credential")
	writeBootstrapCredential(t, p, 1)

	if _, err := verifiedMacCredential(p); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(p, bytes.Repeat([]byte{2}, 16), 0600); err != nil {
		t.Fatal(err)
	}

	if _, err := verifiedMacCredential(p); err == nil {
		t.Fatal("unrelated verification report accepted")
	}
}

func TestCredentialPromotionPreservesPreviousAndRollsBack(t *testing.T) {
	for _, fail := range []bool{false, true} {
		root := t.TempDir()
		destination, candidate := filepath.Join(root, "installed"), filepath.Join(root, "candidate")
		old := writeBootstrapCredential(t, destination, 1)

		fresh := writeBootstrapCredential(t, candidate, 2)
		if fail {
			if err := os.Remove(candidate); err != nil {
				t.Fatal(err)
			}
		}

		err := promoteMacCredential(candidate, destination)
		if (err != nil) != fail {
			t.Fatalf("promotion error: %v", err)
		}

		actual, err := os.ReadFile(destination)
		if err != nil {
			t.Fatal(err)
		}

		want := fresh
		if fail {
			want = old
		}

		if !bytes.Equal(actual, want) {
			t.Fatal("installed credential corrupted")
		}

		if _, err := verifiedMacCredential(destination); err != nil {
			t.Fatal(err)
		}

		if !fail {
			files, err := filepath.Glob(destination + ".previous-*")
			if err != nil || len(files) != 2 {
				t.Fatal("previous credential and provenance not preserved")
			}
		}
	}
}

// Only local AccountInfo is implemented. Any accidental login/download would
// call the nil embedded API and fail the test rather than contact Apple.
type bootstrapLocalAPI struct {
	store.AppStore
	account store.Account
}

func (api bootstrapLocalAPI) AccountInfo() (store.AccountInfoOutput, error) {
	return store.AccountInfoOutput{Account: api.account}, nil
}

func TestMacBootstrapCachedReadinessPreservesClassicState(t *testing.T) {
	oldSkip, oldReset, oldRemint := bootstrapSkipLogin, bootstrapReset, bootstrapRemint

	t.Cleanup(func() { bootstrapSkipLogin, bootstrapReset, bootstrapRemint = oldSkip, oldReset, oldRemint })

	bootstrapSkipLogin, bootstrapReset, bootstrapRemint = true, false, false

	paths, err := config.NewPaths(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	cfg := config.New(paths.ConfigPath())
	cfg.Flow = "legacy"
	cfg.Apple.Email = "classic@example.invalid"
	cfg.Device.User = "classic-user"
	cfg.Anisette.Snapshot = "classic-snapshot"
	a := store.Account{Email: "mac@example.invalid", DirectoryServicesID: "42", PasswordToken: "test-token"}
	s := &macstore.Session{Root: filepath.Join(paths.Root, "mac-store"), API: bootstrapLocalAPI{account: a}}
	p := macstore.AccountCredentialPath(s.Root, a)
	writeBootstrapCredential(t, p, 1)

	if err := bootstrapMac(context.Background(), cfg, s); err != nil {
		t.Fatal(err)
	}

	saved, err := config.Load(paths.ConfigPath())
	if err != nil {
		t.Fatal(err)
	}

	if saved.Flow != "mac" || saved.Apple.Email != cfg.Apple.Email || saved.Device.User != cfg.Device.User || saved.Anisette.Snapshot != cfg.Anisette.Snapshot {
		t.Fatal("flow selection damaged classic settings")
	}
	// Failed verification cannot activate a different backend.
	cfg.Flow = "legacy"

	if err := os.WriteFile(p, bytes.Repeat([]byte{9}, 16), 0600); err != nil {
		t.Fatal(err)
	}

	if err := bootstrapMac(context.Background(), cfg, s); err == nil {
		t.Fatal("bad credential reported ready")
	}

	if cfg.Flow != "legacy" {
		t.Fatal("failed bootstrap switched flow")
	}
}

func TestUnifiedMacDecryptDoesNotReadLegacyCredential(t *testing.T) {
	paths, err := config.NewPaths(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	a := store.Account{Email: "mac@example.invalid", DirectoryServicesID: "42", PasswordToken: "test-token"}

	old, err := paths.CredentialPath(a.DirectoryServicesID, false)
	if err != nil {
		t.Fatal(err)
	}

	writeBootstrapCredential(t, old, 1)

	s := &macstore.Session{Root: filepath.Join(paths.Root, "mac-store"), API: bootstrapLocalAPI{account: a}}

	err = runMacDecrypt(context.Background(), s, "never-downloaded.ipa", macDecryptOptions{})
	if err == nil || !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing Mac credential should fail before download: %v", err)
	}
}
