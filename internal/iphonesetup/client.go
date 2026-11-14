package iphonesetup

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/londek/ipadecrypt/internal/anisette"
	"github.com/londek/ipadecrypt/internal/appstore"
	"github.com/londek/ipadecrypt/internal/config"
)

// loadStaticHeaders reads the optional static.json of window-independent anisette
// headers (routing/device-identity) captured once. Empty path => nil map.
func loadStaticHeaders(path string) (map[string]string, error) {
	if path == "" {
		return nil, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("offline anisette static headers: %w", err)
	}

	var headers map[string]string
	if err := json.Unmarshal(data, &headers); err != nil {
		return nil, fmt.Errorf("offline anisette static headers: %w", err)
	}

	return headers, nil
}

func NewClient(cfg *config.Config, paths *config.Paths) (*appstore.Client, error) {
	provider, err := Provider(cfg.Anisette)
	if err != nil {
		return nil, err
	}

	return appstore.New(filepath.Join(paths.Root, "cookies"), provider)
}

func Provider(settings config.Anisette) (anisette.Provider, error) {
	switch settings.Mode {
	case "", config.AnisetteModeFramework:
		return nil, nil
	case config.AnisetteModeOffline:
		if err := validateOfflineAnisetteConfig(settings); err != nil {
			return nil, err
		}

		static, err := loadStaticHeaders(settings.StaticFile)
		if err != nil {
			return nil, err
		}

		snapshotAMD := settings.Snapshot + "-amd"
		if _, err := os.Stat(filepath.Join(snapshotAMD, "ctx.json")); err != nil {
			snapshotAMD = ""
		}

		return &anisette.NativeProvider{
			Snapshot:    settings.Snapshot,
			SnapshotAMD: snapshotAMD,
			Static:      static,
		}, nil
	default:
		return nil, fmt.Errorf("unknown anisette mode %q", settings.Mode)
	}
}

func validateOfflineAnisetteConfig(settings config.Anisette) error {
	if settings.Snapshot == "" {
		return fmt.Errorf("offline anisette: snapshot path is required")
	}

	// Capture and generation share the same private snapshot format.
	for _, name := range []string{"manifest.json", "ctx.json", "stack.bin", "adidmem.bin", "fetched_pages.json"} {
		if err := requirePrivateFile(filepath.Join(settings.Snapshot, name)); err != nil {
			return fmt.Errorf("offline anisette snapshot: %w", err)
		}
	}

	if settings.StaticFile != "" {
		if err := requirePrivateFile(settings.StaticFile); err != nil {
			return fmt.Errorf("offline anisette static headers: %w", err)
		}
	}

	return nil
}

func requireRegularFile(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}

	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", path)
	}

	return nil
}

func requirePrivateFile(path string) error {
	if err := requireRegularFile(path); err != nil {
		return err
	}

	info, err := os.Stat(path)
	if err != nil {
		return err
	}

	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s is accessible by group or other users; use chmod 0600", path)
	}

	return nil
}
