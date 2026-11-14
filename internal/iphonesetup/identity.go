package iphonesetup

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/londek/ipadecrypt/internal/anisettecapture"
	"github.com/londek/ipadecrypt/internal/config"
	"github.com/londek/ipadecrypt/internal/device"
	"github.com/londek/ipadecrypt/internal/tui"
)

func missingIdentityHeaders(values map[string]string) []string {
	headers := make(http.Header)
	for key, value := range values {
		headers.Set(key, value)
	}

	var missing []string

	for _, key := range anisettecapture.RequiredIdentityHeaders {
		if headers.Get(key) == "" {
			missing = append(missing, key)
		}
	}

	return missing
}

func (setup Setup) ensureIdentity(cfg *config.Config, settings *config.Anisette) error {
	_, err := repairOfflineIdentity(settings, func() (map[string]string, error) {
		tui.Info("The snapshot verifies OTP generation, but its device metadata is incomplete.\nReading the missing static headers from the iPhone before sign-in.")
		configureNativeUSB(cfg)

		if cfg.Device.UDID == "" {
			if err := setup.promptDevice(cfg, false); err != nil {
				return nil, err
			}
		}

		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		client, err := device.Connect(ctx, cfg.Device)
		if err != nil {
			return nil, fmt.Errorf("connect for device metadata: %w", err)
		}
		defer client.Close()

		headers, err := anisettecapture.CaptureStaticHeaders(ctx, client)
		if err != nil {
			return nil, err
		}

		tui.OK("static device headers captured locally; no sign-in request sent")

		return headers, nil
	})

	return err
}

func repairOfflineIdentity(settings *config.Anisette, capture func() (map[string]string, error)) (bool, error) {
	existing, err := loadStaticHeaders(settings.StaticFile)
	if err != nil {
		return false, err
	}

	if len(missingIdentityHeaders(existing)) == 0 {
		return false, nil
	}

	fresh, err := capture()
	if err != nil {
		return false, err
	}

	if missing := missingIdentityHeaders(fresh); len(missing) > 0 {
		return false, fmt.Errorf("device metadata incomplete: missing %s", strings.Join(missing, ", "))
	}

	merged := make(map[string]string, len(existing)+len(fresh))
	for key, value := range existing {
		merged[key] = value
	}

	for key, value := range fresh {
		for old := range merged {
			if strings.EqualFold(old, key) {
				delete(merged, old)
			}
		}

		merged[key] = value
	}

	data, err := json.MarshalIndent(merged, "", "  ")
	if err != nil {
		return false, err
	}

	destination := filepath.Join(settings.Snapshot, "static.json")
	if old, err := os.ReadFile(destination); err == nil {
		backup, err := os.CreateTemp(settings.Snapshot, ".static-before-identity-*.json")
		if err != nil {
			return false, err
		}

		_, writeErr := backup.Write(old)
		closeErr := backup.Close()

		if writeErr != nil {
			return false, writeErr
		}

		if closeErr != nil {
			return false, closeErr
		}
	} else if !os.IsNotExist(err) {
		return false, err
	}

	f, err := os.CreateTemp(settings.Snapshot, ".static-identity-*.json")
	if err != nil {
		return false, err
	}
	defer os.Remove(f.Name())

	_, writeErr := f.Write(data)
	closeErr := f.Close()

	if writeErr != nil {
		return false, writeErr
	}

	if closeErr != nil {
		return false, closeErr
	}

	if err := os.Rename(f.Name(), destination); err != nil {
		return false, err
	}

	settings.StaticFile = destination

	return true, nil
}
