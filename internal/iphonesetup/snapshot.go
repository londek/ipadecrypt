package iphonesetup

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/londek/ipadecrypt/internal/anisette"
	"github.com/londek/ipadecrypt/internal/anisettecapture"
	"github.com/londek/ipadecrypt/internal/config"
	"github.com/londek/ipadecrypt/internal/device"
	"github.com/londek/ipadecrypt/internal/tui"
)

func (setup Setup) ConfigureSnapshot(cfg *config.Config, paths *config.Paths) error {
	tui.Info("Uses the generator built into ipadecrypt. If no snapshot is cached, it is\ncaptured automatically from your jailbroken iPhone connected over USB.")

	settings := cfg.Anisette

	settings.Mode = config.AnisetteModeOffline
	if settings.Snapshot == "" {
		settings.Snapshot = defaultSnapshotPath(paths.Root)
	}

	captured := false

	if !snapshotComplete(settings.Snapshot) {
		if err := setup.captureSnapshot(cfg, settings); err != nil {
			return err
		}

		captured = true
	}

	updateStaticHeaders(&settings, paths.Root)

	checkErr := checkOfflineAnisette(settings)
	if checkErr != nil && !captured {
		tui.Info("The cached snapshot could not be verified; capturing a fresh one.")

		if err := setup.captureSnapshot(cfg, settings); err != nil {
			return err
		}

		updateStaticHeaders(&settings, paths.Root)
		checkErr = checkOfflineAnisette(settings)
	}

	if checkErr != nil {
		return checkErr
	}

	if err := setup.ensureIdentity(cfg, &settings); err != nil {
		return fmt.Errorf("prepare device headers for sign-in: %w", err)
	}

	if err := setup.ensureStoreAMD(cfg, settings); err != nil {
		return fmt.Errorf("prepare Store AMD for sign-in: %w", err)
	}

	cfg.Anisette = settings

	return nil
}

// Keep existing snapshots usable; main also used "anisette" for a state file.
func defaultSnapshotPath(root string) string {
	legacy := filepath.Join(root, "anisette")
	if info, err := os.Stat(legacy); err == nil && info.IsDir() {
		return filepath.Join(legacy, "snapshot")
	}

	return filepath.Join(root, "iphone-anisette", "snapshot")
}

func updateStaticHeaders(settings *config.Anisette, root string) {
	settings.StaticFile = ""

	candidate := filepath.Join(settings.Snapshot, "static.json")
	if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() {
		settings.StaticFile = candidate
		if headers, err := loadStaticHeaders(candidate); err == nil && len(missingIdentityHeaders(headers)) == 0 {
			return
		}
	}

	captured := filepath.Join(root, "anisette", "capture", "static.json")
	if _, err := os.Stat(captured); err == nil {
		settings.StaticFile = captured
		tui.Info("using captured static headers: %s", captured)
	}
}

func checkOfflineAnisette(settings config.Anisette) error {
	if err := validateOfflineAnisetteConfig(settings); err != nil {
		return err
	}

	live := tui.NewLive()
	live.Spin("checking adid snapshot against its device reference")

	if err := verifyOfflineAnisette(settings); err != nil {
		live.Fail("snapshot check failed")
		return err
	}

	live.OK("adid snapshot verified")

	return nil
}

func snapshotComplete(directory string) bool {
	for _, name := range []string{"manifest.json", "ctx.json", "stack.bin", "adidmem.bin", "fetched_pages.json"} {
		info, err := os.Stat(filepath.Join(directory, name))
		if err != nil || !info.Mode().IsRegular() {
			return false
		}
	}

	return true
}

func (setup Setup) captureSnapshot(cfg *config.Config, settings config.Anisette) error {
	tui.Info("The adid capture needs root access over SSH and a USB connection.\nipadecrypt will install, run, and clean up Frida itself.")

	if err := setup.promptDevice(cfg, true); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	var (
		client *device.Client
		err    error
	)
	for attempt := 0; attempt < 3; attempt++ {
		client, err = device.Connect(ctx, cfg.Device)
		if err == nil {
			break
		}

		if !errors.Is(err, device.ErrAuthentication) {
			return fmt.Errorf("connect for adid snapshot capture: %w", err)
		}

		cfg.Device.Auth = config.DeviceAuth{}
		if attempt == 2 {
			if saveErr := cfg.Save(); saveErr != nil {
				return fmt.Errorf("clear rejected device credentials: %w", saveErr)
			}

			return fmt.Errorf("SSH authentication failed for %s; check the password or use an SSH key", cfg.Device.User)
		}

		tui.Warn("SSH rejected authentication for %s; check the user and credentials", cfg.Device.User)

		if err := setup.promptDevice(cfg, true); err != nil {
			return err
		}
	}

	if err := cfg.Save(); err != nil {
		client.Close()
		return fmt.Errorf("save verified device config: %w", err)
	}

	defer client.Close()

	live := tui.NewLive()
	live.Spin("capturing and verifying adid snapshot; keep the iPhone connected")

	if err := anisettecapture.Capture(ctx, client, settings.Snapshot); err != nil {
		live.Fail("snapshot capture failed")
		return err
	}

	live.OK("adid snapshot captured")

	return nil
}

func verifyOfflineAnisette(settings config.Anisette) error {
	data, err := os.ReadFile(filepath.Join(settings.Snapshot, "ctx.json"))
	if err != nil {
		return err
	}

	var context struct {
		RefEpoch30 int64  `json:"refEpoch30"`
		RefOtpB64  string `json:"refOtpB64"`
		RefMidB64  string `json:"refMidB64"`
	}
	if err := json.Unmarshal(data, &context); err != nil {
		return fmt.Errorf("decode ctx.json: %w", err)
	}

	if context.RefEpoch30 == 0 || context.RefOtpB64 == "" {
		return errors.New("ctx.json has no device reference window or MD")
	}

	reference, err := base64.StdEncoding.DecodeString(context.RefOtpB64)
	if err != nil || len(reference) != 28 {
		return errors.New("ctx.json contains an invalid device reference MD")
	}

	static, err := loadStaticHeaders(settings.StaticFile)
	if err != nil {
		return err
	}

	provider := &anisette.NativeProvider{
		Snapshot: settings.Snapshot,
		Static:   static,
	}
	defer provider.Close()

	headers, err := provider.Headers(time.Unix(context.RefEpoch30*30+1, 0))
	if err != nil {
		return err
	}

	generated, err := base64.StdEncoding.DecodeString(headers[anisette.HeaderMD])
	if err != nil || len(generated) != 28 {
		return errors.New("generator returned an invalid MD")
	}

	if !bytes.Equal(generated, reference) {
		return errors.New("generated MD does not match the device reference")
	}

	if context.RefMidB64 != "" {
		mid, err := base64.StdEncoding.DecodeString(context.RefMidB64)
		if err != nil || len(mid) != 60 {
			return errors.New("ctx.json contains an invalid device reference MID")
		}

		generatedMID, err := base64.StdEncoding.DecodeString(headers[anisette.HeaderMDM])
		if err != nil || !bytes.Equal(generatedMID, mid) {
			return errors.New("generated MID does not match the device reference")
		}
	}

	return nil
}
