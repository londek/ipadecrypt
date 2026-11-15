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
	"github.com/londek/ipadecrypt/internal/anisette/nativegen"
	"github.com/londek/ipadecrypt/internal/anisettecapture"
	"github.com/londek/ipadecrypt/internal/config"
	"github.com/londek/ipadecrypt/internal/device"
	"github.com/londek/ipadecrypt/internal/tui"
)

func (setup Setup) ensureStoreAMD(cfg *config.Config, settings config.Anisette) error {
	destination := settings.Snapshot + "-amd"
	if snapshotComplete(destination) {
		if err := verifyOfflineStoreAMD(destination); err == nil {
			tui.OK("Store AMD snapshot verified")
			return nil
		}

		tui.Info("The Store AMD snapshot could not be verified; capturing a fresh one.")
	} else {
		tui.Info("Store sign-in also needs a separate AMD snapshot.\nCapturing it from the iPhone before asking for your Apple ID.")
	}

	configureNativeUSB(cfg)

	if cfg.Device.UDID == "" {
		if err := setup.promptDevice(cfg, false); err != nil {
			return err
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	client, err := device.Connect(ctx, cfg.Device)
	if err != nil {
		return fmt.Errorf("connect for Store AMD capture: %w", err)
	}
	defer client.Close()

	if err := anisettecapture.CaptureAMD(ctx, client, destination); err != nil {
		return err
	}

	if err := verifyOfflineStoreAMD(destination); err != nil {
		return err
	}

	tui.OK("Store AMD snapshot captured and verified")

	return nil
}

func verifyOfflineStoreAMD(directory string) error {
	if err := validateOfflineAnisetteConfig(config.Anisette{Snapshot: directory}); err != nil {
		return err
	}

	data, err := os.ReadFile(filepath.Join(directory, "ctx.json"))
	if err != nil {
		return err
	}

	var reference struct {
		MD  string `json:"refOtpB64"`
		MID string `json:"refMidB64"`
	}
	if err := json.Unmarshal(data, &reference); err != nil {
		return err
	}

	md, err := base64.StdEncoding.DecodeString(reference.MD)
	if err != nil || len(md) != 24 || !bytes.Equal(md[:8], []byte{0, 0, 0, 4, 0, 0, 0, 16}) {
		return errors.New("store AMD snapshot has an invalid type-4 reference")
	}

	emulator, err := nativegen.New(directory, 0)
	if err != nil {
		return err
	}

	otp, err := emulator.Run()
	if err != nil {
		return err
	}

	generated, err := anisette.EncodeAMD(otp)
	if err != nil || generated != reference.MD {
		return errors.New("generated Store AMD does not match the device reference")
	}

	if len(emulator.MID()) != 60 {
		return errors.New("store AMD-M has an invalid length")
	}

	if reference.MID != "" {
		mid, err := base64.StdEncoding.DecodeString(reference.MID)
		if err != nil || !bytes.Equal(mid, emulator.MID()) {
			return errors.New("generated Store AMD-M does not match the device reference")
		}
	}

	return nil
}
