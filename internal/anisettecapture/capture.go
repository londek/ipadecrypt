package anisettecapture

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"

	"github.com/londek/ipadecrypt/internal/device"
)

func Capture(ctx context.Context, client *device.Client, destination string) error {
	return capture(ctx, client, destination, false)
}
func CaptureAMD(ctx context.Context, client *device.Client, destination string) error {
	return capture(ctx, client, destination, true)
}
func capture(ctx context.Context, client *device.Client, destination string, amd bool) (retErr error) {
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt)
	defer stop()

	assets, err := embeddedAssets()
	if err != nil {
		return err
	}

	artifacts, err := ensureFridaArtifacts(ctx)
	if err != nil {
		return err
	}

	server, err := startFridaServerAt(client, artifacts, "127.0.0.1:27042")
	if err != nil {
		return err
	}

	defer func() { retErr = errors.Join(retErr, server.Close()) }()

	if err = prepareCaptureDaemons(client); err != nil {
		return err
	}

	if err = liftAdidJetsamLimit(client, assets.jetsamHelper); err != nil {
		return err
	}

	if err = os.MkdirAll(filepath.Dir(destination), 0700); err != nil {
		return err
	}

	work, err := os.MkdirTemp(filepath.Dir(destination), ".anisette-capture-*")
	if err != nil {
		return err
	}

	defer func() {
		if os.Getenv("IPADECRYPT_DIAG_KEEP_CAPTURE") == "" {
			_ = os.RemoveAll(work)
		}
	}()

	staging := filepath.Join(work, "snapshot")
	if err = os.Mkdir(staging, 0700); err != nil {
		return err
	}

	if err = captureSnapshot(ctx, client, assets, staging, amd); err != nil {
		return fmt.Errorf("capture adid snapshot: %w", err)
	}

	return installSnapshot(staging, destination)
}
func installSnapshot(staging, destination string) error {
	if _, err := os.Stat(destination); err == nil {
		backup := destination + ".previous"
		if _, err := os.Stat(backup); err == nil {
			return fmt.Errorf("replace anisette snapshot: backup %s already exists", backup)
		}

		if err := os.Rename(destination, backup); err != nil {
			return fmt.Errorf("back up previous anisette snapshot: %w", err)
		}

		if err := os.Rename(staging, destination); err != nil {
			_ = os.Rename(backup, destination)
			return fmt.Errorf("install captured anisette snapshot: %w", err)
		}

		if err := os.RemoveAll(backup); err != nil {
			return fmt.Errorf("remove previous anisette snapshot: %w", err)
		}

		return nil
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect anisette snapshot destination: %w", err)
	}

	if err := os.Rename(staging, destination); err != nil {
		return fmt.Errorf("install captured anisette snapshot: %w", err)
	}

	return nil
}
