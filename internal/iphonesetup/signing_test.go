package iphonesetup

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/londek/ipadecrypt/internal/config"
	"github.com/londek/ipadecrypt/internal/fridarpc"
)

// Explicit opt-in: signs an inert body locally on the phone, with no Store
// request, account sign-in, or purchase. The user's config is never saved.
func TestLiveGoMescalSigning(t *testing.T) {
	path := os.Getenv("IPADECRYPT_TEST_SIGNING_CONFIG")
	if path == "" {
		t.Skip("requires explicit device config")
	}

	original, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}

	cfg := config.New(filepath.Join(t.TempDir(), "config.json"))
	cfg.Device = original.Device

	cfg.Anisette.Mode = config.AnisetteModeOffline
	if cfg.Device.UDID == "" {
		t.Fatal("live signing requires saved USB device configuration")
	}

	signing, err := (Setup{}).PrepareSigning(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer signing.Close()

	source, err := os.ReadFile(signing.agent)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	script, err := fridarpc.Attach(ctx, signing.remote, "accountsd", string(source), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer script.Close()

	raw, _, err := script.Call(ctx, "sign", base64.StdEncoding.EncodeToString([]byte("ipadecrypt Go signing transport validation")))
	if err != nil {
		t.Fatal(err)
	}

	var encoded string
	if err = json.Unmarshal(raw, &encoded); err != nil {
		t.Fatal(err)
	}

	signature, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(signature) == 0 || len(signature) > 64<<10 {
		t.Fatal("invalid Mescal signature")
	}

	t.Log("native Mescal signature received through Go transport")
}

func TestPrepareNativeMescalSkipsFrameworkMode(t *testing.T) {
	cfg := &config.Config{Anisette: config.Anisette{Mode: config.AnisetteModeFramework}}

	signing, err := (Setup{}).PrepareSigning(cfg)
	if err != nil {
		t.Fatal(err)
	}

	signing.Close()
}

func TestConfigureNativeUSB(t *testing.T) {
	cfg := &config.Config{Device: config.Device{Host: "192.0.2.1", Port: 22}}
	configureNativeUSB(cfg)

	if !cfg.Device.USB || cfg.Device.Port != 2222 {
		t.Fatalf("device = %+v, want USB port 2222", cfg.Device)
	}
}
