package iphonesetup

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/londek/ipadecrypt/internal/anisettecapture"
	"github.com/londek/ipadecrypt/internal/appstore"
	"github.com/londek/ipadecrypt/internal/config"
	"github.com/londek/ipadecrypt/internal/device"
	"github.com/londek/ipadecrypt/internal/tui"
)

func configureNativeUSB(cfg *config.Config) {
	cfg.Device.USB = true
	if cfg.Device.Port == 0 || cfg.Device.Port == 22 {
		cfg.Device.Port = 2222
	}
}

// SigningSession owns the device server and USB tunnel for native Store work.
// A nil session represents the framework flow and needs no device resources.
type SigningSession struct {
	remote, agent, guid string
	cleanup             func()
}

func (s *SigningSession) Configure(client *appstore.Client) error {
	if s == nil {
		return nil
	}

	return client.ConfigureDeviceSigning(s.remote, s.agent, s.guid)
}

func (s *SigningSession) Close() {
	if s != nil {
		s.cleanup()
	}
}

func (setup Setup) PrepareSigning(cfg *config.Config) (*SigningSession, error) {
	if cfg.Anisette.Mode != config.AnisetteModeOffline {
		return nil, nil
	}

	configureNativeUSB(cfg)

	if cfg.Device.UDID == "" {
		if err := setup.promptDevice(cfg, false); err != nil {
			return nil, err
		}
	}

	if cfg.Device.UDID == "" {
		return nil, errors.New("device UDID is required for native signing")
	}

	if err := cfg.Save(); err != nil {
		return nil, fmt.Errorf("save native signing device config: %w", err)
	}

	agent, err := anisettecapture.MescalAgent()
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	client, err := device.Connect(ctx, cfg.Device)
	if err != nil {
		return nil, fmt.Errorf("connect for native signing: %w", err)
	}

	if err := anisettecapture.EnsureItunesstored(client); err != nil {
		client.Close()
		return nil, fmt.Errorf("prepare itunesstored: %w", err)
	}

	stopFrida, err := anisettecapture.StartFrida(ctx, client)
	if err != nil {
		client.Close()
		return nil, fmt.Errorf("start native signing Frida: %w", err)
	}

	stopTunnel, err := anisettecapture.StartFridaTunnel(cfg.Device.UDID)
	if err != nil {
		_ = stopFrida()

		client.Close()

		return nil, err
	}

	tui.Info("The iPhone will provide native Store signing over USB; anisette is generated on this Mac.")

	var once sync.Once

	return &SigningSession{remote: "127.0.0.1:27042", agent: agent, guid: cfg.Device.UDID, cleanup: func() {
		once.Do(func() {
			stopTunnel()

			if err := stopFrida(); err != nil {
				tui.Warn("native signing Frida cleanup: %v", err)
			}

			client.Close()
		})
	}}, nil
}
