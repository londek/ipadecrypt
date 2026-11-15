package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/londek/ipadecrypt/internal/config"
	"github.com/londek/ipadecrypt/internal/macstore"
	"github.com/londek/ipadecrypt/internal/tui"
	store "github.com/majd/ipatool/v2/pkg/appstore"
	"github.com/spf13/cobra"
)

var bootstrapFlow string
var decryptRefreshTicket bool

const (
	flowOriginal = "original"
	flowSnapshot = "snapshot"
	flowMac      = "mac"
)

func flowName(flow string) string {
	switch flow {
	case flowOriginal:
		return "Framework sign-in"
	case flowSnapshot:
		return "Offline anisette"
	case flowMac:
		return "Mac Store"
	default:
		return flow
	}
}

func selectedFlow(value string) (string, error) {
	switch value {
	case "", "legacy", flowOriginal:
		return flowOriginal, nil
	case flowSnapshot, flowMac:
		return value, nil
	default:
		return "", fmt.Errorf("unknown flow %q; choose original, snapshot or mac in bootstrap", value)
	}
}

// Older configs grouped both device flows under legacy (or omitted the field).
func savedFlow(cfg *config.Config) (string, error) {
	if (cfg.Flow == "" || cfg.Flow == "legacy") && cfg.Anisette.Mode == config.AnisetteModeOffline {
		return flowSnapshot, nil
	}

	return selectedFlow(cfg.Flow)
}

func applyDeviceFlow(cfg *config.Config, flow string) error {
	switch flow {
	case flowOriginal:
		cfg.Anisette.Mode = config.AnisetteModeFramework
	case flowSnapshot:
		cfg.Anisette.Mode = config.AnisetteModeOffline
	default:
		return fmt.Errorf("not a device flow: %q", flow)
	}
	// Preserve cached snapshot paths and device settings when switching back.
	return nil
}

func bootstrapHandler(cmd *cobra.Command, args []string) error {
	cfg, paths, err := loadConfigOrDefault(rootDirOverride)
	if err != nil {
		return err
	}

	current, err := savedFlow(cfg)
	if err != nil {
		return err
	}

	flow := bootstrapFlow
	if flow == "legacy" {
		flow, err = savedFlow(&config.Config{Anisette: cfg.Anisette})
		if err != nil {
			return err
		}
	}

	if flow == "" {
		choices := []string{flowOriginal, flowSnapshot, flowMac}
		defaultChoice := 0

		for i, candidate := range choices {
			if candidate == current {
				defaultChoice = i
			}
		}

		choice, err := tui.SelectDefault("Setup flow", []string{
			flowName(flowOriginal) + " - credential from iPhone",
			flowName(flowSnapshot) + " - iPhone snapshots, signing and credential",
			flowName(flowMac) + " - sign-in and credential on this Mac",
		}, defaultChoice)
		if err != nil {
			return err
		}

		flow = choices[choice]
	}

	flow, err = selectedFlow(flow)
	if err != nil {
		return err
	}

	if flow != flowMac {
		return bootstrapDeviceHandler(cmd, args, flow)
	}
	// Pin the choice in the supervised worker; never ask for the flow twice.
	arguments := append(append([]string{}, os.Args[1:]...), "--flow=mac")

	return macSupervisedArgs(cmd, 30*time.Minute, arguments, func(ctx context.Context) (retErr error) {
		session, err := macstore.Open(filepath.Join(paths.Root, "mac-store"))
		if err != nil {
			return err
		}
		defer func() { retErr = errors.Join(retErr, session.Close()) }()

		return bootstrapMac(ctx, cfg, session)
	})
}

func macSessionAccount(s *macstore.Session) (store.Account, error) {
	info, err := s.API.AccountInfo()
	if err != nil || info.Account.DirectoryServicesID == "" || info.Account.PasswordToken == "" {
		return store.Account{}, errors.New("no usable Mac Store session; run bootstrap and select the Mac flow")
	}

	return info.Account, nil
}

func decryptSelectedFlow(cmd *cobra.Command, args []string) error {
	cfg, paths, err := loadConfigOrDefault(rootDirOverride)
	if err != nil {
		return err
	}

	flow, err := savedFlow(cfg)
	if err != nil {
		return err
	}

	if flow != flowMac {
		if decryptRefreshTicket {
			return errors.New("--refresh-ticket requires the Mac flow selected in bootstrap")
		}

		tui.Info("flow: %s", flowName(flow))
		decryptHandler(cmd, args)

		return nil
	}

	if decryptOnDevice || decryptForceUninstall || decryptNoUninstall || decryptPatchDevType {
		return errors.New("device options require Framework sign-in or Offline anisette")
	}

	if decryptNoVerify || decryptSkipAppex || decryptStorefront != "" {
		return errors.New("the Mac flow verifies all binaries and uses the signed-in storefront; omit --no-verify, --skip-appex and --storefront")
	}

	return macSupervised(cmd, 30*time.Minute, func(ctx context.Context) (retErr error) {
		tui.Info("flow: %s", flowName(flow))

		session, err := macstore.Open(filepath.Join(paths.Root, "mac-store"))
		if err != nil {
			return err
		}
		defer func() { retErr = errors.Join(retErr, session.Close()) }()

		return runMacDecrypt(ctx, session, args[0], macDecryptOptions{
			destination: decryptOutput, version: decryptExtVerID,
			refresh: decryptRefreshTicket, keepWatch: decryptKeepWatch,
		})
	})
}

func versionsSelectedFlow(cmd *cobra.Command, args []string) error {
	cfg, _, err := loadConfigOrDefault(rootDirOverride)
	if err != nil {
		return err
	}

	flow, err := savedFlow(cfg)
	if err != nil {
		return err
	}

	if flow == flowMac {
		return errors.New("the interactive version browser is available in the original and iPhone snapshot flows; Mac decrypt accepts --external-version-id for a known build")
	}

	versionsHandler(cmd, args)

	return nil
}
