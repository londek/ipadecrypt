package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/londek/ipadecrypt/internal/config"
	"github.com/londek/ipadecrypt/internal/fairplay"
	"github.com/londek/ipadecrypt/internal/maccredential"
	"github.com/londek/ipadecrypt/internal/macstore"
	"github.com/londek/ipadecrypt/internal/tui"
	store "github.com/majd/ipatool/v2/pkg/appstore"
)

func bootstrapMac(ctx context.Context, cfg *config.Config, s *macstore.Session) error {
	tui.Info("Mac Store sign-in and credential setup.\nFresh FairPlay state is created on this Mac; no iPhone is needed.")
	tui.Step(1, 3, "Sign in to the Mac Store")

	a, err := macSessionAccount(s)

	login := err != nil || bootstrapReset
	if bootstrapSkipLogin {
		if login {
			return errors.New("--skip-login needs an existing Mac session and cannot be combined with --reset")
		}

		tui.Info("using the saved Mac session; network authentication is skipped")
	} else if !login {
		choice, err := tui.Select("Mac account", []string{"Continue with " + a.Email, "Sign in to another account"})
		if err != nil {
			return err
		}

		login = choice == 1
	}

	if login {
		email, err := tui.Prompt("Apple ID email")
		if err != nil {
			return err
		}

		password, err := tui.PromptPassword("Apple ID password")
		if err != nil {
			return err
		}

		if strings.TrimSpace(email) == "" || password == "" {
			return errors.New("email and password are required")
		}

		tui.Info("Preparing the Mac Store session; the first run may download Apple runtime assets.")

		live := tui.NewLive()
		defer live.Stop()

		live.Spin("signing in")

		_, err = s.API.Login(store.LoginInput{Email: strings.TrimSpace(email), Password: password})
		if errors.Is(err, store.ErrAuthCodeRequired) {
			live.Stop()

			code, e := tui.PromptPassword("Apple verification code")
			if e != nil {
				return e
			}

			code = strings.TrimSpace(code)
			if len(code) != 6 || strings.Trim(code, "0123456789") != "" {
				return errors.New("expected a six-digit verification code")
			}

			live = tui.NewLive()
			defer live.Stop()

			live.Spin("signing in")

			_, err = s.API.Login(store.LoginInput{Email: strings.TrimSpace(email), Password: password, AuthCode: code})
		}

		if err != nil {
			live.Stop()
			return macstore.SafeError(err)
		}

		a, err = macSessionAccount(s)
		if err != nil {
			return err
		}

		live.OK("authenticated")
	} else {
		tui.OK("Mac account loaded")
	}

	tui.Step(2, 3, "Prepare your Mac decryption credential")

	destination := macstore.AccountCredentialPath(s.Root, a)

	_, cachedErr := verifiedMacCredential(destination)
	if cachedErr == nil && !bootstrapRemint {
		tui.OK("Mac credential and its previous verification report are cached")
	} else {
		if cachedErr != nil && !errors.Is(cachedErr, os.ErrNotExist) && !bootstrapRemint {
			return fmt.Errorf("the Mac credential cache is incomplete or invalid: %w; rerun bootstrap --remint to recover and verify a replacement", cachedErr)
		}

		if err := bootstrapRecoverMacCredential(ctx, s, a, destination); err != nil {
			return err
		}
	}

	tui.Step(3, 3, "Verify Mac decryption readiness")

	report, err := verifiedMacCredential(destination)
	if err != nil {
		return err
	}

	tui.OK("Mac credential ready; prior plaintext verification covered %d encrypted images", report.EncryptedImages)
	// Activate only after all required steps succeed. The classic configuration,
	// its account and credentials remain intact for switching back.
	cfg.Flow = "mac"
	if err := cfg.Save(); err != nil {
		return err
	}

	tui.OK("bootstrap complete - run `ipadecrypt decrypt <app-id|bundle-id|url|local.ipa>`")

	return nil
}

func verifiedMacCredential(path string) (maccredential.Report, error) {
	var report maccredential.Report

	credential, err := fairplay.LoadCredential(path)
	if err != nil {
		return report, err
	}
	defer clear(credential)

	b, err := os.ReadFile(path + ".json")
	if err != nil {
		return report, err
	}

	if err = json.Unmarshal(b, &report); err != nil {
		return report, err
	}

	if !report.PlaintextVerified || report.OldCredentialRead || report.EncryptedImages == 0 ||
		report.MachOScanned == 0 || report.MachOCompared != report.MachOScanned ||
		report.CredentialHash != fmt.Sprintf("%x", sha256.Sum256(credential)) {
		return report, errors.New("the Mac credential lacks successful recovery verification")
	}

	return report, nil
}

func bootstrapRecoverMacCredential(ctx context.Context, s *macstore.Session, a store.Account, destination string) error {
	tui.Info("Creating fresh FairPlay state on this Mac, then verifying it against an app owned by this account.\nIf the selected app is not owned, only a free app can be acquired.")

	target, err := tui.Prompt("App for verification (ID, bundle ID or URL)")
	if err != nil {
		return err
	}

	catalog, err := macstore.Resolve(ctx, strings.TrimSpace(target), a.StoreFront)
	if err != nil {
		return err
	}

	ui := &macTransferUI{}
	defer ui.stop()

	ui.spin("checking app ownership")

	owned, err := macstore.Owned(ctx, s.Commerce(ctx), a)
	if err != nil {
		return err
	}

	if !macstore.HasApp(owned, catalog.App.ID) {
		ui.spin("acquiring free app license")

		if _, err = macstore.Purchase(ctx, s.Commerce(ctx), a, catalog, s.Root); err != nil {
			return err
		}
	}

	ui.spin("creating account FairPlay state (one-time)")

	sidb, hardware, err := s.Enroll(ctx, a, catalog)
	if err != nil {
		return err
	}
	defer clear(sidb)
	defer clear(hardware)

	ui.ok("account FairPlay state created")

	source, err := macstore.Download(ctx, s, a, catalog, false, ui.stage, ui.transfer)
	if err != nil {
		return err
	}

	if err = maccredential.MatchAccount(source, a.Email); err != nil {
		return err
	}

	if ui.cached {
		ui.ok("cached %s", filepath.Base(source))
	} else {
		ui.ok("downloaded %s", filepath.Base(source))
	}

	if err = os.MkdirAll(filepath.Dir(destination), 0700); err != nil {
		return err
	}

	stage, err := os.MkdirTemp(filepath.Dir(destination), ".enrollment-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)

	sidbPath, hardwarePath := filepath.Join(stage, "SC Info.sidb"), filepath.Join(stage, "iomac.bin")
	if err = macstore.WritePrivate(sidbPath, sidb); err != nil {
		return err
	}

	if err = macstore.WritePrivate(hardwarePath, hardware); err != nil {
		return err
	}

	candidate := filepath.Join(stage, "credential.bin")

	ui.spin("recovering credential (one-time)")

	_, err = maccredential.Recover(ctx, maccredential.Options{IPA: source, SIDB: sidbPath, Hardware: hardwarePath, Output: candidate, FreshEnrollment: true,
		Progress: func(stage string) {
			if strings.HasPrefix(stage, "Verifying") {
				ui.spin("verifying recovered credential")
			}
		},
	})
	if err != nil {
		return fmt.Errorf("the Mac credential recovery did not complete: %w", err)
	}

	if _, err = verifiedMacCredential(candidate); err != nil {
		return err
	}

	if err = ctx.Err(); err != nil {
		return err
	}

	if err = promoteMacCredential(candidate, destination); err != nil {
		return err
	}

	ui.ok("credential recovered, verified and cached")

	return nil
}

// Called under the Mac session lock, only after full recovery and verification.
// Preserve the previous pair; restore it if promotion fails partway through.
func promoteMacCredential(candidate, destination string) error {
	backup := destination + ".previous-" + fmt.Sprint(time.Now().UnixNano())

	var saved, installed []string

	rollback := func() {
		for _, suffix := range installed {
			_ = os.Remove(destination + suffix)
		}

		for _, suffix := range saved {
			_ = os.Rename(backup+suffix, destination+suffix)
		}
	}

	for _, suffix := range []string{".json", ""} {
		if _, err := os.Lstat(destination + suffix); err == nil {
			if err := os.Rename(destination+suffix, backup+suffix); err != nil {
				rollback()
				return err
			}

			saved = append(saved, suffix)
		} else if !errors.Is(err, os.ErrNotExist) {
			rollback()
			return err
		}
	}

	for _, suffix := range []string{".json", ""} {
		if err := os.Rename(candidate+suffix, destination+suffix); err != nil {
			rollback()
			return err
		}

		installed = append(installed, suffix)
	}

	return nil
}
