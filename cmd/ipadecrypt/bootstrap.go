package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/londek/ipadecrypt/internal/appstore"
	"github.com/londek/ipadecrypt/internal/config"
	"github.com/londek/ipadecrypt/internal/credmint"
	"github.com/londek/ipadecrypt/internal/device"
	"github.com/londek/ipadecrypt/internal/iphonesetup"
	"github.com/londek/ipadecrypt/internal/tui"
	"github.com/londek/ipadecrypt/internal/updater"
	"github.com/spf13/cobra"
)

func bootstrapDeviceHandler(cmd *cobra.Command, args []string, flow string) error {
	cfg, paths, err := loadConfigOrDefault(rootDirOverride)
	if err != nil {
		return err
	}

	previous, err := savedFlow(cfg)
	if err != nil {
		return err
	}

	cfg.Flow = previous

	upd := updater.Start(context.Background(), resolveVersion(), cfg)
	defer upd.Wait()

	if bootstrapReset {
		cfg.Apple = config.Apple{}
		cfg.Device = config.Device{Port: 22}
		cfg.Anisette = config.Anisette{}

		if err := cfg.Save(); err != nil {
			return fmt.Errorf("reset config: %w", err)
		}

		if err := resetFrameworkAuthentication(paths.Root); err != nil {
			return err
		}
	}

	if err := applyDeviceFlow(cfg, flow); err != nil {
		return err
	}

	// ---- Step 1: App Store sign-in -----------------------------------

	if bootstrapSkipLogin {
		tui.Step(1, 3, "Sign in to the App Store (skipped)")
		tui.Info("skipped - App Store downloads and credential minting are disabled.\nYou can still decrypt a local .ipa if a credential is already cached.")

		cfg.Flow = flow
		if err := cfg.Save(); err != nil {
			return err
		}

		tui.Spacer()
		tui.OK("bootstrap complete")

		return nil
	}

	if flow == flowSnapshot {
		if err := (iphonesetup.Setup{PromptDevice: promptMintDevice}).ConfigureSnapshot(cfg, paths); err != nil {
			return fmt.Errorf("configure offline anisette: %w", err)
		}
	}

	if err := cfg.Save(); err != nil {
		return fmt.Errorf("save config: %w", err)
	}

	tui.Step(1, 3, "Sign in to the App Store")
	tui.Info("ipadecrypt needs an Apple ID to download .ipas and to mint your\ndecryption credential. Use the same Apple ID that owns apps on your\njailbroken device. Credentials are stored locally on this machine.")

	account, err := bootstrapSignIn(cfg, paths)
	if err != nil {
		return err
	}

	if account == nil {
		return errors.New("sign-in did not return an account")
	}

	// ---- Step 2: one-time credential mint ----------------------------

	tui.Step(2, 3, "Mint your decryption credential (one-time)")

	dsid := cfg.Apple.DirectoryServicesIdentifier
	if dsid == "" {
		return errors.New("sign-in did not return an account identifier; cannot mint")
	}

	if credentialCached(paths, dsid, false) && !bootstrapRemint {
		tui.OK("credential already cached for this account")
		tui.Info("pass --remint to replace it")
	} else {
		tui.Info("This connects once to your jailbroken device to extract a reusable\n16-byte account key. After this, every decrypt runs offline - no device.")
		tui.Info("Requirements on the device:")
		tui.Bullet("SSH (OpenSSH from Sileo) as root or a sudo user like mobile, reachable over the network or USB")
		tui.Bullet("at least one App Store app bought with this Apple ID, installed")
		tui.Bullet("optionally an Apple Arcade app from this Apple ID, to also decrypt Arcade apps")

		if err := promptMintDevice(cfg, false); err != nil {
			return err
		}

		if err := cfg.Save(); err != nil {
			return fmt.Errorf("save config: %w", err)
		}

		live := tui.NewLive()
		live.Spin("minting credential (one-time)")

		credential, err := credmint.Mint(context.Background(), cfg.Device, dsid, false)
		if err != nil {
			if errors.Is(err, credmint.ErrBinariesUnavailable) {
				live.Fail("this build cannot mint credentials")
				tui.Info("the device binaries aren't compiled into this build; install an official release")

				return err
			}

			live.Fail("mint failed")

			return err
		}

		if err := saveCredential(paths, dsid, false, credential); err != nil {
			live.Fail("cache credential failed")
			return err
		}

		live.OK("credential minted and cached")

		mintArcadeCredential(cfg, paths, dsid)
	}

	// ---- Step 3: on-device decrypt fallback readiness ----------------

	verifyDeviceDecryptReady(cfg)

	tui.Spacer()

	cfg.Flow = flow
	if err := cfg.Save(); err != nil {
		return fmt.Errorf("save selected flow: %w", err)
	}

	tui.OK("bootstrap complete - run `ipadecrypt decrypt <bundle-id|app-store-id|app-store-url|path-to-local-ipa>`")

	return nil
}

// mintArcadeCredential mints the account's Apple Arcade credential when an
// Arcade app from it is installed on the device. Only Arcade apps need it, so
// it never fails bootstrap.
func mintArcadeCredential(cfg *config.Config, paths *config.Paths, dsid string) {
	live := tui.NewLive()
	live.Spin("minting Apple Arcade credential")

	credential, err := credmint.Mint(context.Background(), cfg.Device, dsid, true)

	switch {
	case errors.Is(err, credmint.ErrNoArcadeApp):
		live.Stop()
		tui.Info("no Apple Arcade app from this Apple ID is installed - skipped the Arcade credential.\nOnly Arcade apps need it: install one and re-run `ipadecrypt bootstrap --remint`.")
	case err != nil:
		live.Fail("Arcade credential mint failed: %v", err)
		tui.Info("regular App Store apps are unaffected; only Apple Arcade apps need this credential")
	default:
		if err := saveCredential(paths, dsid, true, credential); err != nil {
			live.Fail("cache Arcade credential: %v", err)
			return
		}

		live.OK("Apple Arcade credential minted and cached")
	}
}

// verifyDeviceDecryptReady checks that the configured device can serve the
// on-device decrypt fallback - the path that handles apps the offline
// decryptor can't (e.g. an unsupported SINF/SUPF format). It confirms
// AppSync Unified + appinst are present and that the embedded helper uploads
// and execs. It is best-effort: offline decryption works regardless, so a
// missing prerequisite only disables the fallback and never fails bootstrap.
func verifyDeviceDecryptReady(cfg *config.Config) {
	tui.Step(3, 3, "Verify on-device decrypt fallback")

	if cfg.Device.Host == "" && !cfg.Device.USB {
		tui.Info("no device configured - skipping; apps the offline decryptor can't handle won't be decryptable until you set one up")
		return
	}

	tui.Info("A few apps can't be decrypted offline; ipadecrypt falls back to\ndecrypting them on this device. That needs two Sileo packages - offline\ndecryption works without them:")
	tui.Bullet("AppSync Unified   bypasses installd's signature check (repo: https://lukezgd.github.io/repo)")
	tui.Bullet("appinst           installs the patched IPA on the device")

	live := tui.NewLive()
	live.Spin("connecting to the device")

	dev, err := device.Connect(context.Background(), cfg.Device)
	if err != nil {
		live.Fail("connect failed: %v", err)
		tui.Info("the on-device fallback won't work until the device is reachable; offline decryption is unaffected")

		return
	}

	defer dev.Close()

	live.OK("connected")

	if err := ensureDeviceSudo(cfg, dev); err != nil {
		tui.Err("sudo as %s failed: %v", cfg.Device.User, err)
		tui.Info("the on-device fallback won't work until sudo does; offline decryption is unaffected")

		return
	}

	missing := 0

	checks := []struct {
		name  string
		probe func() (string, error)
	}{
		{"AppSync Unified", dev.LocateAppSync},
		{"appinst", dev.LocateAppinst},
	}
	for _, c := range checks {
		p, err := c.probe()
		switch {
		case err != nil:
			tui.Err("%s - %v", c.name, err)

			missing++
		case p == "":
			tui.Err("%s - not found", c.name)

			missing++
		default:
			tui.OK("%s → %s", c.name, p)
		}
	}

	live = tui.NewLive()
	live.Spin("uploading decrypt helper")

	helperPath, err := dev.EnsureHelper()
	if err != nil {
		live.Fail("helper upload failed: %v", err)

		missing++
	} else {
		live.Spin("verifying helper can exec")

		if err := dev.VerifyHelper(helperPath); err != nil {
			live.Fail("helper verify failed: %v", err)

			missing++
		} else {
			live.OK("helper ready at %s", helperPath)
		}
	}

	if missing > 0 {
		tui.Warn("on-device fallback not ready (%d issue(s)) - apps that can't be decrypted offline will fail until it's fixed", missing)
		tui.Info("offline decryption is unaffected; this only matters for the few apps it can't handle")

		return
	}

	tui.OK("on-device fallback ready")
}

// bootstrapSignIn runs the interactive App Store login, persisting the
// account into cfg. Returns (nil, nil) when the user aborted a prompt.
func bootstrapSignIn(cfg *config.Config, paths *config.Paths) (*appstore.Account, error) {
	email := cfg.Apple.Email
	password := cfg.Apple.Password

	if email == "" {
		s, err := tui.Prompt("Apple ID email")
		if err != nil {
			return nil, nil
		}

		email = strings.TrimSpace(s)
	}

	if password == "" {
		s, err := tui.PromptPassword("Apple ID password")
		if err != nil {
			return nil, nil
		}

		password = s
	}

	as, err := iphonesetup.NewClient(cfg, paths)
	if err != nil {
		return nil, fmt.Errorf("appstore client: %w", err)
	}

	signing, err := (iphonesetup.Setup{PromptDevice: promptMintDevice}).PrepareSigning(cfg)
	if err != nil {
		return nil, fmt.Errorf("prepare native signing: %w", err)
	}
	defer signing.Close()

	if err := signing.Configure(as); err != nil {
		return nil, err
	}

	tui.Info("The first sign-in runs a one-time machine-signing step and can take a few minutes.")

	var (
		account  *appstore.Account
		authCode string
	)

	for attempt := 0; attempt < 3 && account == nil; attempt++ {
		live := tui.NewLive()
		live.Spin("authenticating")

		account, err = as.SignIn(email, password, authCode)
		switch {
		case errors.Is(err, appstore.ErrAuthCodeRequired):
			live.Stop()

			code, perr := tui.Prompt("Apple sent a 6-digit code - enter it")
			if perr != nil {
				return nil, nil
			}

			authCode = strings.TrimSpace(code)

		case err != nil:
			live.Fail("sign-in failed")
			return nil, err

		default:
			live.OK("authenticated")
		}
	}

	if account == nil {
		return nil, errors.New("login: 3 two-factor attempts failed")
	}

	cfg.Apple.SetAccount(account)

	appStoreCountry, err := appstore.CountryCodeFromStoreFront(account.StoreFront)
	if err != nil {
		return nil, fmt.Errorf("resolve appstore country code: %w", err)
	}

	tui.Fields(
		"Apple ID", redact(account.Email),
		"Name", account.Name,
		"Storefront", fmt.Sprintf("%s (%s)", redact(account.StoreFront), redact(appStoreCountry)),
	)

	if err := cfg.Save(); err != nil {
		return nil, fmt.Errorf("save config: %w", err)
	}

	return account, nil
}

// promptMintDevice fills in cfg.Device for operations that need the jailbroken
// device. confirmUser also prompts when a user is already configured. Returns
// a non-nil error only to signal a user abort.
func promptMintDevice(cfg *config.Config, confirmUser bool) error {
	if cfg.Device.Host == "" && !cfg.Device.USB {
		idx, err := tui.Select("how is the device connected?", []string{
			"Network (device IP over Wi-Fi)",
			"USB (via iproxy)",
		})
		if err != nil {
			return err
		}

		cfg.Device.USB = idx == 1
	}

	if cfg.Device.USB {
		if cfg.Device.UDID == "" {
			u, err := tui.PromptDefault("device UDID (leave empty if only one is connected)", "")
			if err != nil {
				return err
			}

			cfg.Device.UDID = strings.TrimSpace(u)
		}

		if cfg.Device.Port == 0 {
			cfg.Device.Port = 2222
		}
	} else if cfg.Device.Host == "" {
		s, err := tui.Prompt("device IP/host")
		if err != nil {
			return err
		}

		cfg.Device.Host = strings.TrimSpace(s)
	}

	if cfg.Device.User == "" || confirmUser {
		defaultUser := cfg.Device.User
		if defaultUser == "" {
			defaultUser = "mobile"
		}

		u, err := tui.PromptDefault("device SSH user (root, or one that can sudo)", defaultUser)
		if err != nil {
			return err
		}

		cfg.Device.User = strings.TrimSpace(u)
	}

	if cfg.Device.Auth.Kind == "" {
		idx, err := tui.Select("authentication method", []string{
			"password",
			"SSH public key",
		})
		if err != nil {
			return err
		}

		if idx == 1 {
			cfg.Device.Auth.Kind = "key"
		} else {
			cfg.Device.Auth.Kind = "password"
		}
	}

	switch cfg.Device.Auth.Kind {
	case "key":
		if cfg.Device.Auth.KeyPath == "" {
			p, err := tui.PromptDefault("SSH private key path", "~/.ssh/id_ed25519")
			if err != nil {
				return err
			}

			cfg.Device.Auth.KeyPath = strings.TrimSpace(p)
		}

		if cfg.Device.Auth.KeyPassphrase == "" {
			pass, err := tui.PromptPassword("key passphrase (leave empty if unencrypted)")
			if err != nil {
				return err
			}

			cfg.Device.Auth.KeyPassphrase = pass
		}

		if cfg.Device.Auth.Password == "" && cfg.Device.User != "root" {
			pw, err := tui.PromptPassword("sudo password (leave empty if not needed)")
			if err != nil {
				return err
			}

			cfg.Device.Auth.Password = pw
		}

	default:
		if cfg.Device.Auth.Password == "" {
			pw, err := tui.PromptPassword("device SSH password")
			if err != nil {
				return err
			}

			cfg.Device.Auth.Password = pw
		}
	}

	if cfg.Device.Port == 0 {
		cfg.Device.Port = 22
	}

	return nil
}

// Reset supported authentication files while preserving snapshot directories.
func resetFrameworkAuthentication(root string) error {
	for _, name := range []string{appstore.AnisetteFile, "anisette"} {
		path := filepath.Join(root, name)

		info, err := os.Stat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}

		if err != nil {
			return fmt.Errorf("inspect Apple authentication state: %w", err)
		}

		if info.IsDir() && name == "anisette" {
			continue
		}

		if err := os.Remove(path); err != nil {
			return fmt.Errorf("reset Apple authentication state: %w", err)
		}
	}

	return nil
}
