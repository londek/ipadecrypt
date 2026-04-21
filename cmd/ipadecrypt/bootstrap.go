package main

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/londek/ipadecrypt/internal/appstore"
	"github.com/londek/ipadecrypt/internal/config"
	"github.com/londek/ipadecrypt/internal/device"
	"github.com/londek/ipadecrypt/internal/tui"
	"github.com/spf13/cobra"
)

func bootstrapHandler(cmd *cobra.Command, args []string) error {
	ctx, cancel := notifyContext()
	defer cancel()

	cfg, paths, err := loadConfigOrDefault(cacheDirOverride)
	if err != nil {
		tui.Err("%v", err)
		return err
	}

	if bootstrapReset {
		cfg.Apple = config.Apple{}
		cfg.Device = config.Device{Port: 22, User: "mobile", AcceptNewHostKey: true}
		if err := cfg.Save(); err != nil {
			tui.Err("reset config: %v", err)
			return err
		}
	}

	// ---- Step 1: App Store sign-in -----------------------------------

	tui.Step(1, 4, "Sign in to the App Store")
	tui.Info("ipadecrypt downloads IPAs through Apple's Configurator endpoint, which\nrequires an Apple ID. Credentials are stored locally on this machine.")

	if cfg.Apple.Email == "" {
		s, err := tui.Prompt("Apple ID email")
		if err != nil {
			return err
		}
		cfg.Apple.Email = strings.TrimSpace(s)
	}

	if cfg.Apple.Password == "" {
		s, err := tui.PromptPassword("Apple ID password")
		if err != nil {
			return err
		}
		cfg.Apple.Password = s
	}

	as, err := appstore.New(filepath.Join(paths.Root, "cookies"))
	if err != nil {
		tui.Err("appstore client: %v", err)
		return err
	}

	var (
		acc      appstore.Account
		authCode string
		signedIn bool
	)
	for attempt := 0; attempt < 3 && !signedIn; attempt++ {
		live := tui.NewLive()
		live.Spin("authenticating")

		a, lerr := as.Login(cfg.Apple.Email, cfg.Apple.Password, authCode)
		switch {
		case errors.Is(lerr, appstore.ErrAuthCodeRequired):
			live.Stop()
			code, perr := tui.Prompt("Apple sent a 6-digit code — enter it")
			if perr != nil {
				return perr
			}
			authCode = strings.TrimSpace(code)

		case lerr != nil:
			live.Fail("login failed: %v", lerr)
			return lerr

		default:
			live.OK("authenticated")
			acc = a
			signedIn = true
		}
	}

	if !signedIn {
		tui.Err("login: 3 two-factor attempts failed")
		return errors.New("login: 3 two-factor attempts failed")
	}

	cfg.Apple.Account = &acc

	tui.Fields(
		"Apple ID", acc.Email,
		"Name", acc.Name,
		"Storefront", acc.StoreFront,
	)

	if err := cfg.Save(); err != nil {
		tui.Err("save config: %v", err)
		return err
	}

	// ---- Step 2: connect to device -----------------------------------

	tui.Step(2, 4, "Connect to the jailbroken device")
	tui.Info("ipadecrypt drives the iPhone over SSH. On the device install from Sileo:")
	tui.Bullet("OpenSSH   search \"OpenSSH\" in Sileo")
	tui.Info("Find the device IP in Settings → Wi-Fi → tap the ⓘ next to your network.")

	if cfg.Device.Host == "" {
		s, err := tui.Prompt("device IP/host")
		if err != nil {
			return err
		}
		cfg.Device.Host = strings.TrimSpace(s)
	}

	if cfg.Device.User == "" {
		u, err := tui.PromptDefault("device SSH user", "mobile")
		if err != nil {
			return err
		}
		cfg.Device.User = u
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
			pw, err := tui.PromptPassword("device's SSH password")
			if err != nil {
				return err
			}
			cfg.Device.Auth.Password = pw
		}
	}

	if cfg.Device.Port == 0 {
		cfg.Device.Port = 22
	}

	live := tui.NewLive()
	live.Spin("connecting to %s@%s", cfg.Device.User, cfg.Device.Host)
	dev, err := device.Connect(ctx, cfg.Device)
	if err != nil {
		live.Fail("ssh connect failed: %v", err)
		tui.Info("check that OpenSSH is running on the device and the password is correct")
		return err
	}

	live.Spin("probing device")
	probe, err := dev.Probe()
	if err != nil {
		live.Fail("probe failed: %v", err)
		dev.Close()
		return err
	}

	if err := cfg.Save(); err != nil {
		live.Fail("save config: %v", err)
		dev.Close()
		return err
	}

	live.OK("connected")
	dev.Close()

	tui.Fields(
		"Host", fmt.Sprintf("%s@%s", cfg.Device.User, cfg.Device.Host),
		"iOS", probe.IOSVersion,
		"Arch", probe.Arch,
		"Model", probe.Model,
	)

	// ---- Step 3: device prerequisites --------------------------------

	tui.Step(3, 4, "Install device prerequisites")
	tui.Info("ipadecrypt needs these packages on the jailbroken device:")
	tui.Bullet("AppSync Unified   bypasses installd's signature check")
	tui.Bullet("                  add repo: https://lukezgd.github.io/repo")
	tui.Bullet("appinst           installs modified IPAs on the device")
	tui.Bullet("zip               packages the decrypted IPA on-device")
	tui.Info("A reboot may be needed after installing; that's fine, we'll reconnect.")

	prevLines := 0
	prompt := "press Enter once installed to verify"

	for {
		if prevLines > 0 {
			tui.Erase(prevLines)
		}

		// Fresh SSH connection each iteration so a reboot mid-bootstrap is safe.
		printed := 0
		missing := 0
		var connErr error

		pdev, perr := device.Connect(ctx, cfg.Device)
		if perr != nil {
			tui.Err("ssh connect failed: %v", perr)
			printed = 1
			connErr = perr
		} else {
			checks := []struct {
				name  string
				probe func() (string, error)
			}{
				{"AppSync Unified", pdev.LocateAppSync},
				{"appinst", pdev.LocateAppinst},
				{"zip", func() (string, error) { return pdev.LocateBinary("zip") }},
			}
			for _, c := range checks {
				p, err := c.probe()
				switch {
				case err != nil:
					tui.Err("%s — %v", c.name, err)
					missing++
				case p == "":
					tui.Err("%s — not found", c.name)
					missing++
				default:
					tui.OK("%s → %s", c.name, p)
				}
				printed++
			}
			pdev.Close()
		}

		if connErr == nil && missing == 0 {
			break
		}

		if perr := tui.PressEnter(prompt); perr != nil {
			return perr
		}

		// Status rows + prompt row + Enter-echo row.
		prevLines = printed + 2

		if connErr != nil {
			prompt = "press Enter to retry"
		} else {
			prompt = fmt.Sprintf("%d missing — press Enter to retry", missing)
		}
	}

	// ---- Step 4: helper upload + verify ------------------------------

	tui.Step(4, 4, "Install the decrypt helper")
	tui.Info("A small embedded C binary that reads FairPlay-decrypted pages from a\nsuspended task. Uploaded once to /var/mobile/Media/ipadecrypt/helpers/\nand cached by SHA thereafter.")

	dev, err = device.Connect(ctx, cfg.Device)
	if err != nil {
		tui.Err("ssh connect failed: %v", err)
		return err
	}

	defer dev.Close()

	live = tui.NewLive()
	live.Spin("uploading helper binary")
	helperPath, err := dev.EnsureHelper()
	if err != nil {
		live.Fail("upload failed: %v", err)
		return err
	}

	live.Spin("verifying helper can exec")
	if err := dev.VerifyHelper(helperPath); err != nil {
		live.Fail("verify failed: %v", err)
		tui.Info("the device's code-signing layer rejected the helper's entitlements")
		return err
	}

	live.OK("helper ready at %s", helperPath)

	tui.Spacer()
	tui.OK("bootstrap complete — run `ipadecrypt decrypt <bundle-id>` to decrypt an app")

	return nil
}
