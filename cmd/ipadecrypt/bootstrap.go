package main

import (
	"context"
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

func bootstrapHandler(cmd *cobra.Command, args []string) {
	cfg, paths, err := loadConfigOrDefault(rootDirOverride)
	if err != nil {
		tui.Err("%v", err)
		return
	}

	if bootstrapReset {
		cfg.Apple = config.Apple{}
		cfg.Device = config.Device{Port: 22, User: "mobile", AcceptNewHostKey: true}
		if err := cfg.Save(); err != nil {
			tui.Err("reset config: %v", err)
			return
		}
	}

	// ---- Step 1: App Store sign-in -----------------------------------

	tui.Step(1, 4, "Sign in to the App Store")
	tui.Info("ipadecrypt requires an Apple ID to download .ipas.\nIt has to the be same Apple ID used on the jailbroken device.\nCredentials are stored locally on this machine.")

	if cfg.Apple.Email == "" {
		s, err := tui.Prompt("Apple ID email")
		if err != nil {
			return
		}
		cfg.Apple.Email = strings.TrimSpace(s)
	}

	if cfg.Apple.Password == "" {
		s, err := tui.PromptPassword("Apple ID password")
		if err != nil {
			return
		}
		cfg.Apple.Password = s
	}

	as, err := appstore.New(filepath.Join(paths.Root, "cookies"))
	if err != nil {
		tui.Err("appstore client: %v", err)
		return
	}

	var (
		account  *appstore.Account
		authCode string
	)
	for attempt := 0; attempt < 3 && account == nil; attempt++ {
		live := tui.NewLive()
		live.Spin("authenticating")

		account, err = as.Login(cfg.Apple.Email, cfg.Apple.Password, authCode)
		switch {
		case errors.Is(err, appstore.ErrAuthCodeRequired):
			live.Stop()

			code, err := tui.Prompt("Apple sent a 6-digit code - enter it")
			if err != nil {
				return
			}

			authCode = strings.TrimSpace(code)

		case err != nil:
			live.Fail("login failed: %v", err)
			return

		default:
			live.OK("authenticated")
		}
	}

	if account == nil {
		tui.Err("login: 3 two-factor attempts failed")
		return
	}

	cfg.Apple.Account = account

	tui.Fields(
		"Apple ID", account.Email,
		"Name", account.Name,
		"Storefront", account.StoreFront,
	)

	if err := cfg.Save(); err != nil {
		tui.Err("save config: %v", err)
		return
	}

	// ---- Step 2: connect to device -----------------------------------

	tui.Step(2, 4, "Connect to the jailbroken device")
	tui.Info("ipadecrypt drives the iPhone over SSH. On the device install from Sileo:")
	tui.Bullet("OpenSSH   search \"OpenSSH\" in Sileo")
	tui.Info("Find the device IP in Settings → Wi-Fi.")

	if cfg.Device.Host == "" {
		s, err := tui.Prompt("device IP/host")
		if err != nil {
			return
		}
		cfg.Device.Host = strings.TrimSpace(s)
	}

	if cfg.Device.User == "" {
		u, err := tui.PromptDefault("device SSH user", "mobile")
		if err != nil {
			return
		}
		cfg.Device.User = u
	}

	if cfg.Device.Auth.Kind == "" {
		idx, err := tui.Select("authentication method", []string{
			"password",
			"SSH public key",
		})
		if err != nil {
			return
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
				return
			}

			cfg.Device.Auth.KeyPath = strings.TrimSpace(p)
		}

		if cfg.Device.Auth.KeyPassphrase == "" {
			pass, err := tui.PromptPassword("key passphrase (leave empty if unencrypted)")
			if err != nil {
				return
			}

			cfg.Device.Auth.KeyPassphrase = pass
		}

		if cfg.Device.Auth.Password == "" && cfg.Device.User != "root" {
			pw, err := tui.PromptPassword("sudo password (leave empty if not needed)")
			if err != nil {
				return
			}

			cfg.Device.Auth.Password = pw
		}

	default:
		if cfg.Device.Auth.Password == "" {
			pw, err := tui.PromptPassword("device SSH password")
			if err != nil {
				return
			}

			cfg.Device.Auth.Password = pw
		}
	}

	if cfg.Device.Port == 0 {
		cfg.Device.Port = 22
	}

	var probe device.ProbeResult
	connected := false
	func() {
		live := tui.NewLive()
		live.Spin("connecting to %s@%s", cfg.Device.User, cfg.Device.Host)

		dev, err := device.Connect(context.Background(), cfg.Device)
		if err != nil {
			live.Fail("ssh connect failed: %v", err)
			tui.Info("check that OpenSSH is running on the device and the password is correct")
			return
		}
		defer dev.Close()

		live.Spin("probing device")
		probe, err = dev.Probe()
		if err != nil {
			live.Fail("probe failed: %v", err)
			return
		}

		if err := cfg.Save(); err != nil {
			live.Fail("save config: %v", err)
			return
		}

		live.OK("connected")
		connected = true
	}()
	if !connected {
		return
	}

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
		connectionFailed := false

		pdev, err := device.Connect(context.Background(), cfg.Device)
		if err != nil {
			tui.Err("ssh connect failed: %v", err)
			printed = 1
			connectionFailed = true
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
					tui.Err("%s - %v", c.name, err)
					missing++
				case p == "":
					tui.Err("%s - not found", c.name)
					missing++
				default:
					tui.OK("%s → %s", c.name, p)
				}
				printed++
			}
			pdev.Close()
		}

		if !connectionFailed && missing == 0 {
			break
		}

		if err := tui.PressEnter(prompt); err != nil {
			return
		}

		// Status rows + prompt row + Enter-echo row.
		prevLines = printed + 2

		if connectionFailed {
			prompt = "press Enter to retry"
		} else {
			prompt = fmt.Sprintf("%d missing - press Enter to retry", missing)
		}
	}

	// ---- Step 4: helper upload + verify ------------------------------

	tui.Step(4, 4, "Install the decrypt helper")
	tui.Info("A small embedded C binary that reads FairPlay-decrypted pages from a\nsuspended task. Uploaded once to /var/mobile/Media/ipadecrypt/helpers/\nand cached by SHA thereafter.")

	dev, err := device.Connect(context.Background(), cfg.Device)
	if err != nil {
		tui.Err("ssh connect failed: %v", err)
		return
	}

	defer dev.Close()

	live := tui.NewLive()
	live.Spin("uploading helper binary")
	helperPath, err := dev.EnsureHelper()
	if err != nil {
		live.Fail("upload failed: %v", err)
		return
	}

	live.Spin("verifying helper can exec")
	if err := dev.VerifyHelper(helperPath); err != nil {
		live.Fail("verify failed: %v", err)
		tui.Info("the device's code-signing layer rejected the helper's entitlements")
		return
	}

	live.OK("helper ready at %s", helperPath)

	tui.Spacer()
	tui.OK("bootstrap complete - run `ipadecrypt decrypt <bundle-id|app-store-id|app-store-url|path-to-local-ipa>` to decrypt an app")
}
