package main

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"

	"github.com/londek/ipadecrypt/internal/appstore"
	"github.com/londek/ipadecrypt/internal/device"
	"github.com/londek/ipadecrypt/internal/pipeline"
	"github.com/londek/ipadecrypt/internal/tui"
	"github.com/spf13/cobra"
)

var appStoreIDRe = regexp.MustCompile(`/id(\d+)`)

type decryptTarget struct {
	// localPath is set when the user passed a path to an existing .ipa.
	// When set, the App Store download flow is skipped.
	localPath string
	// lookupID is a bundle ID or numeric App Store trackId to resolve
	// against iTunes lookup. Set when localPath is empty.
	lookupID string
}

func parseDecryptArg(raw string) (decryptTarget, error) {
	// App Store URL
	if strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://") {
		u, err := url.Parse(raw)
		if err != nil {
			return decryptTarget{}, fmt.Errorf("parse url: %w", err)
		}
		m := appStoreIDRe.FindStringSubmatch(u.Path)
		if m == nil {
			return decryptTarget{}, fmt.Errorf("no /id<digits> in url %s", raw)
		}
		return decryptTarget{lookupID: m[1]}, nil
	}

	// Local .ipa path
	if strings.HasSuffix(strings.ToLower(raw), ".ipa") {
		if info, err := os.Stat(raw); err == nil && !info.IsDir() {
			abs, aerr := filepath.Abs(raw)
			if aerr != nil {
				return decryptTarget{}, aerr
			}
			return decryptTarget{localPath: abs}, nil
		}
	}

	return decryptTarget{lookupID: raw}, nil
}

func decryptHandler(cmd *cobra.Command, args []string) error {
	ctx, cancel := notifyContext()
	defer cancel()

	cfg, paths, err := loadConfigOrDefault(cacheDirOverride)
	if err != nil {
		tui.Err("%v", err)
		return err
	}

	target, err := parseDecryptArg(args[0])
	if err != nil {
		tui.Err("%v", err)
		return err
	}

	if cfg.Device.Host == "" {
		tui.Err("bootstrap not completed")
		tui.Info("run `ipadecrypt bootstrap` first to verify your device")
		return errors.New("bootstrap not completed")
	}
	if target.localPath == "" && cfg.Apple.Account == nil {
		tui.Err("bootstrap not completed")
		tui.Info("run `ipadecrypt bootstrap` first to sign in to the App Store")
		return errors.New("bootstrap not completed")
	}

	var as *appstore.Client
	if target.localPath == "" {
		as, err = appstore.New(filepath.Join(paths.Root, "cookies"))
		if err != nil {
			tui.Err("appstore client: %v", err)
			return err
		}
		tui.OK("signed in as %s", cfg.Apple.Account.Email)
	} else {
		tui.OK("local IPA %s", filepath.Base(target.localPath))
	}

	// --- connect ---
	live := tui.NewLive()
	live.Spin("connecting to %s@%s", cfg.Device.User, cfg.Device.Host)
	dev, err := device.Connect(ctx, cfg.Device)
	if err != nil {
		live.Fail("ssh connect failed")
		tui.Err("ssh: %v", err)
		return err
	}
	defer dev.Close()

	live.Spin("probing device")
	probe, err := dev.Probe()
	if err != nil {
		live.Fail("probe failed")
		tui.Err("probe device: %v", err)
		return err
	}
	live.OK("%s@%s iOS %s %s", cfg.Device.User, cfg.Device.Host, probe.IOSVersion, probe.Arch)

	// --- resolve app metadata ---
	var (
		app     appstore.App
		encPath string
	)

	if target.localPath != "" {
		bid, ver, aerr := pipeline.AppInfo(target.localPath)
		if aerr != nil {
			tui.Err("read IPA: %v", aerr)
			return aerr
		}
		app.BundleID = bid
		app.Version = ver
		encPath = target.localPath
		tui.OK("%s v%s", app.BundleID, app.Version)
	} else {
		live = tui.NewLive()
		live.Spin("resolving %s", target.lookupID)
		a, lerr := as.Lookup(*cfg.Apple.Account, target.lookupID)
		if lerr != nil {
			live.Fail("lookup failed")
			tui.Err("lookup: %v", lerr)
			return lerr
		}
		if a.Price > 0 {
			live.Fail("paid app (price=%v) - unsupported", a.Price)
			return errors.New("paid apps not supported")
		}
		app = a
		live.OK("%s v%s", app.BundleID, app.Version)

		encPath, err = paths.EncryptedIPA(app.BundleID, app.ID, app.Version)
		if err != nil {
			tui.Err("%v", err)
			return err
		}
	}

	// --- download (retry on token expiry + auto-purchase on missing license) ---
	_, encStatErr := os.Stat(encPath)
	switch {
	case target.localPath != "":
		// skip download, use user-provided IPA directly
	case encStatErr == nil:
		tui.OK("cached %s", filepath.Base(encPath))
	default:
		cacheDir, _ := paths.CacheDir()
		live = tui.NewLive()
		live.Spin("downloading IPA")

		reauth := func() error {
			live.Spin("re-authenticating")
			acc, lerr := as.Login(cfg.Apple.Email, cfg.Apple.Password, "")
			if lerr != nil {
				live.Fail("re-auth failed: %v", lerr)
				return lerr
			}
			cfg.Apple.Account = &acc
			if serr := cfg.Save(); serr != nil {
				live.Fail("save config: %v", serr)
				return serr
			}
			return nil
		}

		downloaded := false
		for tries := 0; tries < 3 && !downloaded; tries++ {
			out, err := as.Download(*cfg.Apple.Account, app, cacheDir, decryptExtVerID)
			switch {
			case err == nil:
				if out.DestinationPath != encPath {
					if rerr := os.Rename(out.DestinationPath, encPath); rerr != nil {
						live.Fail("rename cache failed")
						tui.Err("rename cache: %v", rerr)
						return rerr
					}
				}
				live.OK("downloaded %s", filepath.Base(encPath))
				downloaded = true

			case errors.Is(err, appstore.ErrPasswordTokenExpired):
				if rerr := reauth(); rerr != nil {
					return rerr
				}
				live.Spin("retrying download")

			case errors.Is(err, appstore.ErrLicenseRequired):
				live.Spin("acquiring license")
				perr := as.Purchase(*cfg.Apple.Account, app)
				if errors.Is(perr, appstore.ErrPasswordTokenExpired) {
					if rerr := reauth(); rerr != nil {
						return rerr
					}
					live.Spin("acquiring license")
					perr = as.Purchase(*cfg.Apple.Account, app)
				}
				if perr != nil && !errors.Is(perr, appstore.ErrLicenseAlreadyExists) {
					live.Fail("purchase failed: %v", perr)
					return perr
				}
				live.Spin("retrying download")

			default:
				live.Fail("download failed")
				tui.Err("download: %v", err)
				return err
			}
		}

		if !downloaded {
			live.Fail("exhausted retries")
			return errors.New("download: exhausted retries")
		}
	}

	// --- MinOS patch ---
	uploadPath := encPath
	patchedPath := ""
	tmp := filepath.Join(filepath.Dir(encPath),
		strings.TrimSuffix(filepath.Base(encPath), ".ipa")+"-minos.tmp.ipa")

	live = tui.NewLive()
	live.Spin("patching Info.plist for MinimumOSVersion %s", probe.IOSVersion)
	changed, previous, err := pipeline.PatchMinOS(encPath, tmp, probe.IOSVersion)
	if err != nil {
		live.Fail("patch MinOS failed")
		_ = os.Remove(tmp)
		tui.Err("patch MinOS: %v", err)
		return err
	}
	if changed {
		uploadPath = tmp
		patchedPath = tmp
		live.OK("MinimumOSVersion %s → %s", previous, probe.IOSVersion)
	} else {
		_ = os.Remove(tmp)
		live.OK("no MinOS change needed")
	}

	// --- install (or detect existing) ---
	appDirName, err := pipeline.AppDirName(uploadPath)
	if err != nil {
		tui.Err("read IPA: %v", err)
		return err
	}

	helperPath, err := dev.EnsureHelper()
	if err != nil {
		tui.Err("helper upload: %v", err)
		return err
	}

	appinst, err := dev.LocateAppinst()
	if err != nil {
		tui.Err("locate appinst: %v", err)
		return err
	}

	if appinst == "" {
		tui.Err("appinst not found on device - run `ipadecrypt bootstrap`")
		return errors.New("appinst not found")
	}

	bundlePath, err := dev.FindInstalled(helperPath, appDirName)
	if err != nil {
		tui.Err("scan installed: %v", err)
		return err
	}

	stagingRemote := filepath.ToSlash(
		filepath.Join(device.RemoteRoot, "staging", filepath.Base(uploadPath)))

	if bundlePath == "" {
		live = tui.NewLive()
		live.Spin("uploading IPA to device")
		if err := dev.Upload(uploadPath, stagingRemote); err != nil {
			live.Fail("upload failed")
			tui.Err("upload: %v", err)
			return err
		}

		live.Spin("running appinst")
		if err := dev.Install(appinst, stagingRemote); err != nil {
			live.Fail("install failed")
			tui.Err("install: %v", err)
			return err
		}

		bundlePath, err = dev.FindInstalled(helperPath, appDirName)
		if err != nil {
			live.Fail("post-install scan failed")
			tui.Err("post-install scan: %v", err)
			return err
		}
		if bundlePath == "" {
			live.Fail("install reported success but bundle not found")
			return errors.New("install reported success but bundle not found")
		}
		live.OK("installed → %s", bundlePath)
	} else {
		// Something's already installed at the expected bundle name - but
		// that could be a different version or something our tooling (or
		// the user) tampered with. Verify the main executable's SHA-256
		// matches the IPA we'd otherwise upload before trusting it.
		live = tui.NewLive()
		live.Spin("verifying installed bundle matches IPA")

		execName, wantSum, herr := pipeline.MainExecSHA256(uploadPath)
		if herr != nil {
			live.Fail("hash IPA failed")
			tui.Err("hash ipa: %v", herr)
			return herr
		}

		remoteExec := filepath.ToSlash(filepath.Join(bundlePath, execName))

		gotSum, herr := dev.HashFile(helperPath, remoteExec)
		if herr != nil {
			live.Fail("hash device failed")
			tui.Err("hash device: %v", herr)

			return herr
		}

		if gotSum != wantSum {
			live.Fail("installed bundle differs from IPA")
			tui.Err("sha256 mismatch: IPA=%s device=%s", wantSum[:12]+"…", gotSum[:12]+"…")
			tui.Info("uninstall the app on the device (or delete %s) and re-run", bundlePath)

			return errors.New("installed bundle sha256 mismatch")
		}

		live.OK("already installed → %s", bundlePath)
	}

	// --- decrypt via helper ---
	outRemote := filepath.ToSlash(
		filepath.Join(device.RemoteRoot, "work",
			fmt.Sprintf("%s_%s.ipa", app.BundleID, app.Version)))

	if err := dev.Mkdir(filepath.Dir(outRemote)); err != nil {
		tui.Err("mkdir work: %v", err)
		return err
	}

	live = tui.NewLive()
	live.Spin("starting helper")

	var (
		planTotal        atomic.Int64
		planDone         atomic.Int64
		dumpedTotal      int64
		dumpedMain       int64
		dumpedFrameworks int64
		dumpedOther      int64
		pluginCount      int64
	)

	onEvent := func(ev device.Event) {
		switch ev.Name {
		case "bundle":
			live.Spin("analyzing main bundle")
		case "plugin_start":
			pluginCount++
			live.Note("found extension %s", ev.Attr("name"))
			live.Spin("decrypting extension %s", ev.Attr("name"))
		case "spawn_failed":
			live.Note("could not spawn %s (skipped)", ev.Attr("name"))
		case "spawn_chmod":
			live.Note("chmod +x on %s (was mode %s) to unblock spawn",
				filepath.Base(ev.Attr("path")), ev.Attr("old_mode"))
		case "main":
			live.Spin("decrypting main executable: %s", ev.Attr("name"))
		case "dyld":
			switch ev.Attr("state") {
			case "resuming":
				live.Spin("letting dyld map frameworks")
			case "crashed":
				live.Note("dyld crashed on a missing iOS symbol - frameworks mapped, proceeding")
			}
		case "plan":
			var n int64
			fmt.Sscanf(ev.Attr("total"), "%d", &n)
			planTotal.Store(n)
			planDone.Store(0)
			if n == 0 {
				live.Spin("no frameworks to decrypt")
			} else {
				live.Progress(0, n, "decrypting %d framework(s)", n)
			}
		case "image":
			planDone.Add(1)
			dumpedTotal++
			name := ev.Attr("name")
			switch {
			case strings.Contains(name, ".framework/"):
				dumpedFrameworks++
			case !strings.Contains(name, "/"):
				dumpedMain++
			default:
				dumpedOther++
			}
			display := name
			if len(display) > 48 {
				display = "…" + display[len(display)-47:]
			}
			live.Progress(planDone.Load(), planTotal.Load(), "%s", display)
		case "image_fail":
			live.Note("failed to dump %s", ev.Attr("name"))
		case "zip":
			live.Spin("packaging IPA on device")
		}
	}

	_, stderr, code, err := dev.RunHelper(helperPath, bundlePath, outRemote, onEvent, nil)
	if err != nil {
		live.Fail("helper run: %v", err)
		return fmt.Errorf("helper run: %w (stderr: %s)", err, stderr)
	}
	if code != 0 {
		live.Fail("helper exit %d", code)
		return fmt.Errorf("helper exit %d: %s", code, stderr)
	}

	summary := fmt.Sprintf("decrypted %d image(s): %d main, %d framework",
		dumpedTotal, dumpedMain, dumpedFrameworks)
	if dumpedOther > 0 {
		summary += fmt.Sprintf(", %d other", dumpedOther)
	}
	if pluginCount > 0 {
		summary += fmt.Sprintf(" · %d extension(s)", pluginCount)
	}
	live.OK("%s", summary)

	// --- pull + post-process ---
	cwd, _ := os.Getwd()
	outLocal := filepath.Join(cwd, fmt.Sprintf("%s_%s.decrypted.ipa", app.BundleID, app.Version))

	live = tui.NewLive()
	live.Spin("pulling → %s", filepath.Base(outLocal))
	if err := dev.Download(outRemote, outLocal); err != nil {
		live.Fail("pull failed")
		tui.Err("pull: %v", err)
		return err
	}

	if !decryptKeepMetadata {
		live.Spin("stripping iTunesMetadata.plist")
		if removed, err := pipeline.StripMetadata(outLocal); err != nil {
			live.Fail("strip metadata failed")
			tui.Err("strip metadata: %v", err)
			return err
		} else if removed {
			live.Note("removed iTunesMetadata.plist")
		}
	}

	if !decryptKeepWatch {
		live.Spin("stripping Watch/")
		if n, err := pipeline.StripWatch(outLocal); err != nil {
			live.Fail("strip watch failed")
			tui.Err("strip watch: %v", err)
			return err
		} else if n > 0 {
			live.Note("removed %d Watch/ entries", n)
		}
	}
	live.OK("→ %s", outLocal)

	// --- verify ---
	if !decryptNoVerify {
		live = tui.NewLive()
		live.Spin("checking cryptid on every Mach-O")
		res, verr := pipeline.VerifyCryptid(outLocal)
		if verr != nil {
			live.Fail("verify failed")
			tui.Err("verify: %v", verr)
			return verr
		}
		if len(res.Encrypted) > 0 {
			live.Fail("%d binary(ies) still have cryptid != 0", len(res.Encrypted))
			for _, n := range res.Encrypted {
				tui.Info("  %s", n)
			}
			return fmt.Errorf("verify failed: %d still-encrypted binaries", len(res.Encrypted))
		}

		suffix := ""
		if len(res.Skipped) > 0 {
			suffix = fmt.Sprintf(" (%d skipped)", len(res.Skipped))
		}
		live.OK("%d Mach-O(s) verified cryptid=0%s", res.Scanned, suffix)
	}

	// --- cleanup ---
	if patchedPath != "" {
		_ = os.Remove(patchedPath)
	}

	if !decryptNoCleanup {
		_ = dev.Remove(stagingRemote)
		_ = dev.Remove(outRemote)

		if decryptUninstall {
			if err := dev.Uninstall(appinst, app.BundleID); err != nil {
				tui.Warn("uninstall: %v", err)
			}
		}
	}

	return nil
}
