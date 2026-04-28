package main

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"

	"github.com/londek/ipadecrypt/internal/appstore"
	"github.com/londek/ipadecrypt/internal/config"
	"github.com/londek/ipadecrypt/internal/device"
	"github.com/londek/ipadecrypt/internal/pipeline"
	"github.com/londek/ipadecrypt/internal/tui"
	"github.com/spf13/cobra"
)

var (
	appStoreIDRe = regexp.MustCompile(`/id(\d+)`)

	errAppinstNotFound = errors.New("appinst not found")
)

type decryptTarget struct {
	localPath string
	bundleId  string
	appId     string
}

type patchResult struct {
	uploadPath           string
	patchedPath          string
	changed              bool
	previousMinOS        string
	watchStripped        int
	deviceFamilyExpanded bool
	previousDeviceFamily []int
	newDeviceFamily      []int
}

type installPlan struct {
	helperPath    string
	appinstPath   string
	bundlePath    string
	stagingRemote string
}

type installResult struct {
	bundlePath      string
	installed       bool
	reinstalled     bool
	previousVersion string
}

type sourceDisposition byte

const (
	sourceDispositionCached sourceDisposition = iota + 1
	sourceDispositionDownloaded
)

type installEvent int

const (
	installHashIPA installEvent = iota + 1
	installHashInstalled
	installReadInstalledVersion
	installReplaceInstalled
	installUpload
	installRunAppinst
	installRescan
)

type helperUpdate struct {
	spin         string
	note         string
	progress     bool
	progressCur  int64
	progressMax  int64
	progressText string
}

type helperProgress struct {
	dumpedTotal      atomic.Int64
	dumpedMain       atomic.Int64
	dumpedFrameworks atomic.Int64
	dumpedOther      atomic.Int64
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

		return decryptTarget{appId: m[1]}, nil
	}

	// Local .ipa path
	if strings.HasSuffix(strings.ToLower(raw), ".ipa") {
		info, err := os.Stat(raw)
		if err != nil {
			return decryptTarget{}, fmt.Errorf("local IPA %s: %w", raw, err)
		}
		if info.IsDir() {
			return decryptTarget{}, fmt.Errorf("local IPA %s is a directory", raw)
		}

		abs, err := filepath.Abs(raw)
		if err != nil {
			return decryptTarget{}, err
		}
		return decryptTarget{localPath: abs}, nil
	}

	// Bare numeric string: App Store track ID (e.g. "544007664").
	if isAllDigits(raw) {
		return decryptTarget{appId: raw}, nil
	}

	// Fallback: treat as a bundle identifier.
	return decryptTarget{bundleId: raw}, nil
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}

	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}

	return true
}

func transferProgressText(label string, cur, total int64) string {
	if total <= 0 {
		return label
	}

	return fmt.Sprintf("%s (%s / %s)", label, humanBytes(cur), humanBytes(total))
}

func humanBytes(n int64) string {
	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
		TB = GB * 1024
	)
	switch {
	case n >= TB:
		return fmt.Sprintf("%.2f TB", float64(n)/float64(TB))
	case n >= GB:
		return fmt.Sprintf("%.2f GB", float64(n)/float64(GB))
	case n >= MB:
		return fmt.Sprintf("%.1f MB", float64(n)/float64(MB))
	case n >= KB:
		return fmt.Sprintf("%.1f KB", float64(n)/float64(KB))
	default:
		return fmt.Sprintf("%d B", n)
	}
}

func decryptHandler(cmd *cobra.Command, args []string) {
	cfg, paths, err := loadConfigOrDefault(rootDirOverride)
	if err != nil {
		tui.Err("%v", err)
		return
	}

	target, err := parseDecryptArg(args[0])
	if err != nil {
		tui.Err("%v", err)
		return
	}

	if cfg.Apple.Account == nil || cfg.Device.Host == "" {
		tui.Err("environment not configured")
		tui.Info("run `ipadecrypt bootstrap` first to prepare your environment")
		return
	}

	//
	// Connect to device and probe environment
	//

	live := tui.NewLive()
	live.Spin("connecting to %s@%s", cfg.Device.User, cfg.Device.Host)

	dev, err := device.Connect(context.Background(), cfg.Device)
	if err != nil {
		live.Fail("ssh connect failed: %v", err)
		return
	}

	defer dev.Close()

	live.Spin("probing device")

	probe, err := dev.Probe()
	if err != nil {
		live.Fail("probe failed: %v", err)
		return
	}

	live.OK("%s@%s iOS %s %s", cfg.Device.User, cfg.Device.Host, probe.IOSVersion, probe.Arch)

	//
	// If a bundle-id target is already installed, offer to decrypt the
	// on-device build (e.g. TestFlight) instead of reinstalling from the
	// App Store. Non-TTY aborts - no way to confirm.
	//

	if target.bundleId != "" && !decryptForce {
		live = tui.NewLive()
		live.Spin("checking if %s is installed", target.bundleId)
		installedPath, err := dev.FindInstalledByBundleID(target.bundleId)
		if err != nil {
			live.Fail("scan failed: %v", err)
			return
		}

		if installedPath != "" {
			version, err := dev.InstalledVersion(installedPath)
			if err != nil || version == "" {
				version = "unknown"
			}

			live.OK("found installed %s v%s", target.bundleId, version)

			if !tui.IsTTY() {
				tui.Err("%s v%s is already installed on the device.", target.bundleId, version)
				tui.Info("Non-TTY runs can't prompt. Uninstall the app first, pass a local .ipa path, or re-run in a TTY.")
				return
			}

			idx, err := tui.Select(
				fmt.Sprintf("%s v%s is installed - which build do you want decrypted?", target.bundleId, version),
				[]string{
					fmt.Sprintf("Installed build v%s (no App Store reinstall)", version),
					"Latest from App Store (will reinstall, overwriting installed)",
				},
			)
			if err != nil {
				tui.Err("%v", err)
				return
			}

			if idx == 0 {
				live = tui.NewLive()
				live.Spin("preparing helper")

				helperPath, err := dev.EnsureHelper()
				if err != nil {
					live.Fail("helper upload: %v", err)
					return
				}

				live.OK("helper ready")

				runDecryptOnBundle(dev, helperPath, target.bundleId, installedPath, version, "")

				return
			}
		} else {
			live.OK("%s not installed; will fetch from App Store", target.bundleId)
		}
	}

	//
	// Acquire encrypted IPA, either from the App Store or a local path
	//

	var (
		appBundleID string
		appVersion  string
		encPath     string
	)

	if target.localPath != "" {
		tui.OK("local IPA %s", filepath.Base(target.localPath))

		appBundleID, appVersion, err = pipeline.AppInfo(target.localPath)
		if err != nil {
			tui.Err("read IPA: %v", err)
			return
		}

		encPath = target.localPath

		tui.OK("%s v%s", appBundleID, appVersion)
	} else {
		as, err := appstore.New(filepath.Join(paths.Root, "cookies"))
		if err != nil {
			tui.Err("appstore client: %v", err)
			return
		}

		appStoreCountry, err := appstore.CountryCodeFromStoreFront(cfg.Apple.Account.StoreFront)
		if err != nil {
			tui.Err("resolve appstore country code: %v", err)
			return
		}

		tui.OK("signed in as %s (%s storefront)", cfg.Apple.Account.Email, appStoreCountry)

		live = tui.NewLive()

		if target.appId != "" {
			live.Spin("resolving appId %s", target.appId)
		} else {
			live.Spin("resolving bundleId %s", target.bundleId)
		}

		app, err := lookupTargetApp(as, cfg.Apple.Account, target)
		if err != nil {
			live.Fail("lookup failed (%s): %v", appStoreCountry, err)
			return
		}

		if app.Price > 0 {
			live.Fail("paid app (price=%v) - unsupported", app.Price)
			return
		}

		live.OK("found %s on App Store", app.BundleID)

		live = tui.NewLive()
		live.Spin("fetching download metadata")

		disposition, err := fetchRemoteEncryptedSource(cfg, paths, as, app, decryptExtVerID, func(e authEvent) {
			switch e {
			case authReauth:
				live.Spin("re-authenticating")
			case authLicense:
				live.Spin("acquiring license")
			case authRetryingDownload:
				live.Spin("retrying download")
			}
		}, func(cur, total int64) {
			live.Message("%s", transferProgressText("downloading IPA from App Store", cur, total))
			live.Progress(cur, total)
		})
		if err != nil {
			if errors.Is(err, errRemoteDownloadFailed) {
				live.Fail("download failed: %v", errors.Unwrap(err))
				return
			}

			live.Fail("prepare failed: %v", err)
			return
		}

		appBundleID = app.BundleID
		appVersion = disposition.version
		encPath = disposition.path

		if disposition.kind == sourceDispositionCached {
			live.OK("cached %s", filepath.Base(encPath))
		} else {
			live.OK("downloaded %s", filepath.Base(encPath))
		}
	}

	//
	// Patching MinimumOSVersion if needed
	//

	live = tui.NewLive()
	live.Spin("patching Info.plist for MinimumOSVersion %s", probe.IOSVersion)

	patch, err := patchSourceForDevice(encPath, probe.IOSVersion, probe.DeviceFamily, decryptPatchDevType)
	if err != nil {
		var dfErr *pipeline.ErrDeviceFamilyMismatch
		if errors.As(err, &dfErr) {
			live.Fail("device family mismatch: app supports %v, device is %d (%s) — pass --patch-device-type to install anyway",
				dfErr.Supported, dfErr.Device, pipeline.DeviceFamilyName(dfErr.Device))
			return
		}
		live.Fail("patch MinimumOSVersion failed: %v", err)
		return
	}
	defer func() {
		if patch.patchedPath != "" {
			os.Remove(patch.patchedPath)
		}
	}()

	if patch.changed {
		live.OK("MinimumOSVersion %s → %s", patch.previousMinOS, probe.IOSVersion)
	} else {
		live.OK("no MinimumOSVersion change needed")
	}

	if patch.deviceFamilyExpanded {
		tui.OK("UIDeviceFamily %v → %v", patch.previousDeviceFamily, patch.newDeviceFamily)
	}

	if patch.watchStripped > 0 {
		tui.OK("stripped %d Watch/ entries", patch.watchStripped)
	}

	live = tui.NewLive()
	live.Spin("preparing install plan")

	plan, err := buildInstallPlan(dev, patch.uploadPath)
	if err != nil {
		switch {
		case errors.Is(err, errAppinstNotFound):
			live.Fail("appinst not found on device - run `ipadecrypt bootstrap`")
		default:
			live.Fail("prepare install: %v", err)
		}
		return
	}

	if plan.bundlePath == "" {
		live.Spin("preparing install")
	} else {
		live.Spin("checking installed app at %s", plan.bundlePath)
	}

	install, err := ensureInstalledBundle(dev, plan, patch.uploadPath, func(e installEvent) {
		switch e {
		case installHashIPA:
			live.Spin("computing IPA checksum")
		case installHashInstalled:
			live.Spin("computing installed app checksum")
		case installReadInstalledVersion:
			live.Spin("reading installed app version")
		case installReplaceInstalled:
			live.Spin("installed app differs - replacing it")
		case installUpload:
			live.Spin("uploading IPA to device")
		case installRunAppinst:
			live.Spin("running appinst")
		case installRescan:
			live.Spin("locating installed app")
		}
	}, func(cur, total int64) {
		live.Message("%s", transferProgressText("uploading IPA to device", cur, total))
		live.Progress(cur, total)
	})
	if err != nil {
		live.Fail("install failed: %v", err)
		return
	}

	if install.reinstalled {
		live.OK("reinstalled (%s => %s) → %s", install.previousVersion, appVersion, install.bundlePath)
	} else if install.installed {
		live.OK("installed → %s", install.bundlePath)
	} else {
		live.OK("already installed → %s", install.bundlePath)
	}

	runDecryptOnBundle(dev, plan.helperPath, appBundleID, install.bundlePath, appVersion, plan.stagingRemote)
}

// runDecryptOnBundle runs helper → pull → strip → verify → cleanup on an
// installed bundle. stagingRemote may be "" for the use-installed path.
func runDecryptOnBundle(dev *device.Client, helperPath, bundleID, bundlePath, version, stagingRemote string) {
	outRemote := remoteOutputPath(bundleID, version)

	if err := dev.Mkdir(path.Dir(outRemote)); err != nil {
		tui.Err("mkdir work: %v", err)
		return
	}

	live := tui.NewLive()
	live.Spin("starting helper")

	progress := &helperProgress{}
	onEvent := func(ev device.Event) {
		update := progress.HandleEvent(ev)

		if update.note != "" {
			live.Note("%s", update.note)
		}
		if update.spin != "" {
			live.Spin("%s", update.spin)
		}
		if update.progress {
			if update.progressText != "" {
				live.Message("%s", update.progressText)
			}
			live.Progress(update.progressCur, update.progressMax)
		}
	}

	_, _, code, err := dev.RunHelper(helperPath, bundleID, bundlePath, outRemote, onEvent, nil)
	if err != nil {
		live.Fail("helper run: %v", err)
		return
	}

	if code != 0 {
		live.Fail("helper exit %d", code)
		return
	}

	live.OK("%s", progress.Summary())

	outLocal, err := localOutputPath(decryptOutput, bundleID, version)
	if err != nil {
		tui.Err("output path: %v", err)
		return
	}

	live = tui.NewLive()

	live.Spin("pulling → %s", filepath.Base(outLocal))

	remoteSt, err := dev.Stat(outRemote)
	if err != nil {
		live.Fail("stat remote: %v", err)
		return
	}

	if err := os.MkdirAll(filepath.Dir(outLocal), 0o755); err != nil {
		live.Fail("mkdir local: %v", err)
		return
	}

	outFile, err := os.OpenFile(outLocal, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		live.Fail("open local: %v", err)
		return
	}

	pw := newProgressWriter(outFile, remoteSt.Size(), func(cur, total int64) {
		live.Message("%s", transferProgressText(fmt.Sprintf("pulling → %s", filepath.Base(outLocal)), cur, total))
		live.Progress(cur, total)
	})

	if err := dev.Download(outRemote, pw); err != nil {
		outFile.Close()
		live.Fail("pull failed: %v", err)
		return
	}

	if err := outFile.Close(); err != nil {
		live.Fail("close local: %v", err)
		return
	}

	pw.Flush()

	if !decryptKeepMetadata {
		live.Spin("stripping iTunesMetadata.plist")

		if _, err := pipeline.StripMetadata(outLocal); err != nil {
			live.Fail("strip metadata failed: %v", err)
			return
		}
	}

	if !decryptKeepWatch {
		live.Spin("stripping Watch/")

		if _, err := pipeline.StripWatch(outLocal); err != nil {
			live.Fail("strip watch failed: %v", err)
			return
		}
	}

	live.OK("→ %s", outLocal)

	if !decryptNoVerify {
		live = tui.NewLive()
		live.Spin("checking cryptid on every Mach-O")
		res, err := pipeline.VerifyCryptid(outLocal)
		if err != nil {
			live.Fail("verify failed: %v", err)
			return
		}
		if len(res.Encrypted) > 0 {
			live.Fail("%d binary(ies) still have cryptid != 0", len(res.Encrypted))
			for _, n := range res.Encrypted {
				tui.Info("  %s", n)
			}
			return
		}

		suffix := ""
		if len(res.Skipped) > 0 {
			suffix = fmt.Sprintf(" (%d skipped)", len(res.Skipped))
		}
		live.OK("%d Mach-O(s) verified cryptid=0%s", res.Scanned, suffix)
	}

	cleanupDecrypt(dev, decryptNoCleanup, stagingRemote, outRemote)
}

func lookupTargetApp(as *appstore.Client, acc *appstore.Account, target decryptTarget) (appstore.App, error) {
	if target.appId != "" {
		return as.LookupByAppID(acc, target.appId)
	}

	return as.LookupByBundleID(acc, target.bundleId)
}

var errRemoteDownloadFailed = errors.New("remote download failed")

type remoteSourceDisposition struct {
	path    string
	version string
	kind    sourceDisposition
}

func fetchRemoteEncryptedSource(cfg *config.Config, paths *config.Paths, as *appstore.Client, app appstore.App, extVerID string, onAuth func(authEvent), onProgress func(cur, total int64)) (remoteSourceDisposition, error) {
	if extVerID == "" {
		encPath, err := paths.CachedEncryptedIPA(app.BundleID, app.Version)
		if err != nil {
			return remoteSourceDisposition{}, err
		}

		if fileExists(encPath) {
			return remoteSourceDisposition{
				path:    encPath,
				version: app.Version,
				kind:    sourceDispositionCached,
			}, nil
		}
	}

	ticket, err := withAuth(cfg, as, app, 3, onAuth, func() (appstore.DownloadTicket, error) {
		return as.PrepareDownload(cfg.Apple.Account, app, extVerID)
	})
	if err != nil {
		return remoteSourceDisposition{}, err
	}

	encPath, err := paths.CachedEncryptedIPA(app.BundleID, ticket.Version())
	if err != nil {
		return remoteSourceDisposition{}, err
	}

	if fileExists(encPath) {
		return remoteSourceDisposition{
			path:    encPath,
			version: ticket.Version(),
			kind:    sourceDispositionCached,
		}, nil
	}

	if _, err := as.CompleteDownload(cfg.Apple.Account, ticket, encPath, onProgress); err != nil {
		return remoteSourceDisposition{}, fmt.Errorf("%w: %w", errRemoteDownloadFailed, err)
	}

	return remoteSourceDisposition{
		path:    encPath,
		version: ticket.Version(),
		kind:    sourceDispositionDownloaded,
	}, nil
}

func patchSourceForDevice(encPath, iosVersion string, deviceFamily int, patchDeviceType bool) (patchResult, error) {
	pattern := strings.TrimSuffix(filepath.Base(encPath), ".ipa") + "-patched-*.ipa"
	f, err := os.CreateTemp("", pattern)
	if err != nil {
		return patchResult{}, fmt.Errorf("create temp ipa: %w", err)
	}

	tmp := f.Name()
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return patchResult{}, fmt.Errorf("close temp ipa: %w", err)
	}
	if err := os.Remove(tmp); err != nil && !errors.Is(err, os.ErrNotExist) {
		return patchResult{}, fmt.Errorf("prepare temp ipa: %w", err)
	}

	res, err := pipeline.PatchForInstall(encPath, tmp, iosVersion, deviceFamily, patchDeviceType, decryptKeepWatch)
	if err != nil {
		os.Remove(tmp)
		return patchResult{}, err
	}

	if !res.MinOSChanged && res.WatchRemoved == 0 && !res.DeviceFamilyExpanded {
		os.Remove(tmp)
		return patchResult{uploadPath: encPath}, nil
	}

	return patchResult{
		uploadPath:           tmp,
		patchedPath:          tmp,
		changed:              res.MinOSChanged,
		previousMinOS:        res.PreviousMinOS,
		watchStripped:        res.WatchRemoved,
		deviceFamilyExpanded: res.DeviceFamilyExpanded,
		previousDeviceFamily: res.PreviousDeviceFamily,
		newDeviceFamily:      res.NewDeviceFamily,
	}, nil
}

func buildInstallPlan(dev *device.Client, uploadPath string) (installPlan, error) {
	appDirName, err := pipeline.AppDirName(uploadPath)
	if err != nil {
		return installPlan{}, fmt.Errorf("read IPA: %w", err)
	}

	helperPath, err := dev.EnsureHelper()
	if err != nil {
		return installPlan{}, fmt.Errorf("helper upload: %w", err)
	}

	appinstPath, err := dev.LocateAppinst()
	if err != nil {
		return installPlan{}, fmt.Errorf("locate appinst: %w", err)
	}
	if appinstPath == "" {
		return installPlan{}, errAppinstNotFound
	}

	bundlePath, err := dev.FindInstalled(appDirName)
	if err != nil {
		return installPlan{}, fmt.Errorf("scan installed: %w", err)
	}

	return installPlan{
		helperPath:    helperPath,
		appinstPath:   appinstPath,
		bundlePath:    bundlePath,
		stagingRemote: path.Join(device.RemoteRoot, "staging", filepath.Base(uploadPath)),
	}, nil
}

func ensureInstalledBundle(dev *device.Client, plan installPlan, uploadPath string, onEvent func(installEvent), onProgress func(cur, total int64)) (installResult, error) {
	notify := func(e installEvent) {
		if onEvent != nil {
			onEvent(e)
		}
	}

	if plan.bundlePath == "" {
		return installUploadedBundle(dev, plan, uploadPath, false, "", notify, onProgress)
	}

	if !decryptForce {
		notify(installHashIPA)
		execName, wantSum, err := pipeline.MainExecSHA256(uploadPath)
		if err != nil {
			return installResult{}, fmt.Errorf("hash ipa: %w", err)
		}

		remoteExec := path.Join(plan.bundlePath, execName)
		notify(installHashInstalled)
		gotSum, err := dev.HashFile(remoteExec)
		if err != nil {
			return installResult{}, fmt.Errorf("hash device: %w", err)
		}

		if gotSum == wantSum {
			return installResult{
				bundlePath: plan.bundlePath,
			}, nil
		}
	}

	notify(installReadInstalledVersion)
	previousVersion, err := dev.InstalledVersion(plan.bundlePath)
	if err != nil {
		previousVersion = ""
	}

	notify(installReplaceInstalled)
	return installUploadedBundle(dev, plan, uploadPath, true, previousVersion, notify, onProgress)
}

func installUploadedBundle(dev *device.Client, plan installPlan, uploadPath string, reinstalled bool, previousVersion string, notify func(installEvent), onProgress func(cur, total int64)) (installResult, error) {
	notify(installUpload)

	src, err := os.Open(uploadPath)
	if err != nil {
		return installResult{}, fmt.Errorf("open %s: %w", uploadPath, err)
	}

	defer src.Close()

	st, err := src.Stat()
	if err != nil {
		return installResult{}, fmt.Errorf("stat %s: %w", uploadPath, err)
	}

	pr := newProgressReader(src, st.Size(), onProgress)
	if err := dev.Upload(pr, plan.stagingRemote, 0); err != nil {
		return installResult{}, fmt.Errorf("upload: %w", err)
	}

	notify(installRunAppinst)

	if err := dev.Install(plan.appinstPath, plan.stagingRemote); err != nil {
		return installResult{}, fmt.Errorf("install: %w", err)
	}

	appDirName, err := pipeline.AppDirName(uploadPath)
	if err != nil {
		return installResult{}, fmt.Errorf("read IPA: %w", err)
	}

	notify(installRescan)

	bundlePath, err := dev.FindInstalled(appDirName)
	if err != nil {
		return installResult{}, fmt.Errorf("post-install scan: %w", err)
	}

	if bundlePath == "" {
		return installResult{}, errors.New("install reported success but bundle not found")
	}

	return installResult{
		bundlePath:      bundlePath,
		installed:       true,
		reinstalled:     reinstalled,
		previousVersion: previousVersion,
	}, nil
}

func remoteOutputPath(bundleID, version string) string {
	return path.Join(device.RemoteRoot, "work", fmt.Sprintf("%s_%s.ipa", bundleID, version))
}

func localOutputPath(override, bundleID, version string) (string, error) {
	defaultName := fmt.Sprintf("%s_%s.decrypted.ipa", bundleID, version)

	if override == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return "", err
		}
		return filepath.Join(cwd, defaultName), nil
	}

	abs, err := filepath.Abs(override)
	if err != nil {
		return "", err
	}

	// if override is just a directory (not a full file path), place the default filename inside it
	info, err := os.Stat(abs)
	if err == nil && info.IsDir() {
		return filepath.Join(abs, defaultName), nil
	}

	return abs, nil
}

func cleanupDecrypt(dev *device.Client, noCleanup bool, stagingRemote, outRemote string) {
	if noCleanup {
		return
	}

	if stagingRemote != "" {
		dev.Remove(stagingRemote)
	}
	if outRemote != "" {
		dev.Remove(outRemote)
	}
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func pluralize(count, noun string) string {
	if count == "1" {
		return count + " " + noun
	}
	return count + " " + noun + "s"
}

// prettyImageName renders helper image paths as something readable.
//
//	"Sensor-App"                                   -> "Sensor-App"
//	"Frameworks/Foo.framework/Foo"                 -> "Foo.framework"
//	"Frameworks/Foo.framework/Versions/A/Foo"      -> "Foo.framework"
//	"PlugIns/Bar.appex/Bar"                        -> "Bar.appex"
//
// Anything else passes through unchanged.
func prettyImageName(name string) string {
	if i := strings.Index(name, ".framework/"); i >= 0 {
		start := strings.LastIndex(name[:i], "/") + 1
		return name[start:i] + ".framework"
	}
	if i := strings.Index(name, ".appex/"); i >= 0 {
		start := strings.LastIndex(name[:i], "/") + 1
		return name[start:i] + ".appex"
	}
	return name
}

func parseInt64(s string) int64 {
	var n int64
	fmt.Sscanf(s, "%d", &n)
	return n
}

func (p *helperProgress) HandleEvent(ev device.Event) helperUpdate {
	switch ev.Name {
	case "bundle":
		switch ev.Attr("phase") {
		case "done":
			extras := ev.Attr("extras")
			if extras == "0" {
				return helperUpdate{}
			}
			return helperUpdate{note: fmt.Sprintf("bundle done (%s)", pluralize(extras, "framework"))}
		case "skipped":
			return helperUpdate{note: fmt.Sprintf("bundle skipped: %s (%s)", path.Base(ev.Attr("src")), ev.Attr("reason"))}
		}

	case "spawn_chmod":
		return helperUpdate{note: fmt.Sprintf("chmod +x %s (was mode %s)", path.Base(ev.Attr("path")), ev.Attr("old_mode"))}

	case "spawn_path":
		if ev.Attr("path") == "ptrace" {
			return helperUpdate{note: fmt.Sprintf("spawned %s via ptrace fallback", path.Base(ev.Attr("exec")))}
		}
		return helperUpdate{}

	case "spawn_path_fallback":
		return helperUpdate{note: fmt.Sprintf("%s failed on %s, falling back", ev.Attr("from"), path.Base(ev.Attr("exec")))}

	case "dyld":
		if ev.Attr("phase") == "resuming" {
			return helperUpdate{spin: fmt.Sprintf("running %s so dyld binds frameworks", path.Base(ev.Attr("src")))}
		}

	case "spawn_failed":
		return helperUpdate{note: fmt.Sprintf("could not spawn %s (skipped)", path.Base(ev.Attr("src")))}

	case "image":
		name := ev.Attr("name")
		pretty := prettyImageName(name)
		switch ev.Attr("phase") {
		case "start":
			return helperUpdate{spin: fmt.Sprintf("decrypting %s", pretty)}
		case "done":
			p.dumpedTotal.Add(1)
			switch ev.Attr("kind") {
			case "main":
				p.dumpedMain.Add(1)
			case "framework":
				p.dumpedFrameworks.Add(1)
			default:
				p.dumpedOther.Add(1)
			}
			size := parseInt64(ev.Attr("size"))
			return helperUpdate{
				note: fmt.Sprintf("decrypted %s (%s)", pretty, humanBytes(size)),
				spin: fmt.Sprintf("decrypted %d image(s)", p.dumpedTotal.Load()),
			}
		case "failed":
			if reason := ev.Attr("reason"); reason != "" {
				return helperUpdate{note: fmt.Sprintf("failed to decrypt %s (%s)", pretty, reason)}
			}
			return helperUpdate{note: fmt.Sprintf("failed to decrypt %s", pretty)}
		}

	case "pack":
		switch ev.Attr("phase") {
		case "start":
			return helperUpdate{spin: fmt.Sprintf("packaging IPA → %s", path.Base(ev.Attr("ipa")))}
		case "done":
			return helperUpdate{note: fmt.Sprintf("packaged → %s", path.Base(ev.Attr("ipa")))}
		case "failed":
			return helperUpdate{note: fmt.Sprintf("pack failed → %s", path.Base(ev.Attr("ipa")))}
		}

	case "done":
		return helperUpdate{}
	}

	// Unknown event: surface everything we got so nothing is silently dropped.
	parts := make([]string, 0, len(ev.Attrs)+1)
	parts = append(parts, "event="+ev.Name)

	for k, v := range ev.Attrs {
		if k == "event" {
			continue
		}

		parts = append(parts, fmt.Sprintf("%s=%q", k, v))
	}

	return helperUpdate{note: strings.Join(parts, " ")}
}

func (p *helperProgress) Summary() string {
	total := p.dumpedTotal.Load()
	main := p.dumpedMain.Load()
	frameworks := p.dumpedFrameworks.Load()
	other := p.dumpedOther.Load()

	summary := fmt.Sprintf("decrypted %d image(s): %d main, %d framework", total, main, frameworks)
	if other > 0 {
		summary += fmt.Sprintf(", %d other", other)
	}

	return summary
}
