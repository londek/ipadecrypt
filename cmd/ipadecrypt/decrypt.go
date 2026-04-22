package main

import (
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

	errEnvironmentNotConfigured = errors.New("environment not configured")
	errAppinstNotFound          = errors.New("appinst not found")
	errPaidAppsUnsupported      = errors.New("paid apps not supported")
)

type decryptTarget struct {
	localPath string
	bundleId  string
	appId     string
}

type patchResult struct {
	uploadPath    string
	patchedPath   string
	changed       bool
	previousMinOS string
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
	planTotal        atomic.Int64
	planDone         atomic.Int64
	dumpedTotal      atomic.Int64
	dumpedMain       atomic.Int64
	dumpedFrameworks atomic.Int64
	dumpedOther      atomic.Int64
	pluginCount      atomic.Int64
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
		if info, err := os.Stat(raw); err == nil && !info.IsDir() {
			abs, aerr := filepath.Abs(raw)
			if aerr != nil {
				return decryptTarget{}, aerr
			}
			return decryptTarget{localPath: abs}, nil
		}
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

func decryptHandler(cmd *cobra.Command, args []string) error {
	ctx, cancel := notifyContext()
	defer cancel()

	cfg, paths, err := loadConfigOrDefault(rootDirOverride)
	if err != nil {
		tui.Err("%v", err)
		return err
	}

	target, err := parseDecryptArg(args[0])
	if err != nil {
		tui.Err("%v", err)
		return err
	}

	if cfg.Apple.Account == nil || cfg.Device.Host == "" {
		tui.Err("environment not configured")
		tui.Info("run `ipadecrypt bootstrap` first to prepare your environment")
		return errEnvironmentNotConfigured
	}

	//
	// Connect to device and probe environment
	//

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
			return err
		}
		encPath = target.localPath

		tui.OK("%s v%s", appBundleID, appVersion)
	} else {
		as, err := appstore.New(filepath.Join(paths.Root, "cookies"))
		if err != nil {
			tui.Err("appstore client: %v", err)
			return err
		}

		tui.OK("signed in as %s", cfg.Apple.Account.Email)

		live = tui.NewLive()

		if target.appId != "" {
			live.Spin("resolving appId %s", target.appId)
		} else {
			live.Spin("resolving bundleId %s", target.bundleId)
		}

		app, err := lookupTargetApp(as, cfg.Apple.Account, target)
		if err != nil {
			live.Fail("lookup failed")
			tui.Err("lookup: %v", err)
			return err
		}

		if app.Price > 0 {
			live.Fail("paid app (price=%v) - unsupported", app.Price)
			return errPaidAppsUnsupported
		}

		live.OK("Found %s on AppStore", app.BundleID)

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
		})
		if err != nil {
			if errors.Is(err, errRemoteDownloadFailed) {
				live.Fail("download failed")
				tui.Err("download: %v", errors.Unwrap(err))
				return errors.Unwrap(err)
			}

			live.Fail("prepare failed")
			tui.Err("prepare: %v", err)
			return err
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

	patch, err := patchSourceForDevice(encPath, probe.IOSVersion)
	if err != nil {
		live.Fail("patch MinimumOSVersion failed")
		tui.Err("patch MinimumOSVersion: %v", err)
		return err
	}
	defer func() {
		if patch.patchedPath != "" {
			_ = os.Remove(patch.patchedPath)
		}
	}()

	if patch.changed {
		live.OK("MinimumOSVersion %s → %s", patch.previousMinOS, probe.IOSVersion)
	} else {
		live.OK("no MinimumOSVersion change needed")
	}

	plan, err := buildInstallPlan(dev, patch.uploadPath)
	if err != nil {
		switch {
		case errors.Is(err, errAppinstNotFound):
			tui.Err("appinst not found on device - run `ipadecrypt bootstrap`")
		default:
			tui.Err("prepare install: %v", err)
		}
		return err
	}

	live = tui.NewLive()
	if plan.bundlePath == "" {
		live.Spin("preparing install")
	} else {
		live.Note("app already installed at %s", plan.bundlePath)
		live.Spin("checking installed app")
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
	})
	if err != nil {
		live.Fail("install failed")
		tui.Err("install: %v", err)
		return err
	}

	if install.reinstalled {
		live.OK("reinstalled (%s => %s) → %s", install.previousVersion, appVersion, install.bundlePath)
	} else if install.installed {
		live.OK("installed → %s", install.bundlePath)
	} else {
		live.OK("already installed → %s", install.bundlePath)
	}

	outRemote := remoteOutputPath(appBundleID, appVersion)

	if err := dev.Mkdir(path.Dir(outRemote)); err != nil {
		tui.Err("mkdir work: %v", err)
		return err
	}

	live = tui.NewLive()
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
			live.Progress(update.progressCur, update.progressMax, "%s", update.progressText)
		}
	}

	_, stderr, code, err := dev.RunHelper(plan.helperPath, install.bundlePath, outRemote, onEvent, nil)
	if err != nil {
		live.Fail("helper run: %v", err)
		return fmt.Errorf("helper run: %w (stderr: %s)", err, stderr)
	}
	if code != 0 {
		live.Fail("helper exit %d", code)
		return fmt.Errorf("helper exit %d: %s", code, stderr)
	}

	live.OK("%s", progress.Summary())

	outLocal, err := localOutputPath(appBundleID, appVersion)
	if err != nil {
		tui.Err("output path: %v", err)
		return err
	}

	live = tui.NewLive()
	live.Spin("pulling → %s", filepath.Base(outLocal))
	if err := dev.Download(outRemote, outLocal); err != nil {
		live.Fail("pull failed")
		tui.Err("pull: %v", err)
		return err
	}

	if !decryptKeepMetadata {
		live.Spin("stripping iTunesMetadata.plist")
		removed, err := pipeline.StripMetadata(outLocal)
		if err != nil {
			live.Fail("strip metadata failed")
			tui.Err("strip metadata: %v", err)
			return err
		}
		if removed {
			live.Note("removed iTunesMetadata.plist")
		}
	}

	if !decryptKeepWatch {
		live.Spin("stripping Watch/")
		n, err := pipeline.StripWatch(outLocal)
		if err != nil {
			live.Fail("strip watch failed")
			tui.Err("strip watch: %v", err)
			return err
		}
		if n > 0 {
			live.Note("removed %d Watch/ entries", n)
		}
	}
	live.OK("→ %s", outLocal)

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

	cleanupDecrypt(dev, decryptNoCleanup, plan.stagingRemote, outRemote)

	return nil
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

func fetchRemoteEncryptedSource(cfg *config.Config, paths *config.Paths, as *appstore.Client, app appstore.App, extVerID string, onAuth func(authEvent)) (remoteSourceDisposition, error) {
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

	if _, err := as.CompleteDownload(cfg.Apple.Account, ticket, encPath); err != nil {
		return remoteSourceDisposition{}, fmt.Errorf("%w: %w", errRemoteDownloadFailed, err)
	}

	return remoteSourceDisposition{
		path:    encPath,
		version: ticket.Version(),
		kind:    sourceDispositionDownloaded,
	}, nil
}

func patchSourceForDevice(encPath, iosVersion string) (patchResult, error) {
	pattern := strings.TrimSuffix(filepath.Base(encPath), ".ipa") + "-minos-*.ipa"
	f, err := os.CreateTemp("", pattern)
	if err != nil {
		return patchResult{}, fmt.Errorf("create temp ipa: %w", err)
	}

	tmp := f.Name()
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return patchResult{}, fmt.Errorf("close temp ipa: %w", err)
	}
	if err := os.Remove(tmp); err != nil && !errors.Is(err, os.ErrNotExist) {
		return patchResult{}, fmt.Errorf("prepare temp ipa: %w", err)
	}

	changed, previous, err := pipeline.PatchMinOS(encPath, tmp, iosVersion)
	if err != nil {
		_ = os.Remove(tmp)
		return patchResult{}, err
	}

	if !changed {
		_ = os.Remove(tmp)
		return patchResult{uploadPath: encPath}, nil
	}

	return patchResult{
		uploadPath:    tmp,
		patchedPath:   tmp,
		changed:       true,
		previousMinOS: previous,
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

	bundlePath, err := dev.FindInstalled(helperPath, appDirName)
	if err != nil {
		return installPlan{}, fmt.Errorf("scan installed: %w", err)
	}

	return installPlan{
		helperPath:    helperPath,
		appinstPath:   appinstPath,
		bundlePath:    bundlePath,
		stagingRemote: filepath.ToSlash(filepath.Join(device.RemoteRoot, "staging", filepath.Base(uploadPath))),
	}, nil
}

func ensureInstalledBundle(dev *device.Client, plan installPlan, uploadPath string, onEvent func(installEvent)) (installResult, error) {
	notify := func(e installEvent) {
		if onEvent != nil {
			onEvent(e)
		}
	}

	if plan.bundlePath == "" {
		return installUploadedBundle(dev, plan, uploadPath, false, "", notify)
	}

	notify(installHashIPA)
	execName, wantSum, err := pipeline.MainExecSHA256(uploadPath)
	if err != nil {
		return installResult{}, fmt.Errorf("hash ipa: %w", err)
	}

	remoteExec := filepath.ToSlash(filepath.Join(plan.bundlePath, execName))
	notify(installHashInstalled)
	gotSum, err := dev.HashFile(plan.helperPath, remoteExec)
	if err != nil {
		return installResult{}, fmt.Errorf("hash device: %w", err)
	}

	if gotSum == wantSum {
		return installResult{
			bundlePath: plan.bundlePath,
		}, nil
	}

	notify(installReadInstalledVersion)
	previousVersion, err := dev.InstalledVersion(plan.bundlePath)
	if err != nil {
		previousVersion = ""
	}

	notify(installReplaceInstalled)
	return installUploadedBundle(dev, plan, uploadPath, true, previousVersion, notify)
}

func installUploadedBundle(dev *device.Client, plan installPlan, uploadPath string, reinstalled bool, previousVersion string, notify func(installEvent)) (installResult, error) {
	notify(installUpload)
	if err := dev.Upload(uploadPath, plan.stagingRemote); err != nil {
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
	bundlePath, err := dev.FindInstalled(plan.helperPath, appDirName)
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
	return filepath.ToSlash(
		filepath.Join(device.RemoteRoot, "work", fmt.Sprintf("%s_%s.ipa", bundleID, version)),
	)
}

func localOutputPath(bundleID, version string) (string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}

	return filepath.Join(cwd, fmt.Sprintf("%s_%s.decrypted.ipa", bundleID, version)), nil
}

func cleanupDecrypt(dev *device.Client, noCleanup bool, stagingRemote, outRemote string) {
	if noCleanup {
		return
	}

	_ = dev.Remove(stagingRemote)
	_ = dev.Remove(outRemote)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func (p *helperProgress) HandleEvent(ev device.Event) helperUpdate {
	switch ev.Name {
	case "bundle":
		return helperUpdate{spin: "analyzing main bundle"}

	case "plugin_start":
		p.pluginCount.Add(1)
		return helperUpdate{
			note: fmt.Sprintf("found extension %s", ev.Attr("name")),
			spin: fmt.Sprintf("decrypting extension %s", ev.Attr("name")),
		}

	case "spawn_failed":
		return helperUpdate{note: fmt.Sprintf("could not spawn %s (skipped)", ev.Attr("name"))}

	case "spawn_chmod":
		return helperUpdate{
			note: fmt.Sprintf("chmod +x on %s (was mode %s) to unblock spawn",
				filepath.Base(ev.Attr("path")), ev.Attr("old_mode")),
		}

	case "main":
		return helperUpdate{spin: fmt.Sprintf("decrypting main executable: %s", ev.Attr("name"))}

	case "dyld":
		switch ev.Attr("state") {
		case "resuming":
			return helperUpdate{spin: "letting dyld map frameworks"}
		case "crashed":
			return helperUpdate{note: "dyld crashed on a missing iOS symbol - frameworks mapped, proceeding"}
		}

	case "plan":
		var total int64
		fmt.Sscanf(ev.Attr("total"), "%d", &total)
		p.planTotal.Store(total)
		p.planDone.Store(0)

		if total == 0 {
			return helperUpdate{spin: "no frameworks to decrypt"}
		}

		return helperUpdate{
			progress:     true,
			progressCur:  0,
			progressMax:  total,
			progressText: fmt.Sprintf("decrypting %d framework(s)", total),
		}

	case "image":
		cur := p.planDone.Add(1)
		p.dumpedTotal.Add(1)

		name := ev.Attr("name")
		switch {
		case strings.Contains(name, ".framework/"):
			p.dumpedFrameworks.Add(1)
		case !strings.Contains(name, "/"):
			p.dumpedMain.Add(1)
		default:
			p.dumpedOther.Add(1)
		}

		display := name
		if len(display) > 48 {
			display = "…" + display[len(display)-47:]
		}

		return helperUpdate{
			progress:     true,
			progressCur:  cur,
			progressMax:  p.planTotal.Load(),
			progressText: display,
		}

	case "image_fail":
		return helperUpdate{note: fmt.Sprintf("failed to dump %s", ev.Attr("name"))}

	case "zip":
		return helperUpdate{spin: "packaging IPA on device"}
	}

	return helperUpdate{}
}

func (p *helperProgress) Summary() string {
	total := p.dumpedTotal.Load()
	main := p.dumpedMain.Load()
	frameworks := p.dumpedFrameworks.Load()
	other := p.dumpedOther.Load()
	plugins := p.pluginCount.Load()

	summary := fmt.Sprintf("decrypted %d image(s): %d main, %d framework", total, main, frameworks)
	if other > 0 {
		summary += fmt.Sprintf(", %d other", other)
	}
	if plugins > 0 {
		summary += fmt.Sprintf(" · %d extension(s)", plugins)
	}

	return summary
}
