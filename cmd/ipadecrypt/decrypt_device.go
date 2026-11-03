package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync/atomic"

	"github.com/londek/ipadecrypt/internal/config"
	"github.com/londek/ipadecrypt/internal/device"
	"github.com/londek/ipadecrypt/internal/pipeline"
	"github.com/londek/ipadecrypt/internal/tui"
)

var errAppinstNotFound = errors.New("appinst not found")

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
	bundleID      string
	bundlePath    string
	stagingRemote string
}

type installResult struct {
	bundlePath      string
	installed       bool
	reinstalled     bool
	previousVersion string
}

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

// runDeviceDecrypt performs the on-device FairPlay decrypt fallback: it
// connects to the configured jailbroken device, installs the host-side
// encrypted IPA, runs the inject + mremap_encrypted helper to decrypt every
// slice (incl. the 32-bit slice the offline path cannot), assembles the
// decrypted IPA at outLocal by fusing the helper's Mach-Os into the source
// IPA, and re-verifies. encPath is the encrypted source IPA already on the
// host; cleanups owns device teardown so it runs on a live session.
func runDeviceDecrypt(cfg *config.Config, cleanups *cleanupStack, encPath, appBundleID, appVersion, outLocal string) error {
	live := tui.NewLive()
	live.Spin("connecting to %s", deviceEndpoint(cfg.Device))

	dev, err := device.Connect(context.Background(), cfg.Device)
	if err != nil {
		live.Fail("device connect failed: %v", err)
		return err
	}

	// dev.Close pushed first so it runs LAST: remote rm/uninstall need a
	// live SSH session.
	cleanups.push(dev.Close)

	var (
		uninstall           bool
		uninstallBundleID   string
		uninstallBundlePath string
	)

	cleanups.push(func() {
		if !uninstall || uninstallBundlePath == "" {
			return
		}

		if err := dev.Uninstall(uninstallBundlePath); err != nil {
			tui.Err("uninstall %s: %v", uninstallBundleID, err)
			return
		}

		tui.OK("uninstalled %s", uninstallBundleID)
	})

	live.Spin("probing device")

	probe, err := dev.Probe()
	if err != nil {
		live.Fail("probe failed: %v", err)
		return err
	}

	live.OK("%s · iOS %s %s %s (%s)", deviceEndpoint(cfg.Device), probe.IOSVersion, probe.Arch, probe.Model, probe.Jailbreak)

	live = tui.NewLive()
	live.Spin("patching Info.plist for %s", probe.IOSVersion)

	patch, err := patchSourceForDevice(encPath, probe.IOSVersion, probe.DeviceFamily, decryptPatchDevType)
	if err != nil {
		var dfErr *pipeline.ErrDeviceFamilyMismatch
		if errors.As(err, &dfErr) {
			live.Fail("device family mismatch: app supports %v, device is %d (%s) - pass --patch-device-type to install anyway",
				dfErr.Supported, dfErr.Device, pipeline.DeviceFamilyName(dfErr.Device))

			return err
		}

		live.Fail("patch Info.plist failed: %v", err)

		return err
	}

	cleanups.push(func() {
		if patch.patchedPath != "" {
			os.Remove(patch.patchedPath)
		}
	})

	live.OK("patched Info.plist")

	if patch.changed {
		tui.OK("MinimumOSVersion %s → %s", patch.previousMinOS, probe.IOSVersion)
	}

	if patch.deviceFamilyExpanded {
		tui.OK("UIDeviceFamily %v → %v", patch.previousDeviceFamily, patch.newDeviceFamily)
	}

	if patch.watchStripped > 0 {
		tui.OK("stripped %d Watch/ entries", patch.watchStripped)
	}

	live = tui.NewLive()
	live.Spin("preparing install plan")

	plan, err := buildInstallPlan(dev, patch.uploadPath, appBundleID)
	if err != nil {
		if errors.Is(err, errAppinstNotFound) {
			live.Fail("appinst not found on device - install AppSync Unified + appinst, then re-run")
		} else {
			live.Fail("prepare install: %v", err)
		}

		return err
	}

	cleanups.push(func() {
		if plan.stagingRemote != "" {
			dev.Remove(plan.stagingRemote)
		}
	})

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
		return err
	}

	switch {
	case install.reinstalled:
		live.OK("reinstalled (%s => %s) → %s", install.previousVersion, appVersion, install.bundlePath)
	case install.installed:
		live.OK("installed → %s", install.bundlePath)
	default:
		live.OK("already installed → %s", install.bundlePath)
	}

	uninstall = decideUninstall(install.installed || install.reinstalled, decryptForceUninstall, decryptNoUninstall)
	uninstallBundleID = appBundleID
	uninstallBundlePath = install.bundlePath

	return decryptInstalledBundle(dev, cleanups, plan.helperPath, appBundleID, install.bundlePath, encPath, outLocal)
}

// decideUninstall picks the post-decrypt cleanup behavior. weInstalledIt
// is true when this run put the bundle on the device (fresh install or
// reinstall over a different version). force/no come from the flags.
func decideUninstall(weInstalledIt, force, no bool) bool {
	switch {
	case force:
		return true
	case no:
		return false
	}

	return weInstalledIt
}

// decryptInstalledBundle runs the helper on an installed bundle, fuses the
// decrypted Mach-Os it streams into the source IPA at outLocal, and verifies.
func decryptInstalledBundle(dev *device.Client, cleanups *cleanupStack, helperPath, bundleID, bundlePath, srcIPAPath, outLocal string) error {
	outFile, err := os.OpenFile(outLocal, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("open local: %w", err)
	}

	// Best-effort: drop the partially-written IPA on any error return.
	// Cleared after we commit on success.
	abandonLocal := true

	cleanups.push(func() {
		outFile.Close()

		if abandonLocal {
			os.Remove(outLocal)
		}
	})

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

	cw := &countingWriter{w: outFile, onTick: func(n int64) {
		live.Message("writing IPA → %s", humanBytes(n))
	}}

	// Host-side assembly: the helper streams decrypted Mach-Os on stdout;
	// the host fuses them with the (unpatched) source IPA into outFile, so
	// the output keeps the original Info.plist and layout.
	assembleErr := pipeline.Assemble(srcIPAPath, cw, func(write pipeline.SubstituteWriter) error {
		code, err := dev.RunHelperExecs(helperPath, bundleID, bundlePath, decryptVerbose, decryptSkipAppex, onEvent, func(name string, _ int64, r io.Reader) error {
			return write(name, r)
		})
		if err != nil {
			return fmt.Errorf("helper run: %w", err)
		}

		if code != 0 {
			return fmt.Errorf("helper exit %d", code)
		}

		return nil
	})
	if assembleErr != nil {
		live.Fail("assemble: %v", assembleErr)
		return assembleErr
	}

	if err := outFile.Sync(); err != nil {
		live.Fail("sync local: %v", err)
		return err
	}

	live.OK("%s (%s → %s)", progress.Summary(), humanBytes(cw.n), outLocal)

	abandonLocal = false

	if decryptNoVerify {
		return nil
	}

	compareSource := decryptExtraVerify

	src := ""
	if compareSource {
		src = srcIPAPath
	}

	live = tui.NewLive()
	if compareSource {
		live.Spin("verifying Mach-Os (cryptid, zero-fill, source byte-compare)")
	} else {
		live.Spin("verifying Mach-Os (cryptid, zero-fill)")
	}

	res, err := pipeline.Verify(outLocal, src, decryptSkipAppex)
	if err != nil {
		live.Fail("verify failed: %v", err)
		return err
	}

	if !res.OK() {
		live.Fail("verify failed: %s", verifyFailureSummary(res))

		for _, n := range res.StillEncrypted {
			tui.Info("  %s still encrypted (cryptid != 0)", n)
		}

		for _, n := range res.AllZeroCrypt {
			tui.Info("  %s crypt region all zeros", n)
		}

		for _, m := range res.Mismatches {
			tui.Info("  %s %s", m.Name, m.Reason)
		}

		return errors.New("verification failed")
	}

	live.OK("%s", verifyOKSummary(res, compareSource))

	return nil
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

	res, err := pipeline.PatchForInstall(encPath, tmp, iosVersion, deviceFamily, patchDeviceType)
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

func buildInstallPlan(dev *device.Client, uploadPath, bundleID string) (installPlan, error) {
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

	bundlePath, _, err := dev.FindInstalledByBundleID(bundleID)
	if err != nil {
		return installPlan{}, fmt.Errorf("scan installed: %w", err)
	}

	return installPlan{
		helperPath:    helperPath,
		appinstPath:   appinstPath,
		bundleID:      bundleID,
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
		return installResult{bundlePath: plan.bundlePath}, nil
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

	notify(installRescan)

	bundlePath, _, err := dev.FindInstalledByBundleID(plan.bundleID)
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

// deviceEndpoint renders a short label for the configured connection.
func deviceEndpoint(dev config.Device) string {
	if dev.USB {
		if dev.UDID != "" {
			return "usb:" + dev.UDID
		}

		return "usb"
	}

	if dev.User != "" {
		return dev.User + "@" + dev.Host
	}

	return dev.Host
}

// HandleEvent renders one helper event into a TUI update. The helper
// embeds a human-readable `msg` attribute on every event, so this
// function mostly just relays msg as the note, with per-event spinner
// updates and counters layered on top.
func (p *helperProgress) HandleEvent(ev device.Event) helperUpdate {
	upd := helperUpdate{note: ev.Attr("msg")}

	switch ev.Name {
	// Spinner-only events: progress indicator, no note line.
	case "bundle.begin":
		upd.note = ""
		upd.spin = fmt.Sprintf("decrypting %s", path.Base(ev.Attr("src")))
	case "dyld.resuming":
		upd.note = ""
		upd.spin = "running target"
	case "image.begin":
		upd.note = ""
		upd.spin = fmt.Sprintf("decrypting %s", ev.Attr("name"))
	case "pack.begin":
		upd.note = ""

		ipa := ev.Attr("ipa")
		if ipa == "-" {
			upd.spin = "packaging IPA → stdout"
		} else {
			upd.spin = fmt.Sprintf("packaging IPA → %s", path.Base(ipa))
		}

	// Counters + spinner update on each successful dump.
	case "image.done":
		p.dumpedTotal.Add(1)

		switch ev.Attr("kind") {
		case "main":
			p.dumpedMain.Add(1)
		case "framework":
			p.dumpedFrameworks.Add(1)
		default:
			p.dumpedOther.Add(1)
		}

		upd.spin = fmt.Sprintf("decrypted %d image(s)", p.dumpedTotal.Load())

	// Suppress empty-result bundle.done so the TUI stays quiet on appex
	// passes that produce no extras.
	case "bundle.done":
		if ev.Attr("extras") == "0" {
			upd.note = ""
		}

	// Trap on the benign dyld halt brk is silent  the helper catches it
	// on purpose so the address space stays readable; nothing to surface.
	case "dyld.trapped":
		if ev.Attr("exception") == "EXC_BREAKPOINT" {
			upd.note = ""
		}

	// Pure diagnostics that show up only in --verbose runs.
	case "target.csflags",
		"patch.scan_skipped", "patch.skipped", "patch.dyld_base_diff",
		"dyld.settled", "dyld.fault_skip", "dyld.pac_stripped",
		"staging.begin", "done":
		upd.note = ""
	}

	// Catch-all for unknown event names: fall back to msg attr (already
	// set above). If a future event lacks msg, render attrs verbatim so
	// nothing is silently lost.
	if upd.note == "" && upd.spin == "" && ev.Attr("msg") == "" {
		parts := []string{"event=" + ev.Name}
		for k, v := range ev.Attrs {
			if k == "event" || k == "level" {
				continue
			}

			parts = append(parts, fmt.Sprintf("%s=%q", k, v))
		}

		upd.note = strings.Join(parts, " ")
	}

	return upd
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
