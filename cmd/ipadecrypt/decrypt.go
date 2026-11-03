package main

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"

	"github.com/londek/ipadecrypt/internal/appstore"
	"github.com/londek/ipadecrypt/internal/config"
	"github.com/londek/ipadecrypt/internal/fairplay"
	"github.com/londek/ipadecrypt/internal/pipeline"
	"github.com/londek/ipadecrypt/internal/tui"
	"github.com/londek/ipadecrypt/internal/updater"
	"github.com/spf13/cobra"
)

var appStoreIdRegex = regexp.MustCompile(`/id(\d+)`)

type decryptTarget struct {
	localPath string
	bundleId  string
	appId     string
}

type sourceDisposition byte

const (
	sourceDispositionCached sourceDisposition = iota + 1
	sourceDispositionDownloaded
)

func parseDecryptArg(raw string) (decryptTarget, error) {
	// App Store URL
	if strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://") {
		u, err := url.Parse(raw)
		if err != nil {
			return decryptTarget{}, fmt.Errorf("parse url: %w", err)
		}

		m := appStoreIdRegex.FindStringSubmatch(u.Path)
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
	if decryptOnDevice && decryptNoOnDevice {
		tui.Err("--on-device and --no-on-device are mutually exclusive; pass at most one.")
		return
	}

	if decryptForceUninstall && decryptNoUninstall {
		tui.Err("--force-uninstall and --no-uninstall are mutually exclusive; pass at most one.")
		return
	}

	cfg, paths, err := loadConfigOrDefault(rootDirOverride)
	if err != nil {
		tui.Err("%v", err)
		return
	}

	upd := updater.Start(context.Background(), resolveVersion(), cfg)
	defer upd.Wait()

	target, err := parseDecryptArg(args[0])
	if err != nil {
		tui.Err("%v", err)
		return
	}

	// The decryption credential is required only for the offline path;
	// --on-device decrypts via the device's own FairPlay and skips it.
	var credential []byte

	if !decryptOnDevice {
		dsid := cfg.Apple.DirectoryServicesIdentifier
		if dsid == "" {
			tui.Err("no Apple account configured")
			tui.Info("run `ipadecrypt bootstrap` to sign in and mint your decryption credential")

			return
		}

		credential, err = loadCachedCredential(paths, dsid)
		if err != nil {
			tui.Err("no decryption credential for this account: %v", err)
			tui.Info("run `ipadecrypt bootstrap` to mint it (one-time, needs your jailbroken device)")

			return
		}
	}

	cleanups := &cleanupStack{}
	defer cleanups.run()

	sigCh := make(chan os.Signal, 1)

	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	go func() {
		sig, ok := <-sigCh
		if !ok {
			return
		}

		signal.Reset(syscall.SIGINT, syscall.SIGTERM)
		tui.Warn("interrupted (%v), cleaning up (press again to force quit)", sig)
		cleanups.run()
		os.Exit(130)
	}()

	//
	// Acquire the encrypted IPA, either from the App Store or a local path.
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
		if cfg.Apple.Email == "" {
			tui.Err("this app must be downloaded from the App Store, but no Apple ID is configured")
			tui.Info("run `ipadecrypt bootstrap` to sign in, or decrypt a local .ipa instead")

			return
		}

		as, err := appstore.New(filepath.Join(paths.Root, "cookies"))
		if err != nil {
			tui.Err("appstore client: %v", err)
			return
		}

		acc, err := accountWithStorefront(cfg, decryptStorefront)
		if err != nil {
			tui.Err("storefront: %v", err)
			return
		}

		appStoreCountry, err := appstore.CountryCodeFromStoreFront(acc.StoreFront)
		if err != nil {
			tui.Err("resolve appstore country code: %v", err)
			return
		}

		tui.OK("signed in as %s (%s storefront)", redact(acc.Email), redact(appStoreCountry))

		live := tui.NewLive()

		if target.appId != "" {
			live.Spin("resolving appId %s", target.appId)
		} else {
			live.Spin("resolving bundleId %s", target.bundleId)
		}

		app, err := lookupTargetApp(as, acc, target)
		if err != nil {
			live.Fail("lookup failed (%s): %v", appStoreCountry, err)
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

			if errors.Is(err, appstore.ErrPaidAppNotOwned) {
				live.Fail("paid app not owned by %s. sign in with the Apple ID that purchased it", redact(acc.Email))
				return
			}

			if errors.Is(err, appstore.ErrModernDownloadUnsupported) {
				live.Fail("can't download this build from the App Store yet")
				tui.Info("Apple now requires device attestation for this app's current build; its download endpoints answer HTTP 403.")
				tui.Info("ipadecrypt doesn't implement that yet. Decrypt a local .ipa instead: `ipadecrypt decrypt <file>.ipa`")

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
	// Decrypt: offline FairPlay first (no device); fall back to on-device
	// decryption for apps the arm64-only offline path can't fully handle
	// (e.g. old builds that still ship a 32-bit slice).
	//

	outLocal, err := localOutputPath(decryptOutput, appBundleID, appVersion)
	if err != nil {
		tui.Err("output path: %v", err)
		return
	}

	if err := os.MkdirAll(filepath.Dir(outLocal), 0o755); err != nil {
		tui.Err("mkdir local: %v", err)
		return
	}

	deviceConfigured := cfg.Device.Host != "" || cfg.Device.USB

	if !decryptOnDevice {
		switch attemptOfflineDecrypt(encPath, credential, outLocal) {
		case offlineDone, offlineFatal:
			return
		}

		// offlineNeedsDevice: the offline arm64 decrypt left a slice
		// encrypted (or couldn't handle the app). Decide on the fallback.
		switch {
		case decryptNoOnDevice:
			tui.Warn("offline decrypt left encrypted slice(s); on-device fallback suppressed (--no-on-device)")
			return
		case !deviceConfigured:
			tui.Err("offline decryption couldn't fully decrypt this app (commonly an old build that still ships a 32-bit slice); on-device decryption is required")
			tui.Info("run `ipadecrypt bootstrap` to set up your jailbroken device, then re-run")

			return
		}

		tui.Info("falling back to on-device decryption")
	} else if !deviceConfigured {
		tui.Err("--on-device needs a configured jailbroken device")
		tui.Info("run `ipadecrypt bootstrap` to set one up")

		return
	}

	if err := runDeviceDecrypt(cfg, cleanups, encPath, appBundleID, appVersion, outLocal); err != nil {
		return
	}
}

type offlineOutcome int

const (
	offlineDone offlineOutcome = iota
	offlineNeedsDevice
	offlineFatal
)

// attemptOfflineDecrypt runs the no-device FairPlay decrypt into outLocal and
// verifies it. It returns offlineDone when the output verifies, offlineFatal
// for an error already surfaced to the user (e.g. a credential that belongs to
// a different account), and offlineNeedsDevice when the arm64-only offline path
// couldn't fully decrypt the app (a still-encrypted 32-bit slice, or an app it
// can't parse) - the caller then decides whether to fall back to the device.
// On any non-done outcome the partial output is removed so a fallback writes a
// clean file.
func attemptOfflineDecrypt(encPath string, credential []byte, outLocal string) offlineOutcome {
	outFile, err := os.OpenFile(outLocal, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		tui.Err("open local: %v", err)
		return offlineFatal
	}

	keep := false

	defer func() {
		outFile.Close()

		if !keep {
			os.Remove(outLocal)
		}
	}()

	live := tui.NewLive()
	live.Spin("decrypting %s", filepath.Base(encPath))

	cw := &countingWriter{w: outFile, onTick: func(n int64) {
		live.Message("writing IPA → %s", humanBytes(n))
	}}

	summary, err := fairplay.Decrypt(encPath, cw, credential, decryptSkipAppex)
	if err != nil {
		if strings.Contains(err.Error(), "does not decode this SINF") {
			live.Fail("decrypt failed: %v", err)
			tui.Info("this credential belongs to a different Apple account; sign in with the account that owns the app and re-run `ipadecrypt bootstrap --remint`")

			return offlineFatal
		}

		// Offline couldn't decrypt this app at all; let the device try.
		live.Fail("offline decrypt failed: %v", err)

		return offlineNeedsDevice
	}

	if err := outFile.Sync(); err != nil {
		live.Fail("sync local: %v", err)
		return offlineFatal
	}

	live.OK("decrypted %d binary(s), %d page(s) (%s → %s)", summary.Binaries, summary.Pages, humanBytes(cw.n), outLocal)

	if decryptVerbose {
		tui.Info("output: %s", outLocal)
	}

	if decryptNoVerify {
		keep = true
		return offlineDone
	}

	compareSource := decryptExtraVerify

	src := ""
	if compareSource {
		src = encPath
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
		return offlineFatal
	}

	if res.OK() {
		live.OK("%s", verifyOKSummary(res, compareSource))

		keep = true

		return offlineDone
	}

	// A failure whose only symptom is still-encrypted slices is the 32-bit
	// (armv7) gap the arm64-only offline decryptor can't close - hand it to
	// the device fallback.
	if len(res.StillEncrypted) > 0 && len(res.AllZeroCrypt) == 0 && len(res.Mismatches) == 0 {
		live.Fail("%d slice(s) still encrypted (32-bit; offline decrypt is arm64-only)", len(res.StillEncrypted))

		for _, n := range res.StillEncrypted {
			tui.Info("  %s still encrypted (cryptid != 0)", n)
		}

		return offlineNeedsDevice
	}

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

	return offlineFatal
}

func verifyOKSummary(res pipeline.VerifyResult, compareSource bool) string {
	var b strings.Builder

	fmt.Fprintf(&b, "%d Mach-O(s) verified", res.Scanned)

	if compareSource {
		fmt.Fprintf(&b, ", %d source-matched", res.Compared)
	}

	var extras []string
	if len(res.Missing) > 0 {
		extras = append(extras, fmt.Sprintf("%d source-missing", len(res.Missing)))
	}

	if len(res.Skipped) > 0 {
		extras = append(extras, fmt.Sprintf("%d skipped", len(res.Skipped)))
	}

	if len(extras) > 0 {
		fmt.Fprintf(&b, " (%s)", strings.Join(extras, ", "))
	}

	return b.String()
}

func verifyFailureSummary(res pipeline.VerifyResult) string {
	parts := make([]string, 0, 3)

	if n := len(res.StillEncrypted); n > 0 {
		parts = append(parts, fmt.Sprintf("%d still encrypted", n))
	}

	if n := len(res.AllZeroCrypt); n > 0 {
		parts = append(parts, fmt.Sprintf("%d all-zero crypt", n))
	}

	if n := len(res.Mismatches); n > 0 {
		parts = append(parts, fmt.Sprintf("%d source diff", n))
	}

	return strings.Join(parts, ", ")
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
		return as.PrepareDownload(cfg.Apple.Account(), app, extVerID)
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

	if _, err := as.CompleteDownload(cfg.Apple.Account(), ticket, encPath, onProgress); err != nil {
		return remoteSourceDisposition{}, fmt.Errorf("%w: %w", errRemoteDownloadFailed, err)
	}

	return remoteSourceDisposition{
		path:    encPath,
		version: ticket.Version(),
		kind:    sourceDispositionDownloaded,
	}, nil
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

// cleanupStack is a LIFO of best-effort cleanup callbacks. Drained on normal
// return (via defer) and on SIGINT/SIGTERM. Idempotent: a second run() is a
// no-op so the deferred run after signal-driven run is harmless.
type cleanupStack struct {
	mu  sync.Mutex
	fns []func()
}

func (c *cleanupStack) push(fn func()) {
	c.mu.Lock()
	c.fns = append(c.fns, fn)
	c.mu.Unlock()
}

func (c *cleanupStack) run() {
	c.mu.Lock()
	fns := c.fns
	c.fns = nil
	c.mu.Unlock()

	for i := len(fns) - 1; i >= 0; i-- {
		fns[i]()
	}
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
