package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/londek/ipadecrypt/internal/appstore"
	"github.com/londek/ipadecrypt/internal/config"
	"github.com/londek/ipadecrypt/internal/fairplay"
	"github.com/londek/ipadecrypt/internal/pipeline"
	"github.com/londek/ipadecrypt/internal/testflight"
	"github.com/londek/ipadecrypt/internal/tui"
	"github.com/spf13/cobra"
)

func testFlightAppsHandler(cmd *cobra.Command, _ []string) {
	cfg, paths, err := loadConfigOrDefault(rootDirOverride)
	if err != nil {
		tui.Err("%v", err)
		return
	}

	_, _, apps, err := openTestFlight(cmd.Context(), cfg, paths)
	if err != nil {
		tui.Err("list TestFlight apps: %v", err)
		return
	}

	if len(apps) == 0 {
		tui.Info("no TestFlight apps are available for this account")
		return
	}

	developer := ""
	for _, app := range apps {
		if app.DeveloperName != developer {
			developer = app.DeveloperName
			tui.Heading("%s", developer)
		}

		tui.Item("%s (%d)", app.Name, app.ID)
	}
}

func testFlightLinkHandler(cmd *cobra.Command, args []string) {
	code, err := testflight.ParsePublicLink(args[0])
	if err != nil {
		tui.Err("%v", err)
		return
	}

	cfg, paths, err := loadConfigOrDefault(rootDirOverride)
	if err != nil {
		tui.Err("%v", err)
		return
	}

	_, client, link, err := withTestFlightSession(cmd.Context(), cfg, paths, false, true,
		func(client *testflight.Client, ctx context.Context) (testflight.PublicLink, error) {
			return client.ResolvePublicLink(ctx, code)
		})
	if err != nil {
		tui.Err("preview TestFlight link: %v", err)
		return
	}

	renderTestFlightLink(link)

	if !testFlightLinkAccept {
		return
	}

	if err := link.AvailabilityError(); err != nil {
		tui.Err("accept TestFlight link: %v", err)
		return
	}

	if err := client.AcceptPublicLink(cmd.Context(), code); err != nil {
		tui.Err("accept TestFlight link: %v", err)
		return
	}

	tui.OK("accepted %s", link.App.Name)
}

func renderTestFlightLink(link testflight.PublicLink) {
	tui.Heading("%s", link.App.ProviderName)
	tui.Item("%s (%d)", link.App.Name, link.App.ID)

	if err := link.AvailabilityError(); err != nil {
		tui.Warn("%v", err)
		return
	}

	if warning := link.CompatibilityWarning(); warning != "" {
		tui.Warn("%s", warning)
	}
}

func testFlightVersionsHandler(cmd *cobra.Command, args []string) {
	appID, err := parseTestFlightAppID(args[0])
	if err != nil {
		tui.Err("%v", err)
		return
	}

	cfg, paths, err := loadConfigOrDefault(rootDirOverride)
	if err != nil {
		tui.Err("%v", err)
		return
	}

	_, client, apps, err := openTestFlight(cmd.Context(), cfg, paths)
	if err != nil {
		tui.Err("connect to TestFlight: %v", err)
		return
	}

	app, err := findTestFlightApp(apps, appID)
	if err != nil {
		tui.Err("%v", err)
		return
	}

	versions, err := client.ListVersions(cmd.Context(), appID)
	if err != nil {
		tui.Err("list TestFlight versions: %v", err)
		return
	}

	if len(versions) == 0 {
		tui.Info("no TestFlight versions are available for %s", app.Name)
		return
	}

	tui.Heading("%s", app.Name)

	for _, version := range versions {
		tui.Item("%s", version.Name)
	}
}

func testFlightDecryptHandler(cmd *cobra.Command, args []string) {
	appID, err := parseTestFlightAppID(args[0])
	if err != nil {
		tui.Err("%v", err)
		return
	}

	cfg, paths, err := loadConfigOrDefault(rootDirOverride)
	if err != nil {
		tui.Err("%v", err)
		return
	}

	credentials := fairplay.Credentials{}

	credentials.Standard, err = loadCachedCredential(paths, cfg.Apple.DirectoryServicesIdentifier, false)
	if err != nil {
		tui.Err("no decryption credential for this account: %v", err)
		tui.Info("run `ipadecrypt bootstrap` to mint it")

		return
	}

	credentials.Arcade, err = loadCachedCredential(paths, cfg.Apple.DirectoryServicesIdentifier, true)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		tui.Err("Apple Arcade credential: %v", err)
		return
	}

	_, client, apps, err := openTestFlight(cmd.Context(), cfg, paths)
	if err != nil {
		tui.Err("connect to TestFlight: %v", err)
		return
	}

	app, err := findTestFlightApp(apps, appID)
	if err != nil {
		tui.Err("%v", err)
		return
	}

	deviceID := testFlightUDID
	if deviceID == "" {
		deviceID = cfg.TestFlight.DeviceID
	}

	if deviceID == "" {
		deviceID = cfg.Device.UDID
	}

	live := tui.NewLive()
	live.Spin("selecting a build for %s", app.Name)

	build, err := client.SelectBuild(cmd.Context(), appID, testFlightVersion)
	if err != nil {
		live.Fail("select TestFlight build: %v", err)
		return
	}

	live.OK("selected %s %s", app.Name, build.Version)

	encryptedPath, err := paths.CachedTestFlightIPA(cfg.Apple.DirectoryServicesIdentifier, build.Version, build.AppID, build.BuildID)
	if err != nil {
		tui.Err("cache path: %v", err)
		return
	}

	bundleID := build.BundleID
	if cachedTestFlightPackageMatches(encryptedPath, bundleID, build.Version) {
		tui.OK("using cached TestFlight IPA")
	} else {
		live = tui.NewLive()
		live.Spin("authorizing %s", app.Name)

		ticket, err := client.AuthorizeDownload(cmd.Context(), build, deviceID)
		if err != nil {
			live.Fail("authorize TestFlight download: %v", err)
			return
		}

		bundleID = ticket.BundleID()

		live.Spin("downloading TestFlight IPA")

		err = client.CompleteDownload(cmd.Context(), cfg.Apple.Account(), ticket, encryptedPath, func(current, total int64) {
			live.Message("%s", transferProgressText("downloading TestFlight IPA", current, total))
			live.Progress(current, total)
		})
		if err != nil {
			live.Fail("TestFlight download failed: %v", err)

			return
		}

		live.OK("downloaded %s %s", app.Name, build.Version)
	}

	outputPath, err := localOutputPath(decryptOutput, bundleID, build.Version)
	if err != nil {
		tui.Err("output path: %v", err)
		return
	}

	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		tui.Err("mkdir local: %v", err)
		return
	}

	if attemptOfflineDecrypt(encryptedPath, credentials, outputPath) == offlineNeedsDevice {
		tui.Err("this TestFlight build could not be fully decrypted offline")
	}
}

func parseTestFlightAppID(raw string) (int64, error) {
	raw = strings.TrimSpace(raw)

	appID, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || appID <= 0 {
		return 0, fmt.Errorf("invalid TestFlight app ID %q; run `ipadecrypt testflight apps`", raw)
	}

	return appID, nil
}

func findTestFlightApp(apps []testflight.App, appID int64) (testflight.App, error) {
	for _, app := range apps {
		if app.ID == appID {
			return app, nil
		}
	}

	return testflight.App{}, fmt.Errorf("app %d is not available in this TestFlight account", appID)
}

func cachedTestFlightPackageMatches(path, bundleID, version string) bool {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return false
	}

	cachedBundleID, cachedVersion, err := pipeline.AppInfo(path)

	return err == nil && cachedBundleID == bundleID && cachedVersion == version
}

func openTestFlight(ctx context.Context, cfg *config.Config, paths *config.Paths) (*appstore.Client, *testflight.Client, []testflight.App, error) {
	return withTestFlightSession(ctx, cfg, paths, false, true, (*testflight.Client).ListApps)
}

// Run a read operation with the saved session, authenticating once if needed.
func withTestFlightSession[T any](ctx context.Context, cfg *config.Config, paths *config.Paths, forceLogin, interactive bool, read func(*testflight.Client, context.Context) (T, error)) (*appstore.Client, *testflight.Client, T, error) {
	var zero T
	if cfg.Apple.DirectoryServicesIdentifier == "" {
		return nil, nil, zero, errors.New("no Apple account configured; run `ipadecrypt bootstrap` to sign in")
	}

	deviceID, err := testFlightDownloadIdentity(testFlightUDID, cfg.TestFlight.DeviceID, cfg.Device.UDID)
	if err != nil {
		return nil, nil, zero, err
	}

	store, err := appstore.New(filepath.Join(paths.Root, "cookies"))
	if err != nil {
		return nil, nil, zero, fmt.Errorf("open App Store session: %w", err)
	}

	newClient := func(session testflight.Session) (*testflight.Client, error) {
		return testflight.New(store, cfg.Apple.Account(), session)
	}
	session := testflight.Session{SessionID: cfg.TestFlight.SessionID, AccountID: cfg.TestFlight.AccountID}

	if !forceLogin {
		client, err := newClient(session)
		if err != nil {
			return nil, nil, zero, err
		}

		result, err := read(client, ctx)
		if !errors.Is(err, testflight.ErrSessionExpired) {
			if err == nil && cfg.TestFlight.DeviceID != deviceID {
				cfg.TestFlight.DeviceID = deviceID
				if err := cfg.Save(); err != nil {
					return nil, nil, zero, fmt.Errorf("save TestFlight device: %w", err)
				}
			}

			return store, client, result, err
		}
	}

	if cfg.Apple.Email == "" || cfg.Apple.Password == "" {
		return nil, nil, zero, errors.New("no saved Apple credentials; run `ipadecrypt bootstrap` to sign in")
	}

	tui.Info("authenticating to TestFlight…")

	client, err := newClient(testflight.Session{})
	if err != nil {
		return nil, nil, zero, err
	}

	var verify func() (string, error)
	if interactive {
		verify = func() (string, error) {
			return tui.Prompt("Apple sent a 6-digit code - enter it")
		}
	}

	session, err = client.Authenticate(ctx, cfg.Apple.Email, cfg.Apple.Password, verify)
	if err != nil {
		return nil, nil, zero, err
	}

	client, err = newClient(session)
	if err != nil {
		return nil, nil, zero, err
	}

	result, err := read(client, ctx)
	if err != nil {
		return nil, nil, zero, err
	}

	cfg.TestFlight = config.TestFlight{SessionID: session.SessionID, AccountID: session.AccountID, DeviceID: deviceID}
	if err := cfg.Save(); err != nil {
		return nil, nil, zero, fmt.Errorf("save TestFlight session: %w", err)
	}

	if !forceLogin {
		tui.OK("connected to TestFlight")
	}

	return store, client, result, nil
}

func testFlightDownloadIdentity(override, saved, configured string) (string, error) {
	valid := func(value string) bool {
		decoded, err := hex.DecodeString(value)
		return err == nil && len(decoded) == 20
	}
	if override != "" {
		if !valid(override) {
			return "", errors.New("TestFlight --udid must contain 40 hexadecimal digits")
		}

		return override, nil
	}

	for _, value := range []string{saved, configured} {
		if valid(value) {
			return value, nil
		}
	}

	var identity [20]byte
	if _, err := rand.Read(identity[:]); err != nil {
		return "", fmt.Errorf("create TestFlight download identity: %w", err)
	}

	return hex.EncodeToString(identity[:]), nil
}

func testFlightBootstrapHandler(cmd *cobra.Command, _ []string) {
	cfg, paths, err := loadConfigOrDefault(rootDirOverride)
	if err != nil {
		tui.Err("%v", err)
		return
	}

	if _, _, _, err := withTestFlightSession(cmd.Context(), cfg, paths, true, true, (*testflight.Client).ListApps); err != nil {
		tui.Err("authenticate TestFlight: %v", err)
		return
	}

	tui.OK("authenticated to TestFlight")
	tui.Info("run `ipadecrypt testflight apps` to list available apps")
}
