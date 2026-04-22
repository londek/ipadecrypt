package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/londek/ipadecrypt/internal/appstore"
	"github.com/londek/ipadecrypt/internal/config"
	"github.com/londek/ipadecrypt/internal/tui"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// versionsTarget is the subset of decryptTarget that makes sense for the
// versions command - a local .ipa path has no App Store versions to list.
type versionsTarget struct {
	bundleId string
	appId    string
}

func parseVersionsArg(raw string) (versionsTarget, error) {
	dt, err := parseDecryptArg(raw)
	if err != nil {
		return versionsTarget{}, err
	}
	if dt.localPath != "" {
		return versionsTarget{}, errors.New("versions: local IPA paths are not supported - pass a bundle-id or app-store-id")
	}

	return versionsTarget{bundleId: dt.bundleId, appId: dt.appId}, nil
}

func versionsHandler(cmd *cobra.Command, args []string) error {
	ctx, cancel := notifyContext()
	defer cancel()
	_ = ctx

	cfg, paths, err := loadConfigOrDefault(rootDirOverride)
	if err != nil {
		tui.Err("%v", err)
		return err
	}

	target, err := parseVersionsArg(args[0])
	if err != nil {
		tui.Err("%v", err)
		return err
	}

	if cfg.Apple.Account == nil {
		tui.Err("environment not configured")
		tui.Info("run `ipadecrypt bootstrap` first to sign in")
		return errEnvironmentNotConfigured
	}

	if !cfg.Versions.WarningAccepted {
		if err := showVersionsWarning(); err != nil {
			return err
		}
		cfg.Versions.WarningAccepted = true
		if err := cfg.Save(); err != nil {
			tui.Err("save config: %v", err)
			return err
		}
	}

	as, err := appstore.New(filepath.Join(paths.Root, "cookies"))
	if err != nil {
		tui.Err("appstore client: %v", err)
		return err
	}

	live := tui.NewLive()
	if target.appId != "" {
		live.Spin("resolving appId %s", target.appId)
	} else {
		live.Spin("resolving bundleId %s", target.bundleId)
	}

	app, err := lookupVersionsTargetApp(as, cfg.Apple.Account, target)
	if err != nil {
		live.Fail("lookup failed")
		tui.Err("lookup: %v", err)
		return err
	}

	live.OK("found %s (%s)", app.BundleID, app.Name)

	var logPath string
	if versionsLogResponses {
		p, err := paths.VersionsLog()
		if err != nil {
			tui.Err("log path: %v", err)
			return err
		}
		logPath = p
	}

	live = tui.NewLive()
	live.Spin("listing versions for %s", app.BundleID)

	list, err := listVersionsWithAuth(cfg, as, app)
	if err != nil {
		live.Fail("list versions failed")
		tui.Err("list: %v", err)
		return err
	}

	logVersionsResponse(logPath, "list_versions", app.BundleID, "", list.Raw)

	live.OK("%d version(s), latest %s", len(list.ExternalVersionIDs), list.LatestExternalVersionID)

	cachePath, err := paths.VersionsCacheFile(app.BundleID)
	if err != nil {
		tui.Err("cache path: %v", err)
		return err
	}

	cache, err := loadVersionsCache(cachePath)
	if err != nil {
		tui.Warn("load cache: %v (starting fresh)", err)
		cache = &versionsCache{BundleID: app.BundleID, Versions: map[string]cachedVersion{}}
	}
	if cache.Versions == nil {
		cache.Versions = map[string]cachedVersion{}
	}
	cache.BundleID = app.BundleID

	return runVersionsTUI(cfg, as, app, list, cache, cachePath, logPath)
}

func lookupVersionsTargetApp(as *appstore.Client, acc *appstore.Account, target versionsTarget) (appstore.App, error) {
	if target.appId != "" {
		return as.LookupByAppID(acc, target.appId)
	}
	return as.LookupByBundleID(acc, target.bundleId)
}

func listVersionsWithAuth(cfg *config.Config, as *appstore.Client, app appstore.App) (appstore.ListVersionsOutput, error) {
	return withAuth(cfg, as, app, 3, nil, func() (appstore.ListVersionsOutput, error) {
		return as.ListVersions(cfg.Apple.Account, app)
	})
}

func getVersionMetadataWithAuth(cfg *config.Config, as *appstore.Client, app appstore.App, extVerID string) (appstore.VersionMetadata, error) {
	return withAuth(cfg, as, app, 3, nil, func() (appstore.VersionMetadata, error) {
		return as.GetVersionMetadata(cfg.Apple.Account, app, extVerID)
	})
}

// ---- warning ------------------------------------------------------------

func showVersionsWarning() error {
	w := tui.Out
	fmt.Fprintln(w)
	fmt.Fprintln(w, "  \x1b[31;1m⚠  Warning\x1b[0m")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "  Listing every App Store version of an app requires a separate")
	fmt.Fprintln(w, "  request to Apple's private endpoint for each version you open.")
	fmt.Fprintln(w, "  Making many of these in a short time can get your Apple ID")
	fmt.Fprintln(w, "  \x1b[33mflagged, rate-limited, or permanently banned\x1b[0m. ipadecrypt fetches")
	fmt.Fprintln(w, "  only the 3 newest versions eagerly; older versions are fetched")
	fmt.Fprintln(w, "  only when you explicitly press Enter on their row. Results are")
	fmt.Fprintln(w, "  cached on disk and re-used across runs.")
	fmt.Fprintln(w)
	fmt.Fprint(w, "  Press \x1b[1mEnter\x1b[0m to accept and continue, or \x1b[1mCtrl-C\x1b[0m to exit.")

	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return errors.New("versions: stdin is not a terminal")
	}

	old, err := term.MakeRaw(fd)
	if err != nil {
		return err
	}
	defer term.Restore(fd, old)

	buf := make([]byte, 4)
	for {
		n, err := os.Stdin.Read(buf)
		if err != nil {
			return err
		}
		if n == 0 {
			continue
		}
		switch buf[0] {
		case '\r', '\n':
			fmt.Fprintln(w)
			return nil
		case 0x03, 0x04: // Ctrl-C, Ctrl-D
			fmt.Fprintln(w)
			return errors.New("aborted")
		}
	}
}

// ---- cache --------------------------------------------------------------

type versionsCache struct {
	BundleID  string                   `json:"bundleId"`
	UpdatedAt time.Time                `json:"updatedAt"`
	Versions  map[string]cachedVersion `json:"versions"`
}

type cachedVersion struct {
	FetchedAt        time.Time      `json:"fetchedAt"`
	DisplayVersion   string         `json:"displayVersion,omitempty"`
	BundleVersion    string         `json:"bundleVersion,omitempty"`
	SupportedDevices []int          `json:"supportedDevices,omitempty"`
	ReleaseDate      time.Time      `json:"releaseDate,omitempty"`
	Raw              map[string]any `json:"raw,omitempty"`
}

// reconcileFromRaw fills typed fields from Raw when they're missing.
// This is how we migrate cache entries written before a typed field
// was introduced: the Raw dict still has the data, we just didn't
// copy it out at the time.
func (v *cachedVersion) reconcileFromRaw() {
	if v.Raw == nil {
		return
	}
	if v.DisplayVersion == "" {
		if s, ok := v.Raw["bundleShortVersionString"].(string); ok {
			v.DisplayVersion = s
		}
	}
	if v.BundleVersion == "" {
		if s, ok := v.Raw["bundleVersion"].(string); ok {
			v.BundleVersion = s
		}
	}
	if len(v.SupportedDevices) == 0 {
		if arr, ok := v.Raw["softwareSupportedDeviceIds"].([]any); ok {
			for _, e := range arr {
				switch n := e.(type) {
				case float64:
					v.SupportedDevices = append(v.SupportedDevices, int(n))
				case int:
					v.SupportedDevices = append(v.SupportedDevices, n)
				case int64:
					v.SupportedDevices = append(v.SupportedDevices, int(n))
				}
			}
		}
	}
}

func loadVersionsCache(path string) (*versionsCache, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &versionsCache{Versions: map[string]cachedVersion{}}, nil
		}
		return nil, err
	}

	c := &versionsCache{}
	if err := json.Unmarshal(data, c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if c.Versions == nil {
		c.Versions = map[string]cachedVersion{}
	}
	for k, v := range c.Versions {
		v.reconcileFromRaw()
		c.Versions[k] = v
	}
	return c, nil
}

func (c *versionsCache) save(path string) error {
	c.UpdatedAt = time.Now().UTC()

	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}

	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// ---- response logging ---------------------------------------------------

var versionsLogMu sync.Mutex

// logVersionsResponse appends a JSONL record of one API response to path.
// Best-effort: failures are swallowed so logging never blocks the UI.
func logVersionsResponse(path, kind, bundleID, extVerID string, raw map[string]any) {
	if path == "" || raw == nil {
		return
	}

	rec := map[string]any{
		"ts":       time.Now().UTC().Format(time.RFC3339Nano),
		"kind":     kind,
		"bundleId": bundleID,
		"extVerId": extVerID,
		"metadata": raw,
	}

	data, err := json.Marshal(rec)
	if err != nil {
		return
	}

	versionsLogMu.Lock()
	defer versionsLogMu.Unlock()

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return
	}
	defer f.Close()

	_, _ = f.Write(append(data, '\n'))
}
