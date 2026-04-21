package main

import (
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/londek/ipadecrypt/internal/appstore"
	"github.com/londek/ipadecrypt/internal/config"
	"github.com/londek/ipadecrypt/internal/tui"
	"github.com/spf13/cobra"
	"howett.net/plist"
)

func versionsHandler(cmd *cobra.Command, args []string) error {
	cfg, paths, err := loadConfigOrDefault(cacheDirOverride)
	if err != nil {
		tui.Err("%v", err)
		return err
	}

	target := ""
	if len(args) > 0 {
		target = args[0]
	}

	// --find-version: binary search for a version string among historical IDs
	if versionsFindVersion != "" {
		if target == "" {
			tui.Err("--find-version requires a bundle ID argument")
			return fmt.Errorf("missing bundle ID")
		}
		return findVersionHandler(cfg, paths, target, versionsFindVersion)
	}

	if target == "" {
		// No bundle ID: list what's in cache.
		cacheDir, cerr := paths.CacheDir()
		if cerr != nil {
			return cerr
		}
		entries, rerr := os.ReadDir(cacheDir)
		if rerr != nil {
			return rerr
		}
		seen := map[string]bool{}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".ipa") || strings.Contains(e.Name(), "-minos.tmp") {
				continue
			}
			parts := strings.SplitN(strings.TrimSuffix(e.Name(), ".ipa"), "_", 3)
			if len(parts) == 3 && !seen[parts[0]] {
				seen[parts[0]] = true
				fmt.Printf("  %s\n", parts[0])
			}
		}
		if len(seen) == 0 {
			tui.Warn("no cached IPAs found")
		}
		return nil
	}

	if cfg.Apple.Account == nil {
		tui.Err("not bootstrapped — run `ipadecrypt bootstrap` first")
		return errors.New("bootstrap required")
	}

	as, aerr := appstore.New(filepath.Join(paths.Root, "cookies"))
	if aerr != nil {
		return aerr
	}

	live := tui.NewLive()
	live.Spin("resolving %s", target)
	app, lerr := as.Lookup(*cfg.Apple.Account, target)
	if lerr != nil {
		live.Fail("lookup failed: %v", lerr)
		return lerr
	}
	live.OK("%s (trackId %d, current v%s)", app.BundleID, app.ID, app.Version)

	// Get version IDs — prefer cache (has full list), fall back to API.
	var allIDs []uint64
	idToVer := map[string]string{} // pre-seed from cached IPAs

	if cacheDir, cerr := paths.CacheDir(); cerr == nil {
		if entries, rerr := os.ReadDir(cacheDir); rerr == nil {
			for _, e := range entries {
				if e.IsDir() || !strings.HasSuffix(e.Name(), ".ipa") || strings.Contains(e.Name(), "-minos.tmp") {
					continue
				}
				parts := strings.SplitN(strings.TrimSuffix(e.Name(), ".ipa"), "_", 3)
				if len(parts) != 3 || parts[0] != target {
					continue
				}
				curID, ids := extractVersionIDs(filepath.Join(cacheDir, e.Name()))
				if len(ids) > len(allIDs) {
					allIDs = ids
				}
				if curID != "" && parts[2] != "" {
					idToVer[curID] = parts[2]
				}
			}
		}
	}

	if len(allIDs) == 0 {
		live.Spin("fetching version list from App Store…")
		currentID, ids, ferr := as.FetchVersionIDs(*cfg.Apple.Account, app)
		if errors.Is(ferr, appstore.ErrPasswordTokenExpired) {
			live.Note("re-authenticating…")
			acc, rerr := as.Login(cfg.Apple.Email, cfg.Apple.Password, "")
			if rerr != nil {
				live.Fail("re-auth failed: %v", rerr)
				return rerr
			}
			cfg.Apple.Account = &acc
			_ = cfg.Save()
			currentID, ids, ferr = as.FetchVersionIDs(acc, app)
		}
		if ferr != nil {
			live.Fail("fetch version IDs: %v", ferr)
			return ferr
		}
		allIDs = ids
		if currentID != "" && app.Version != "" {
			idToVer[currentID] = app.Version
		}
		live.OK("fetched %d version IDs", len(allIDs))
	}

	// Decide which IDs to display.
	show := allIDs
	if !versionsShowAll && len(show) > 30 {
		show = show[len(show)-30:]
	}

	reauth := func() {
		acc, rerr := as.Login(cfg.Apple.Email, cfg.Apple.Password, "")
		if rerr == nil {
			cfg.Apple.Account = &acc
			_ = cfg.Save()
		}
	}

	// Annotate: PeekVersion for IDs we don't already know. Collect results
	// first so the progress line doesn't interleave with output.
	type row struct {
		id  string
		ver string
	}
	rows := make([]row, len(show))
	for i, id := range show {
		idStr := fmt.Sprintf("%d", id)
		ver := idToVer[idStr]
		if ver == "" {
			fmt.Fprintf(os.Stderr, "\r  fetching version… %d/%d", i+1, len(show))
			v, perr := as.PeekVersion(*cfg.Apple.Account, app, idStr)
			if errors.Is(perr, appstore.ErrPasswordTokenExpired) {
				reauth()
				v, perr = as.PeekVersion(*cfg.Apple.Account, app, idStr)
			}
			if perr == nil {
				ver = v
				idToVer[idStr] = ver
			}
		}
		rows[i] = row{id: idStr, ver: ver}
	}
	fmt.Fprintf(os.Stderr, "\r%40s\r", "") // clear progress line

	skipped := len(allIDs) - len(show)
	if skipped > 0 {
		fmt.Printf("  ... %d older versions omitted (use --all to show all)\n", skipped)
	}
	for _, r := range rows {
		if r.ver != "" {
			fmt.Printf("  %s  ← v%s\n", r.id, r.ver)
		} else {
			fmt.Printf("  %s\n", r.id)
		}
	}
	fmt.Println()
	tui.Info("use: ipadecrypt decrypt %s --external-version-id <id>", target)
	return nil
}

// extractVersionIDs reads iTunesMetadata.plist from an IPA and returns:
// - the externalVersionId of this specific IPA
// - the full list of all historically available version IDs
func extractVersionIDs(ipaPath string) (current string, all []uint64) {
	zr, err := zip.OpenReader(ipaPath)
	if err != nil {
		return "", nil
	}
	defer zr.Close()

	for _, f := range zr.File {
		if f.Name != "iTunesMetadata.plist" {
			continue
		}

		rc, err := f.Open()
		if err != nil {
			return "", nil
		}
		defer rc.Close()

		data, err := io.ReadAll(rc)
		if err != nil {
			return "", nil
		}

		var meta map[string]interface{}
		if err := plist.NewDecoder(bytes.NewReader(data)).Decode(&meta); err != nil {
			return "", nil
		}

		if v, ok := meta["softwareVersionExternalIdentifier"]; ok {
			current = fmt.Sprintf("%v", v)
		}

		if v, ok := meta["softwareVersionExternalIdentifiers"]; ok {
			switch ids := v.(type) {
			case []interface{}:
				for _, id := range ids {
					switch n := id.(type) {
					case uint64:
						all = append(all, n)
					case int64:
						all = append(all, uint64(n))
					case float64:
						all = append(all, uint64(n))
					}
				}
			}
		}

		return current, all
	}
	return "", nil
}

// findVersionHandler performs a binary search over the historical version IDs
// to locate the one corresponding to targetVersion.
func findVersionHandler(cfg *config.Config, paths *config.Paths, bundleID, targetVersion string) error {
	if cfg.Apple.Account == nil {
		tui.Err("not bootstrapped — run `ipadecrypt bootstrap` first")
		return errors.New("bootstrap required")
	}

	// Load all IDs from any cached IPA for this bundle
	cacheDir, err := paths.CacheDir()
	if err != nil {
		return err
	}
	entries, err := os.ReadDir(cacheDir)
	if err != nil {
		return err
	}

	var allIDs []uint64
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".ipa") || strings.Contains(e.Name(), "-minos.tmp") {
			continue
		}
		parts := strings.SplitN(strings.TrimSuffix(e.Name(), ".ipa"), "_", 3)
		if len(parts) != 3 || parts[0] != bundleID {
			continue
		}
		_, ids := extractVersionIDs(filepath.Join(cacheDir, e.Name()))
		if len(ids) > len(allIDs) {
			allIDs = ids
		}
	}

	// Create App Store client and resolve the app (needed for PeekVersion calls).
	as, err := appstore.New(filepath.Join(paths.Root, "cookies"))
	if err != nil {
		return err
	}

	live := tui.NewLive()
	live.Spin("resolving %s", bundleID)
	app, err := as.Lookup(*cfg.Apple.Account, bundleID)
	if err != nil {
		live.Fail("lookup failed")
		return err
	}
	live.OK("%s (trackId %d)", app.BundleID, app.ID)

	if len(allIDs) == 0 {
		// No cached IPA — fetch the version list directly from the API.
		live.Spin("fetching version list from App Store…")
		_, ids, ferr := as.FetchVersionIDs(*cfg.Apple.Account, app)
		if errors.Is(ferr, appstore.ErrPasswordTokenExpired) {
			live.Note("re-authenticating…")
			acc, rerr := as.Login(cfg.Apple.Email, cfg.Apple.Password, "")
			if rerr != nil {
				live.Fail("re-auth failed: %v", rerr)
				return rerr
			}
			cfg.Apple.Account = &acc
			_ = cfg.Save()
			_, ids, ferr = as.FetchVersionIDs(acc, app)
		}
		if ferr != nil {
			live.Fail("fetch version IDs: %v", ferr)
			return ferr
		}
		allIDs = ids
		live.OK("fetched %d version IDs", len(allIDs))
	}

	tui.Info("searching %d version IDs for v%s via binary search…", len(allIDs), targetVersion)

	// Binary search: IDs are sorted ascending (oldest→newest), version strings
	// also generally increase. We probe the midpoint and decide direction.
	lo, hi := 0, len(allIDs)-1
	probeCount := 0
	foundID := ""

	reauth := func() error {
		acc, lerr := as.Login(cfg.Apple.Email, cfg.Apple.Password, "")
		if lerr != nil {
			return lerr
		}
		cfg.Apple.Account = &acc
		return cfg.Save()
	}

	peek := func(idx int) (string, error) {
		idStr := fmt.Sprintf("%d", allIDs[idx])
		probeCount++
		live.Spin("[%d probes] checking ID %s (index %d/%d)", probeCount, idStr, idx, len(allIDs)-1)
		ver, err := as.PeekVersion(*cfg.Apple.Account, app, idStr)
		if errors.Is(err, appstore.ErrPasswordTokenExpired) {
			if rerr := reauth(); rerr != nil {
				return "", rerr
			}
			ver, err = as.PeekVersion(*cfg.Apple.Account, app, idStr)
		}
		return ver, err
	}

	// Binary search loop
	for lo <= hi {
		mid := (lo + hi) / 2
		ver, err := peek(mid)
		if err != nil {
			live.Fail("probe failed at index %d: %v", mid, err)
			return err
		}

		cmp := compareVersions(ver, targetVersion)
		switch {
		case cmp == 0:
			foundID = fmt.Sprintf("%d", allIDs[mid])
			lo = hi + 1 // break
		case cmp < 0:
			lo = mid + 1
		default:
			hi = mid - 1
		}
	}

	if foundID == "" {
		// Binary search may miss if versioning is non-monotonic; do a final
		// linear scan in the neighbourhood of lo.
		live.Note("exact match not found via binary search, scanning neighbourhood…")
		start := lo - 5
		if start < 0 {
			start = 0
		}
		end := lo + 5
		if end >= len(allIDs) {
			end = len(allIDs) - 1
		}
		for i := start; i <= end; i++ {
			ver, err := peek(i)
			if err != nil {
				continue
			}
			if ver == targetVersion {
				foundID = fmt.Sprintf("%d", allIDs[i])
				break
			}
		}
	}

	if foundID == "" {
		live.Fail("version %s not found after %d probes", targetVersion, probeCount)
		tui.Info("the version may not be available in the App Store history for this region/account")
		return fmt.Errorf("version %s not found", targetVersion)
	}

	live.OK("found v%s → external version ID: %s", targetVersion, foundID)
	fmt.Printf("\n  ipadecrypt decrypt %s --external-version-id %s\n\n", bundleID, foundID)
	return nil
}

// compareVersions compares two dotted version strings (e.g. "26.5.0" vs "26.7.2").
// Returns -1, 0, or 1.
func compareVersions(a, b string) int {
	partsA := strings.Split(a, ".")
	partsB := strings.Split(b, ".")
	max := len(partsA)
	if len(partsB) > max {
		max = len(partsB)
	}
	for i := 0; i < max; i++ {
		var na, nb int
		if i < len(partsA) {
			fmt.Sscanf(partsA[i], "%d", &na)
		}
		if i < len(partsB) {
			fmt.Sscanf(partsB[i], "%d", &nb)
		}
		if na < nb {
			return -1
		}
		if na > nb {
			return 1
		}
	}
	return 0
}
