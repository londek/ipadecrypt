package macstore

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	store "github.com/majd/ipatool/v2/pkg/appstore"
	"github.com/schollz/progressbar/v3"
	"howett.net/plist"
)

func FileHash(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil {
		return "", err
	}

	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

// Download delegates ticket acquisition, resumable transfer and metadata patching
// to upstream. Only a fully verified, personalized IPA is published to the cache.
func Download(ctx context.Context, s *Session, account store.Account, catalog CatalogApp, refresh bool, progress func(string), transferProgress func(int64, int64)) (string, error) {
	version := catalog.ExternalVersionID
	if !digits.MatchString(version) || catalog.App.ID <= 0 || catalog.App.BundleID == "" || account.Email == "" {
		return "", errors.New("missing download account, app or external version ID")
	}

	if err := ctx.Err(); err != nil {
		return "", err
	}

	stage := func(message string) {
		if progress != nil {
			progress(message)
		}
	}

	dir := filepath.Join(s.Root, "downloads", AccountHash(account), fmt.Sprintf("%d-%s", catalog.App.ID, version))
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}

	final, ready := filepath.Join(dir, "encrypted.ipa"), filepath.Join(dir, "ready.json")

	var saved struct {
		SHA256 string `json:"sha256"`
	}
	if b, err := os.ReadFile(ready); err == nil && json.Unmarshal(b, &saved) == nil && !refresh {
		if hash, err := FileHash(final); err == nil && hash == saved.SHA256 {
			if err = validateDownload(final, account, catalog); err == nil {
				stage("Using verified encrypted IPA cache")
				return final, nil
			}
		}
	}
	// Stable destination lets upstream reuse its contiguous .tmp file after an
	// interrupted transfer. The account/app/version are isolated by directory.
	destination := filepath.Join(dir, "download.ipa")

	stage("Requesting account-bound download ticket")

	bar := progressbar.NewOptions64(-1, progressbar.OptionSetWriter(io.Discard))
	stop := relayProgress(bar, stage, transferProgress)
	out, err := s.API.Download(store.DownloadInput{Context: ctx, Account: account, App: catalog.App,
		OutputPath: destination, ExternalVersionID: version, Platform: store.PlatformIPhone, Progress: bar})

	stop()

	if err != nil {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}

		return "", SafeError(err)
	}

	if out.DestinationPath != destination {
		return "", errors.New("unexpected download destination")
	}

	if len(out.Sinfs) == 0 {
		return "", errors.New("download has no account SINF")
	}
	// SINF replication also uses <path>.tmp. Keep that separate from the
	// downloader's resumable raw file, including after failed replication.
	prepared := filepath.Join(dir, "personalized.ipa")
	if err = os.Rename(destination, prepared); err != nil {
		return "", err
	}

	destination = prepared

	stage("Applying metadata and account SINF")

	if err = s.API.ReplicateSinf(store.ReplicateSinfInput{Sinfs: out.Sinfs, PackagePath: destination}); err != nil {
		return "", SafeError(err)
	}

	if err = CheckZIP(destination); err != nil {
		return "", err
	}

	if err = validateDownload(destination, account, catalog); err != nil {
		return "", err
	}

	if err = os.Chmod(destination, 0600); err != nil {
		return "", err
	}

	hash, err := FileHash(destination)
	if err != nil {
		return "", err
	}

	if err = ctx.Err(); err != nil {
		return "", err
	}

	if err = os.Rename(destination, final); err != nil {
		return "", err
	}

	saved.SHA256 = hash
	if err = WriteJSON(ready, saved); err != nil {
		return "", err
	}

	return final, nil
}

// Poll the public progress state without rendering another UI. Joining before
// returning keeps callbacks serialized with stage changes and error handling.
func relayProgress(bar *progressbar.ProgressBar, stage func(string), transfer func(int64, int64)) func() {
	done, joined := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(joined)

		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()

		started := false
		report := func() {
			state := bar.State()
			if state.Max <= 0 {
				return
			}

			if !started {
				stage("Downloading encrypted IPA")

				started = true
			}

			if transfer != nil {
				transfer(state.CurrentNum, state.Max)
			}
		}

		for {
			select {
			case <-done:
				report()
				return
			case <-ticker.C:
				report()
			}
		}
	}()

	return func() { close(done); <-joined }
}

// Check both server metadata and the actual root bundle, including cache hits.
// Upstream's public API does not expose the ticket MD5; ZIP CRC validation is
// separate from this identity check and our SHA-256 cache integrity check.
func validateDownload(path string, account store.Account, catalog CatalogApp) error {
	r, err := zip.OpenReader(path)
	if err != nil {
		return err
	}
	defer r.Close()

	seen := map[string]bool{}

	var (
		metadata, root       bool
		rootPath, executable string
	)

	readPlist := func(f *zip.File, value any) error {
		if f.UncompressedSize64 > 16<<20 {
			return errors.New("IPA metadata exceeds size limit")
		}

		stream, err := f.Open()
		if err != nil {
			return err
		}
		defer stream.Close()

		b, err := io.ReadAll(io.LimitReader(stream, (16<<20)+1))
		if err != nil {
			return err
		}

		if len(b) > 16<<20 {
			return errors.New("IPA metadata exceeds size limit")
		}

		_, err = plist.Unmarshal(b, value)

		return err
	}
	for _, f := range r.File {
		if seen[f.Name] {
			return errors.New("duplicate IPA member")
		}

		seen[f.Name] = true
		if f.Name == "iTunesMetadata.plist" {
			var m struct {
				AppleID string `plist:"apple-id"`
				ID      int64  `plist:"itemId"`
				Bundle  string `plist:"softwareVersionBundleId"`
				Version int64  `plist:"softwareVersionExternalIdentifier"`
			}
			if err = readPlist(f, &m); err != nil {
				return err
			}

			if !strings.EqualFold(m.AppleID, account.Email) || m.ID != int64(catalog.App.ID) || m.Bundle != catalog.App.BundleID || strconv.FormatInt(m.Version, 10) != catalog.ExternalVersionID {
				return errors.New("download account/app/version mismatch")
			}

			metadata = true
		}

		parts := strings.Split(f.Name, "/")
		if len(parts) == 3 && parts[0] == "Payload" && strings.HasSuffix(parts[1], ".app") && parts[2] == "Info.plist" {
			if root {
				return errors.New("IPA has multiple root apps")
			}

			var info struct {
				Bundle     string   `plist:"CFBundleIdentifier"`
				Platforms  []string `plist:"CFBundleSupportedPlatforms"`
				Executable string   `plist:"CFBundleExecutable"`
			}
			if err = readPlist(f, &info); err != nil {
				return err
			}

			if info.Bundle != catalog.App.BundleID || !slices.Contains(info.Platforms, "iPhoneOS") || info.Executable == "" || info.Executable == "." || info.Executable == ".." || strings.ContainsAny(info.Executable, "/\\") {
				return errors.New("download root bundle mismatch")
			}

			root, rootPath, executable = true, strings.Join(parts[:2], "/"), info.Executable
		}
	}

	if !metadata || !root || !seen[rootPath+"/"+executable] || !seen[rootPath+"/SC_Info/"+executable+".sinf"] {
		return errors.New("download missing metadata, root executable or personalized SINF")
	}

	return nil
}
