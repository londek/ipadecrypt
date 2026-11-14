package main

import (
	"errors"
	"fmt"

	"github.com/londek/ipadecrypt/internal/fairplay"
	"github.com/londek/ipadecrypt/internal/macstore"
	"github.com/londek/ipadecrypt/internal/tui"
	store "github.com/majd/ipatool/v2/pkg/appstore"
)

// Match the classic download path: acquire a missing free license once,
// then retry the ticket once. Never repeat an uncertain purchase.
func downloadWithMacLicense(app macstore.CatalogApp, download func(bool) (string, error), acquire func() error) (string, error) {
	path, err := download(false)
	if !errors.Is(err, store.ErrLicenseRequired) {
		return path, err
	}

	if app.App.Price != 0 || app.OfferPrice != 0 || app.Currency == "" {
		if app.App.Price > 0 || app.OfferPrice > 0 {
			return "", errors.New("paid app not owned by this account; sign in with the Apple ID that purchased it")
		}

		return "", errors.New("app price is not confirmed free; no license acquisition attempted")
	}

	if err := acquire(); err != nil {
		return "", err
	}

	path, err = download(true)
	if errors.Is(err, store.ErrLicenseRequired) {
		return "", fmt.Errorf("license is still unavailable after acquisition; no further purchase attempted: %w", err)
	}

	return path, err
}

type macTransferUI struct {
	live   *tui.Live
	bytes  int64
	cached bool
}

func (u *macTransferUI) spin(format string, args ...any) {
	if u.live == nil {
		u.live = tui.NewLive()
	}

	u.live.Spin(format, args...)
}
func (u *macTransferUI) stop() {
	if u.live != nil {
		u.live.Stop()
		u.live = nil
	}
}
func (u *macTransferUI) ok(format string, args ...any) {
	if u.live != nil {
		u.live.OK(format, args...)
		u.live = nil
	} else {
		tui.OK(format, args...)
	}
}
func (u *macTransferUI) stage(stage string) {
	if stage == "Using verified encrypted IPA cache" {
		u.cached = true
	}

	labels := map[string]string{
		"Requesting account-bound download ticket": "fetching download metadata",
		"Downloading encrypted IPA":                "downloading IPA from App Store",
		"Applying metadata and account SINF":       "preparing IPA",
		"Using verified encrypted IPA cache":       "using cached IPA",
	}
	if label, ok := labels[stage]; ok {
		stage = label
	}

	u.spin("%s", stage)
}
func (u *macTransferUI) transfer(cur, total int64) {
	u.live.Message("%s", transferProgressText("downloading IPA from App Store", cur, total))
	u.live.Progress(cur, total)
}
func (u *macTransferUI) writing(n int64) {
	u.bytes = n
	u.live.Message("writing IPA → %s", humanBytes(n))
}
func (u *macTransferUI) verifying(summary fairplay.Summary, destination string) {
	u.ok("decrypted %d binary(s), %d page(s) (%s → %s)", summary.Binaries, summary.Pages, humanBytes(u.bytes), destination)
	u.spin("verifying Mach-Os (cryptid, zero-fill, source byte-compare)")
}
