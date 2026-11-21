package testflight

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/londek/ipadecrypt/internal/appstore"
	"github.com/londek/ipadecrypt/internal/pipeline"
	"github.com/londek/ipadecrypt/internal/sap/assets"
	"github.com/londek/ipadecrypt/internal/sap/machine"
)

// CompleteDownload unwraps and prepares a TestFlight package. Each authorization
// gets a private workspace so its ciphertext cannot resume another ticket's bytes.
func (c *Client) CompleteDownload(ctx context.Context, account *appstore.Account, ticket DownloadTicket, output string, progress func(current, total int64)) error {
	if output == "" {
		return errors.New("TestFlight download requires an output file")
	}

	dir, err := os.MkdirTemp(filepath.Dir(output), ".ipadecrypt-testflight-*")
	if err != nil {
		return fmt.Errorf("stage TestFlight package: %w", err)
	}
	defer os.RemoveAll(dir)

	encrypted := filepath.Join(dir, "encrypted")
	if err := c.store.FetchPackage(ticket.URL, encrypted, progress); err != nil {
		return err
	}

	if progress != nil && ticket.FileSize() > 0 {
		progress(ticket.FileSize(), ticket.FileSize())
	}

	unwrapped := filepath.Join(dir, "unwrapped.ipa")
	if err := decryptPackage(ctx, ticket, encrypted, unwrapped); err != nil {
		return fmt.Errorf("unwrap TestFlight package: %w", err)
	}

	prepared := filepath.Join(dir, "package.ipa")
	if err := appstore.PatchPackage(unwrapped, prepared, ticket.DownloadTicket, account); err != nil {
		return err
	}

	return publishPackage(prepared, output, ticket)
}

// The source stays inside the caller's private workspace through validation and
// rename. The destination is never opened for writing, including through symlinks.
func publishPackage(source, output string, ticket DownloadTicket) error {
	bundleID, version, err := pipeline.AppInfo(source)
	if err != nil {
		return fmt.Errorf("validate TestFlight IPA: %w", err)
	}

	if bundleID != ticket.BundleID() || version != ticket.Version() {
		return errors.New("downloaded IPA does not match the selected TestFlight app and version")
	}

	if err := os.Chmod(source, 0o600); err != nil {
		return fmt.Errorf("protect TestFlight IPA: %w", err)
	}

	if err := os.Rename(source, output); err != nil {
		return fmt.Errorf("publish TestFlight IPA: %w", err)
	}

	return nil
}

func decryptPackage(ctx context.Context, ticket DownloadTicket, source, output string) (err error) {
	bundle, err := assets.Load(ctx)
	if err != nil {
		return fmt.Errorf("load StoreAgent assets: %w", err)
	}

	agent, err := machine.OpenStoreAgent(ctx, bundle, ticket.HardwareID, ticket.DPInfo)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, agent.Close()) }()

	src, err := os.Open(source)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, src.Close()) }()

	dst, err := os.OpenFile(output, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, dst.Close()) }()

	_, err = agent.Decrypt(ctx, dst, src)

	return err
}
