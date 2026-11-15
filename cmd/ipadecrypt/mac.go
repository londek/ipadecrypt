package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/londek/ipadecrypt/internal/fairplay"
	"github.com/londek/ipadecrypt/internal/macstore"
	"github.com/londek/ipadecrypt/internal/pipeline"
	"github.com/londek/ipadecrypt/internal/tui"
	"github.com/spf13/cobra"
)

var errCommandReported = errors.New("worker already reported the command failure")

func macOfflineDecryptUI(source, destination string, credential []byte, keepWatch bool, ui *macTransferUI) (pipeline.VerifyResult, error) {
	var verify pipeline.VerifyResult

	out, err := os.CreateTemp(filepath.Dir(destination), ".decrypt-*.ipa")
	if err != nil {
		return verify, err
	}
	defer os.Remove(out.Name())

	cw := &countingWriter{w: out, onTick: ui.writing}
	summary, decryptErr := fairplay.Decrypt(source, cw, fairplay.Credentials{Standard: credential}, false, keepWatch)

	err = errors.Join(decryptErr, out.Sync(), out.Close())
	if err != nil {
		return verify, err
	}

	ui.verifying(summary, destination)

	verify, err = pipeline.Verify(out.Name(), source, false)
	if err != nil {
		return verify, err
	}

	if !verify.OK() || verify.Scanned == 0 || verify.Compared != verify.Scanned || len(verify.Skipped) > 0 || len(verify.Missing) > 0 {
		return verify, errors.New("offline verification failed; output was not published and no device fallback was attempted")
	}

	if err = os.Link(out.Name(), destination); err != nil {
		return verify, fmt.Errorf("publish verified output (must not already exist): %w", err)
	}

	return verify, nil
}

func macSupervised(cmd *cobra.Command, timeout time.Duration, work func(context.Context) error) error {
	return macSupervisedArgs(cmd, timeout, os.Args[1:], work)
}
func macSupervisedArgs(cmd *cobra.Command, timeout time.Duration, arguments []string, work func(context.Context) error) error {
	if runtime.GOOS != "darwin" {
		return errors.New("the mac backend currently requires macOS")
	}

	if timeout <= 0 {
		return errors.New("the Mac worker timeout must be positive")
	}

	ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt)
	defer stop()

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	if os.Getenv("IPADECRYPT_MAC_WORKER") != "1" {
		binary, err := os.Executable()
		if err != nil {
			return err
		}

		child := exec.CommandContext(ctx, binary, arguments...)

		child.Env = append(os.Environ(), "IPADECRYPT_MAC_WORKER=1")
		child.Stdin = os.Stdin
		child.Stdout = os.Stdout

		child.Stderr = os.Stderr
		if err = child.Run(); err != nil {
			if ctx.Err() != nil {
				return fmt.Errorf("the Mac command stopped: %w; completed state and download parts remain saved", ctx.Err())
			}

			var exit *exec.ExitError
			if errors.As(err, &exit) && exit.ExitCode() == 1 {
				return errCommandReported
			}

			return fmt.Errorf("the Mac worker stopped: %w", err)
		}

		return nil
	}

	return work(ctx)
}

type macDecryptOptions struct {
	destination, version string
	refresh, keepWatch   bool
}

func runMacDecrypt(ctx context.Context, s *macstore.Session, target string, options macDecryptOptions) error {
	destination, version := options.destination, options.version
	refresh := options.refresh

	a, err := macSessionAccount(s)
	if err != nil {
		return err
	}

	credentialPath := macstore.AccountCredentialPath(s.Root, a)
	if _, err := verifiedMacCredential(credentialPath); err != nil {
		return fmt.Errorf("the Mac credential verification: %w; run bootstrap", err)
	}

	credential, err := fairplay.LoadCredential(credentialPath)
	if err != nil {
		return fmt.Errorf("offline account credential required before proceeding: %w; run bootstrap --flow mac to prepare a verified credential", err)
	}
	defer clear(credential)

	local := false
	if st, err := os.Stat(target); err == nil && st.Mode().IsRegular() {
		local = true
	}

	if destination != "" {
		if _, err := os.Lstat(destination); err == nil {
			return errors.New("output already exists; choose another --output")
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}

	ui := &macTransferUI{}
	defer ui.stop()

	progress := ui.stage

	source := target
	if local {
		tui.OK("local IPA %s", filepath.Base(source))

		bundle, appVersion, err := pipeline.AppInfo(source)
		if err != nil {
			return fmt.Errorf("read IPA: %w", err)
		}

		tui.OK("%s v%s", bundle, appVersion)

		if refresh || version != "" {
			return errors.New("store flags cannot be used with a local IPA")
		}

		if destination == "" {
			destination = strings.TrimSuffix(filepath.Base(source), filepath.Ext(source)) + ".decrypted.ipa"
		}
	} else {
		country, err := macstore.Country(a.StoreFront)
		if err != nil {
			return err
		}

		tui.OK("signed in as %s (%s storefront)", redact(a.Email), redact(strings.ToUpper(country)))

		parsed, err := parseDecryptArg(target)
		if err != nil {
			return err
		}

		if parsed.appId != "" {
			ui.spin("resolving appId %s", parsed.appId)
		} else {
			ui.spin("resolving bundleId %s", parsed.bundleId)
		}

		catalog, err := macstore.Resolve(ctx, target, a.StoreFront)
		if err != nil {
			return err
		}

		ui.ok("found %s on App Store", catalog.App.BundleID)

		if version != "" {
			if _, _, err := macstore.Target(version); err != nil || strings.ContainsAny(version, ".:/") {
				return errors.New("--external-version-id must be a positive integer")
			}

			catalog.ExternalVersionID = version
		}

		if destination == "" {
			destination = fmt.Sprintf("%s_%s.decrypted.ipa", catalog.App.BundleID, catalog.ExternalVersionID)
		}

		if _, err := os.Lstat(destination); err == nil {
			return errors.New("output already exists; choose another --output")
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}

		source, err = downloadWithMacLicense(catalog,
			func(force bool) (string, error) {
				return macstore.Download(ctx, s, a, catalog, refresh || force, progress, ui.transfer)
			},
			func() error {
				progress("acquiring license")

				_, err := macstore.Purchase(ctx, s.Commerce(ctx), a, catalog, s.Root)

				return err
			})
		if err != nil {
			return err
		}

		if ui.cached {
			ui.ok("cached %s", filepath.Base(source))
		} else {
			ui.ok("downloaded %s", filepath.Base(source))
		}
	}

	ui.spin("decrypting %s", filepath.Base(source))

	verification, err := macOfflineDecryptUI(source, destination, credential, options.keepWatch, ui)
	if err != nil {
		return err
	}

	ui.ok("%s", verifyOKSummary(verification, true))

	if decryptVerbose {
		tui.Info("output: %s", destination)
	}

	return nil
}
