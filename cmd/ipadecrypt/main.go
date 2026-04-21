package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/londek/ipadecrypt/internal/config"
	"github.com/londek/ipadecrypt/internal/tui"
	"github.com/spf13/cobra"
)

var (
	cacheDirOverride string

	bootstrapReset bool

	decryptExtVerID     string
	decryptUninstall    bool
	decryptNoCleanup    bool
	decryptKeepMetadata bool
	decryptNoVerify     bool
	decryptKeepWatch    bool
)

func main() {
	root := &cobra.Command{
		Use:           "ipadecrypt",
		Short:         "End-to-end FairPlay decrypter for App Store apps",
		Long:          "ipadecrypt is an end-to-end suite for decrypting encrypted IPAs from the App Store with minimal user interaction.\n\nRun `ipadecrypt bootstrap` first to sign in and verify your device.",
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	root.PersistentFlags().StringVar(&cacheDirOverride, "cache-dir", "",
		"cache directory path (default: ~/.ipadecrypt/cache)")

	bootstrap := &cobra.Command{
		Use:   "bootstrap",
		Short: "Interactive setup. App Store sign-in, device probe, prerequisite checks",
		RunE:  bootstrapHandler,
	}
	bootstrap.Flags().BoolVar(&bootstrapReset, "reset", false, "forget cached credentials and re-prompt")

	decrypt := &cobra.Command{
		Use:   "decrypt <bundle-id|app-store-id>",
		Short: "Download, install, decrypt, and retrieve an app by bundle ID or App Store ID",
		Args:  cobra.ExactArgs(1),
		RunE:  decryptHandler,
	}
	decrypt.Flags().StringVar(&decryptExtVerID, "external-version-id", "", "pin to a specific historical App Store version")
	decrypt.Flags().BoolVar(&decryptUninstall, "uninstall", false, "uninstall the app on device after decrypt")
	decrypt.Flags().BoolVar(&decryptNoCleanup, "no-cleanup", false, "leave remote staging files in place")
	decrypt.Flags().BoolVar(&decryptKeepMetadata, "keep-metadata", false, "keep iTunesMetadata.plist (Apple ID + purchase info) in the output IPA")
	decrypt.Flags().BoolVar(&decryptNoVerify, "no-verify", false, "skip the post-decrypt cryptid==0 check on every Mach-O")
	decrypt.Flags().BoolVar(&decryptKeepWatch, "keep-watch", false, "keep the Watch/ directory (watchOS binaries that remain encrypted)")

	root.AddCommand(bootstrap, decrypt)

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

func loadConfigOrDefault(cacheDir string) (*config.Config, *config.Paths, error) {
	rootDir := ""
	if cacheDir != "" {
		absCacheDir, err := filepath.Abs(cacheDir)
		if err != nil {
			return nil, nil, fmt.Errorf("cache dir: %w", err)
		}

		cacheDir = absCacheDir
		rootDir = filepath.Dir(cacheDir)
	}

	paths, err := config.NewPaths(rootDir)
	if err != nil {
		return nil, nil, err
	}

	if cacheDir != "" {
		if err := paths.SetCacheDir(cacheDir); err != nil {
			return nil, nil, err
		}
	}

	cfgFile := paths.ConfigPath()

	cfg, err := config.Load(cfgFile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return config.New(cfgFile), paths, nil
		}

		return nil, nil, fmt.Errorf("load config: %w", err)
	}

	return cfg, paths, nil
}

// notifyContext wires SIGINT/SIGTERM to context cancellation. Stdin reads
// (prompt helpers) don't respect context, so we force-exit if the first
// signal doesn't drain within 2 seconds, or a second signal arrives.
func notifyContext() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())

	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	go func() {
		defer signal.Stop(sigCh)

		select {
		case <-sigCh:
		case <-ctx.Done():
			return
		}

		fmt.Fprint(os.Stderr, "\r\033[2K\033[0m")

		tui.Warn("interrupted — cleaning up")

		cancel()

		select {
		case <-sigCh:
		case <-time.After(2 * time.Second):
		}

		fmt.Fprint(os.Stderr, "\033[0m")

		os.Exit(130)
	}()

	return ctx, func() {
		signal.Stop(sigCh)
		cancel()
	}
}
