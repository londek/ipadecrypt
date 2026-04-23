package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/londek/ipadecrypt/internal/config"
	"github.com/spf13/cobra"
)

var (
	rootDirOverride string

	bootstrapReset bool

	decryptExtVerID     string
	decryptOutput       string
	decryptNoCleanup    bool
	decryptKeepMetadata bool
	decryptNoVerify     bool
	decryptKeepWatch    bool
	decryptForce        bool

	versionsLogResponses bool
)

func main() {
	root := &cobra.Command{
		Use:   "ipadecrypt",
		Short: "End-to-end FairPlay decrypter for App Store apps",
		Long:  "ipadecrypt is an end-to-end suite for decrypting encrypted IPAs from the App Store with minimal user interaction.\n\nRun `ipadecrypt bootstrap` first to sign in and verify your device.",
	}

	root.PersistentFlags().StringVar(&rootDirOverride, "root-dir", "",
		"config root directory path (default: ~/.ipadecrypt)")

	bootstrap := &cobra.Command{
		Use:   "bootstrap",
		Short: "Interactive setup. App Store sign-in, device probe, prerequisite checks",
		Run:   bootstrapHandler,
	}
	bootstrap.Flags().BoolVar(&bootstrapReset, "reset", false, "forget cached credentials and re-prompt")

	decrypt := &cobra.Command{
		Use:   "decrypt <bundle-id|app-store-id|app-store-url|path-to-local-ipa>",
		Short: "Download, install, decrypt, and retrieve an app by bundle ID, App Store ID, or App Store URL",
		Args:  cobra.ExactArgs(1),
		Run:   decryptHandler,
	}
	decrypt.Flags().StringVar(&decryptExtVerID, "external-version-id", "", "pin to a specific historical App Store version")
	decrypt.Flags().StringVarP(&decryptOutput, "output", "o", "", "output path for the decrypted IPA (default: ./<bundleID>_<version>.decrypted.ipa)")
	decrypt.Flags().BoolVar(&decryptNoCleanup, "no-cleanup", false, "leave remote staging files in place")
	decrypt.Flags().BoolVar(&decryptKeepMetadata, "keep-metadata", false, "keep iTunesMetadata.plist (Apple ID + purchase info) in the output IPA")
	decrypt.Flags().BoolVar(&decryptNoVerify, "no-verify", false, "skip the post-decrypt cryptid==0 check on every Mach-O")
	decrypt.Flags().BoolVar(&decryptKeepWatch, "keep-watch", false, "keep the Watch/ directory")
	decrypt.Flags().BoolVarP(&decryptForce, "force", "f", false, "force reinstall from provided .ipa source regardless of what's on the device")

	versions := &cobra.Command{
		Use:   "versions <bundle-id|app-store-id|app-store-url>",
		Short: "Browse the App Store version history of an app",
		Long:  "Opens an interactive table of every App Store release of the given app. Metadata for the 3 newest versions is fetched eagerly; older versions are fetched on-demand (Enter on a row) and cached on disk.",
		Args:  cobra.ExactArgs(1),
		Run:   versionsHandler,
	}
	versions.Flags().BoolVar(&versionsLogResponses, "log-responses", false, "append each API response as a JSONL record to ~/.ipadecrypt/logs/versions.log")

	root.AddCommand(bootstrap, decrypt, versions)

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

func loadConfigOrDefault(rootDir string) (*config.Config, *config.Paths, error) {
	paths, err := config.NewPaths(rootDir)
	if err != nil {
		return nil, nil, err
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
