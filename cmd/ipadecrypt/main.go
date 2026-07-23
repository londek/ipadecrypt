package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/londek/ipadecrypt/internal/config"
	"github.com/spf13/cobra"
)

var Version = "dev"

var (
	rootDirOverride string
	redactSensitive bool

	bootstrapReset bool

	decryptExtVerID       string
	decryptOutput         string
	decryptStorefront     string
	decryptNoCleanup      bool
	decryptNoVerify       bool
	decryptExtraVerify    bool
	decryptFromAppStore   bool
	decryptUseInstalled   bool
	decryptPatchDevType   bool
	decryptSkipAppex      bool
	decryptForceUninstall bool
	decryptNoUninstall    bool
	decryptVerbose        bool
	decryptOwned          bool

	versionsStorefront   string
	versionsLogResponses bool
)

func main() {
	root := &cobra.Command{
		Use:     "ipadecrypt",
		Short:   "End-to-end FairPlay decrypter for App Store apps",
		Long:    "ipadecrypt is an end-to-end suite for decrypting encrypted IPAs from the App Store with minimal user interaction.\n\nRun `ipadecrypt bootstrap` first to sign in and verify your device.",
		Version: Version,
	}

	root.PersistentFlags().StringVar(&rootDirOverride, "root-dir", "",
		"config root directory path (default: ~/.ipadecrypt)")
	root.PersistentFlags().BoolVar(&redactSensitive, "redact", false,
		"redact sensitive identifiers (Apple ID email, storefront) from output")

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
	decrypt.Flags().StringVar(&decryptStorefront, "storefront", "", "override App Store storefront (numeric ID or two-letter country code, e.g. 143441 or US)")
	decrypt.Flags().StringVarP(&decryptOutput, "output", "o", "", "output path for the decrypted IPA (default: ./<bundleID>_<version>.decrypted.ipa)")
	decrypt.Flags().BoolVar(&decryptNoCleanup, "no-cleanup", false, "leave remote staging files in place")
	decrypt.Flags().BoolVar(&decryptNoVerify, "no-verify", false, "skip the post-decrypt Mach-O verification pass")
	decrypt.Flags().BoolVar(&decryptExtraVerify, "extra-verify", false, "also byte-compare every output Mach-O against its source counterpart (outside the encrypted region) to catch decrypt corruption")
	decrypt.Flags().BoolVarP(&decryptFromAppStore, "from-appstore", "", false, "fetch from App Store and reinstall, ignoring what's installed on the device")
	decrypt.Flags().BoolVar(&decryptUseInstalled, "use-installed", false, "decrypt the installed build directly; skip the App Store path even if a newer version exists")
	decrypt.Flags().BoolVar(&decryptPatchDevType, "patch-device-type", false, "if the IPA's UIDeviceFamily excludes this device, append the device's family (iPadOS apps then run on iOS)")
	decrypt.Flags().BoolVar(&decryptSkipAppex, "skip-appex", false, "skip Payload/<App>.app/PlugIns/*.appex; extensions stay encrypted in the output IPA")
	decrypt.Flags().BoolVar(&decryptForceUninstall, "force-uninstall", false, "always uninstall the app after decryption, even if it was already installed when we started")
	decrypt.Flags().BoolVar(&decryptNoUninstall, "no-uninstall", false, "never uninstall the app after decryption (default: uninstall only if we installed or replaced it)")
	decrypt.Flags().BoolVarP(&decryptVerbose, "verbose", "v", false, "stream the on-device helper's LOG/ERR lines to stderr (useful for debugging decryption failures)")
	decrypt.Flags().BoolVar(&decryptOwned, "owned", false, "allow paid apps: proceed to download a paid app the signed-in Apple ID already owns (never buys; unowned paid apps still fail)")

	versions := &cobra.Command{
		Use:   "versions <bundle-id|app-store-id|app-store-url>",
		Short: "Browse the App Store version history of an app",
		Long:  "Opens an interactive table of every App Store release of the given app. Metadata for the 3 newest versions is fetched eagerly; older versions are fetched on-demand (Enter on a row) and cached on disk.",
		Args:  cobra.ExactArgs(1),
		Run:   versionsHandler,
	}
	versions.Flags().StringVar(&versionsStorefront, "storefront", "", "override App Store storefront (numeric ID or two-letter country code, e.g. 143441 or US)")
	versions.Flags().BoolVar(&versionsLogResponses, "log-responses", false, "append each API response as a JSONL record to ~/.ipadecrypt/logs/versions.log")

	root.AddCommand(bootstrap, decrypt, versions)

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

func redact(s string) string {
	if !redactSensitive || s == "" {
		return s
	}

	return "######"
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
