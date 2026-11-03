package main

import (
	"errors"
	"fmt"
	"os"
	"runtime/debug"

	"github.com/londek/ipadecrypt/internal/config"
	"github.com/spf13/cobra"
)

var Version = "dev"

// resolveVersion prefers the linker-injected Version, falling back to the
// module version recorded by `go install` so those builds are identifiable.
func resolveVersion() string {
	if Version != "dev" {
		return Version
	}

	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}

	return Version
}

var (
	rootDirOverride string
	redactSensitive bool

	bootstrapReset     bool
	bootstrapSkipLogin bool
	bootstrapRemint    bool

	decryptExtVerID       string
	decryptOutput         string
	decryptStorefront     string
	decryptNoVerify       bool
	decryptExtraVerify    bool
	decryptSkipAppex      bool
	decryptVerbose        bool
	decryptOnDevice       bool
	decryptNoOnDevice     bool
	decryptNoUninstall    bool
	decryptForceUninstall bool
	decryptPatchDevType   bool

	versionsStorefront   string
	versionsLogResponses bool
)

func main() {
	root := &cobra.Command{
		Use:     "ipadecrypt",
		Short:   "End-to-end FairPlay decrypter for App Store apps",
		Long:    "ipadecrypt is an end-to-end suite for decrypting encrypted IPAs from the App Store with minimal user interaction.\n\nRun `ipadecrypt bootstrap` first to sign in and verify your device.",
		Version: resolveVersion(),
	}

	root.PersistentFlags().StringVar(&rootDirOverride, "root-dir", "",
		"config root directory path (default: ~/.ipadecrypt)")
	root.PersistentFlags().BoolVar(&redactSensitive, "redact", false,
		"redact sensitive identifiers (Apple ID email, storefront) from output")

	bootstrap := &cobra.Command{
		Use:   "bootstrap",
		Short: "Interactive setup. App Store sign-in and one-time credential minting",
		Run:   bootstrapHandler,
	}
	bootstrap.Flags().BoolVar(&bootstrapReset, "reset", false, "forget cached credentials and re-prompt")
	bootstrap.Flags().BoolVar(&bootstrapSkipLogin, "skip-login", false, "do not login to the App Store. ipadecrypt won't be able to use any App Store related features")
	bootstrap.Flags().BoolVar(&bootstrapRemint, "remint", false, "re-run credential minting even if one is already cached for the account")

	decrypt := &cobra.Command{
		Use:   "decrypt <bundle-id|app-store-id|app-store-url|path-to-local-ipa>",
		Short: "Download (or read a local .ipa) and decrypt an app offline by bundle ID, App Store ID, or App Store URL",
		Args:  cobra.ExactArgs(1),
		Run:   decryptHandler,
	}
	decrypt.Flags().StringVar(&decryptExtVerID, "external-version-id", "", "pin to a specific historical App Store version")
	decrypt.Flags().StringVar(&decryptStorefront, "storefront", "", "override App Store storefront (numeric ID or two-letter country code, e.g. 143441 or US)")
	decrypt.Flags().StringVarP(&decryptOutput, "output", "o", "", "output path for the decrypted IPA (default: ./<bundleID>_<version>.decrypted.ipa)")
	decrypt.Flags().BoolVar(&decryptNoVerify, "no-verify", false, "skip the post-decrypt Mach-O verification pass")
	decrypt.Flags().BoolVar(&decryptExtraVerify, "extra-verify", false, "also byte-compare every output Mach-O against its source counterpart (outside the encrypted region) to catch decrypt corruption")
	decrypt.Flags().BoolVar(&decryptSkipAppex, "skip-appex", false, "skip Payload/<App>.app/PlugIns/*.appex; extensions stay encrypted in the output IPA")
	decrypt.Flags().BoolVarP(&decryptVerbose, "verbose", "v", false, "print extra detail (e.g. the output path) during decryption")
	decrypt.Flags().BoolVar(&decryptOnDevice, "on-device", false, "decrypt on the jailbroken device instead of offline (required for old builds that still ship a 32-bit slice)")
	decrypt.Flags().BoolVar(&decryptNoOnDevice, "no-on-device", false, "never fall back to the device; fail if offline decryption can't fully decrypt the app")
	decrypt.Flags().BoolVar(&decryptForceUninstall, "force-uninstall", false, "always uninstall the app from the device after an on-device decrypt")
	decrypt.Flags().BoolVar(&decryptNoUninstall, "no-uninstall", false, "never uninstall the app from the device after an on-device decrypt")
	decrypt.Flags().BoolVar(&decryptPatchDevType, "patch-device-type", false, "expand UIDeviceFamily so an app for a different device type still installs on the device")

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
