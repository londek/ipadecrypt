package main

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/londek/ipadecrypt/internal/config"
	"github.com/londek/ipadecrypt/internal/testflight"
	"github.com/londek/ipadecrypt/internal/tui"
	"howett.net/plist"
)

func TestSavedTestFlightSessionPersistsIdentityAfterValidation(t *testing.T) {
	previousUDID := testFlightUDID
	testFlightUDID = ""

	t.Cleanup(func() { testFlightUDID = previousUDID })

	for _, readFails := range []bool{false, true} {
		name := "validated catalog"
		if readFails {
			name = "catalog failure"
		}

		t.Run(name, func(t *testing.T) {
			paths, err := config.NewPaths(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}

			cfg := config.New(paths.ConfigPath())
			cfg.Apple.DirectoryServicesIdentifier = "12345"
			cfg.Apple.StoreFront = "143441-1,13"

			cfg.TestFlight = config.TestFlight{SessionID: "example-session", AccountID: "example-account"}
			if err := cfg.Save(); err != nil {
				t.Fatal(err)
			}

			before, err := os.ReadFile(paths.ConfigPath())
			if err != nil {
				t.Fatal(err)
			}

			catalogErr := errors.New("catalog unavailable")

			_, _, _, err = withTestFlightSession(context.Background(), cfg, paths, false, false, func(*testflight.Client, context.Context) ([]testflight.App, error) {
				if readFails {
					return nil, catalogErr
				}

				return []testflight.App{{ID: 100, Name: "Example App", DeveloperName: "Example Developer"}}, nil
			})
			if readFails {
				if !errors.Is(err, catalogErr) {
					t.Fatalf("got error %v", err)
				}

				after, err := os.ReadFile(paths.ConfigPath())
				if err != nil {
					t.Fatal(err)
				}

				if !bytes.Equal(before, after) {
					t.Fatal("failed catalog validation changed saved session")
				}

				return
			}

			if err != nil {
				t.Fatal(err)
			}

			saved, err := config.Load(paths.ConfigPath())
			if err != nil {
				t.Fatal(err)
			}

			identity, err := hex.DecodeString(saved.TestFlight.DeviceID)
			if err != nil || len(identity) != 20 {
				t.Fatal("validated session has no saved download identity")
			}

			if saved.TestFlight.SessionID != "example-session" || saved.TestFlight.AccountID != "example-account" {
				t.Fatal("existing session was replaced")
			}
		})
	}
}

func TestTestFlightDownloadIdentity(t *testing.T) {
	const (
		first  = "00112233445566778899aabbccddeeff00112233"
		second = "112233445566778899aabbccddeeff0011223344"
	)
	for _, test := range []struct {
		name, override, saved, configured, want string
		wantError                               bool
	}{
		{name: "explicit override", override: first, saved: second, want: first},
		{name: "saved identity", saved: first, configured: second, want: first},
		{name: "configured identity", configured: first, want: first},
		{name: "generated identity"},
		{name: "modern device identifier", configured: "00008110-0011223344556677"},
		{name: "invalid saved identity", saved: "invalid"},
		{name: "invalid override", override: "invalid", saved: first, wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := testFlightDownloadIdentity(test.override, test.saved, test.configured)
			if (err != nil) != test.wantError {
				t.Fatalf("got error %v", err)
			}

			if err != nil {
				return
			}

			if test.want != "" && got != test.want {
				t.Fatalf("got %q, want %q", got, test.want)
			}

			decoded, err := hex.DecodeString(got)
			if err != nil || len(decoded) != 20 {
				t.Fatalf("invalid generated identity: %q", got)
			}

			retained, err := testFlightDownloadIdentity("", got, second)
			if err != nil || retained != got {
				t.Fatal("saved identity was not retained")
			}
		})
	}
}

func TestParseTestFlightAppID(t *testing.T) {
	got, err := parseTestFlightAppID(" 1000000000 ")
	if err != nil || got != 1000000000 {
		t.Fatalf("app ID = %d, %v", got, err)
	}

	for _, input := range []string{"", "App", "-1", "0"} {
		if _, err := parseTestFlightAppID(input); err == nil {
			t.Errorf("accepted %q", input)
		}
	}
}

func TestCachedTestFlightPackageMatchesIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "package.ipa")

	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}

	writer := zip.NewWriter(file)

	entry, err := writer.Create("Payload/Example.app/Info.plist")
	if err != nil {
		t.Fatal(err)
	}

	info, err := plist.Marshal(map[string]any{
		"CFBundleIdentifier":         "com.example.beta",
		"CFBundleShortVersionString": "2.3.0",
	}, plist.XMLFormat)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := entry.Write(info); err != nil {
		t.Fatal(err)
	}

	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	if !cachedTestFlightPackageMatches(path, "com.example.beta", "2.3.0") {
		t.Fatal("matching TestFlight package was rejected")
	}

	if cachedTestFlightPackageMatches(path, "com.example.other", "2.3.0") {
		t.Fatal("mismatched TestFlight bundle was accepted")
	}
}

func TestRenderTestFlightLinkMatchesAppList(t *testing.T) {
	previous := tui.Out
	defer func() { tui.Out = previous }()

	var output bytes.Buffer

	tui.Out = &output

	renderTestFlightLink(testflight.PublicLink{
		Status: testflight.PublicLinkOpen,
		App: testflight.PublicLinkApp{
			ID:           1_000_000_000,
			Name:         "Example App",
			ProviderName: "Example Developer",
		},
	})

	want := "  Example Developer\n    • Example App (1000000000)\n"
	if output.String() != want {
		t.Fatalf("output = %q, want %q", output.String(), want)
	}
}
