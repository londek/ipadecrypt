package testflight

import (
	"bytes"
	"encoding/base64"
	"testing"

	"github.com/londek/ipadecrypt/internal/appstore"
	"howett.net/plist"
)

func TestParseInstallData(t *testing.T) {
	sinf, err := plist.Marshal(sinfEnvelope{Sinfs: []appstore.Sinf{{ID: 7, Data: []byte{1, 2, 3}}}}, plist.XMLFormat)
	if err != nil {
		t.Fatal(err)
	}

	dpInfo := bytes.Repeat([]byte{4}, 88)

	ticket, identity, err := parseInstallData(installData{
		ITunesMetadata: map[string]any{"betaExternalVersionId": int64(123)},
		Framework: framework{
			BundleID:     "com.example.beta",
			Version:      "2.3.0",
			BuildVersion: "9",
		},
		Packages: packages{Full: fullPackage{
			URL:         "https://iosapps.itunes.apple.com/path/app.ipa?token=secret",
			Sinf:        string(sinf),
			DPInfo:      base64.StdEncoding.EncodeToString(dpInfo),
			PackageSize: 456,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}

	if identity.BundleID != "com.example.beta" || ticket.Version() != "2.3.0" || ticket.FileSize() != 456 {
		t.Fatalf("identity = %#v, version = %q, size = %d", identity, ticket.Version(), ticket.FileSize())
	}

	if len(ticket.Sinfs) != 1 || ticket.Sinfs[0].ID != 7 {
		t.Fatalf("sinfs = %#v", ticket.Sinfs)
	}

	if !bytes.Equal(ticket.DPInfo, dpInfo) {
		t.Fatal("ticket did not preserve transport metadata")
	}
}

func TestParseInstallDataRejectsMissingDPInfo(t *testing.T) {
	sinf, err := plist.Marshal(sinfEnvelope{Sinfs: []appstore.Sinf{{ID: 7, Data: []byte{1}}}}, plist.XMLFormat)
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = parseInstallData(installData{
		Framework: framework{BundleID: "com.example.beta", Version: "2.3.0", BuildVersion: "9"},
		Packages: packages{Full: fullPackage{
			URL:  "https://iosapps.itunes.apple.com/path/app.ipa?token=secret",
			Sinf: string(sinf),
		}},
	})
	if err == nil {
		t.Fatal("accepted a TestFlight package without dpInfo")
	}
}

func TestTestFlightHardwareID(t *testing.T) {
	got, err := testFlightHardwareID("000102030405060708090a0b0c0d0e0f10111213")
	if err != nil {
		t.Fatal(err)
	}

	want := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19}
	if !bytes.Equal(got, want) {
		t.Fatalf("hardware ID = %x", got)
	}

	for _, input := range []string{"", "00010203", "000102030405060708090a0b0c0d0e0f1011121z"} {
		if _, err := testFlightHardwareID(input); err == nil {
			t.Fatalf("accepted invalid TestFlight device ID %q", input)
		}
	}
}

func TestParseInstallDataRejectsUntrustedPackageURL(t *testing.T) {
	_, _, err := parseInstallData(installData{
		URL: "https://example.com/app.ipa?token=secret",
	})
	if err == nil {
		t.Fatal("accepted an untrusted package URL")
	}
}
