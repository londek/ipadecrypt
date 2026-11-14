package macstore

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	store "github.com/majd/ipatool/v2/pkg/appstore"
	"howett.net/plist"
)

func TestEnrollmentKeybagIdentity(t *testing.T) {
	account := store.Account{DirectoryServicesID: "12345"}
	app := CatalogApp{App: store.App{ID: 123, BundleID: "test.app"}, ExternalVersionID: "456"}

	for _, tc := range []struct {
		name   string
		alter  func(map[string]any, map[string]any)
		reject bool
	}{
		{"matching", func(map[string]any, map[string]any) {}, false},
		{"wrong account", func(r, m map[string]any) { r["dsPersonId"] = "999" }, true},
		{"wrong app", func(r, m map[string]any) { m["itemId"] = uint64(999) }, true},
		{"wrong bundle", func(r, m map[string]any) { m["softwareVersionBundleId"] = "another.app" }, true},
		{"wrong version", func(r, m map[string]any) { m["softwareVersionExternalIdentifier"] = uint64(999) }, true},
		{"missing keybag", func(r, m map[string]any) { delete(r, "keybag") }, true},
		{"wrong keybag type", func(r, m map[string]any) { r["keybag"] = "encoded string" }, true},
		{"ambiguous tickets", func(r, m map[string]any) {
			r["songList"] = []any{map[string]any{"metadata": m}, map[string]any{"metadata": m}}
		}, true},
		{"store failure", func(r, m map[string]any) { r["failureType"] = "9610" }, true},
		{"failed status", func(r, m map[string]any) { r["status"] = uint64(1) }, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			meta := map[string]any{"itemId": uint64(123), "softwareVersionBundleId": "test.app", "softwareVersionExternalIdentifier": uint64(456)}
			response := map[string]any{"jingleDocType": "purchaseSuccess", "status": uint64(0), "dsPersonId": uint64(12345), "keybag": []byte("synthetic keybag"), "songList": []any{map[string]any{"metadata": meta}}}
			tc.alter(response, meta)
			// Exercise the real plist representation, including numeric identifiers.
			encoded, err := plist.Marshal(response, plist.XMLFormat)
			if err != nil {
				t.Fatal(err)
			}

			var decoded map[string]any
			if _, err = plist.Unmarshal(encoded, &decoded); err != nil {
				t.Fatal(err)
			}

			bag, err := enrollmentKeybag(decoded, account, app)
			if (err != nil) != tc.reject || !tc.reject && string(bag) != "synthetic keybag" {
				t.Fatalf("keybag=%q error=%v", bag, err)
			}
		})
	}
}

func TestStoreEndpointRejectsTokenDestinations(t *testing.T) {
	valid := "https://downloaddispatch.itunes.apple.com" + entDownloadPath
	if _, err := storeEndpoint(valid, entDownloadPath); err != nil {
		t.Fatal(err)
	}

	for _, raw := range []string{
		strings.Replace(valid, "https:", "http:", 1), valid + "?", valid + "?redirect=1", valid + "#fragment",
		strings.Replace(valid, ".com/", ".com.evil/", 1), strings.Replace(valid, ".com/", ".com:443/", 1),
		strings.Replace(valid, "https://", "https://user@", 1), strings.Replace(valid, "/ent/", "/%65nt/", 1),
		"https://p42-buy.itunes.apple.com" + entDownloadPath,
	} {
		if _, err := storeEndpoint(raw, entDownloadPath); err == nil {
			t.Errorf("accepted %q", raw)
		}
	}
}

func TestStoreActionsAndPurchaseEvidence(t *testing.T) {
	url := "https://p42-buy.itunes.apple.com" + termsPath
	response := map[string]any{"jingleDocType": "buyProductFailure", "action": map[string]any{"kind": "Goto", "url": url, "target": "main"}}
	err := storeInteraction(response)

	var interaction *InteractionError
	if !errors.As(err, &interaction) || interaction.TermsURL != "macappstores://p42-buy.itunes.apple.com"+termsPath {
		t.Fatalf("terms action: %v", err)
	}

	for _, link := range []string{"https://evil.example" + termsPath, url + "?token=secret", "https://p42-buy.itunes.apple.com/other", "file:///tmp/terms"} {
		if termsAction(map[string]any{"action": map[string]any{"kind": "Goto", "url": link}}, 0) != "" {
			t.Errorf("accepted action %q", link)
		}
	}

	for _, failure := range []error{interaction, store.ErrPasswordTokenExpired} {
		api := &fakeCommerce{purchaseErr: failure}
		catalog := CatalogApp{App: store.App{ID: 123}, Currency: "USD", CheckedAt: time.Now()}

		ev, got := Purchase(context.Background(), api, store.Account{DirectoryServicesID: "12345"}, catalog, t.TempDir())
		if !errors.Is(got, failure) || api.calls != 1 || ev.OwnedAfter || ev.Outcome != "pending-or-unknown" {
			t.Fatalf("lost actionable failure/evidence: %+v %v", ev, got)
		}
	}

	for _, response := range []map[string]any{{"failureType": "2034"}, {"metrics": map[string]any{"messageCode": uint64(2034)}}} {
		if !errors.Is(storeInteraction(response), store.ErrPasswordTokenExpired) {
			t.Fatal("reauthentication code lost")
		}
	}

	err = storeInteraction(map[string]any{"customerMessage": "Please verify your email address"})
	if !errors.As(err, &interaction) || !interaction.EmailVerification {
		t.Fatal("email action lost")
	}
}
