package macstore

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	store "github.com/majd/ipatool/v2/pkg/appstore"
)

func TestCatalogFailsClosed(t *testing.T) {
	good := `{"resultCount":1,"results":[{"trackId":123,"bundleId":"test.app","trackName":"App","version":"1","price":0,"currency":"USD","kind":"software"}]}`
	for _, tc := range []struct {
		name, body string
		ok         bool
	}{
		{"valid", good, true}, {"missing price", strings.Replace(good, `"price":0,`, "", 1), false}, {"wrong id", strings.Replace(good, `"trackId":123`, `"trackId":456`, 1), false}, {"wrong kind", strings.Replace(good, `"software"`, `"podcast"`, 1), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := parseLookup([]byte(tc.body), "123", "")
			if (err == nil) != tc.ok {
				t.Fatalf("err=%v", err)
			}
		})
	}

	app := store.App{ID: 123, BundleID: "test.app"}
	offer := `<script id="serialized-server-data" type="application/json">[{"$kind":"PurchaseConfiguration","bundleId":"recommended.app","appPlatforms":["phone"],"buyParams":"price=0&salableAdamId=999&appExtVrsId=100"},{"$kind":"PurchaseConfiguration","bundleId":"test.app","appPlatforms":["phone"],"buyParams":"price=0&salableAdamId=123&appExtVrsId=456"}]</script>`

	v, p, err := parseOffer([]byte(offer), app)
	if err != nil || v != "456" || p != 0 {
		t.Fatalf("%s %f %v", v, p, err)
	}

	for _, bad := range []string{strings.ReplaceAll(offer, "price=0&", ""), strings.ReplaceAll(offer, `["phone"]`, `["mac"]`), strings.ReplaceAll(offer, "salableAdamId=123", "salableAdamId=124")} {
		if _, _, err := parseOffer([]byte(bad), app); err == nil {
			t.Fatal("accepted invalid offer")
		}
	}

	if c, err := Country("143441-1,34"); err != nil || c != "us" {
		t.Fatal(c, err)
	}

	for _, bad := range []string{"https://evil.test/us/app/id123", "https://apps.apple.com.evil.test/id123", "../path", "0"} {
		if _, _, err := Target(bad); err == nil {
			t.Fatal("accepted", bad)
		}
	}
}

type fakeCommerce struct {
	apps        []store.App
	purchaseErr error
	calls       int
	change      bool
}

func (f *fakeCommerce) OwnedApps(in store.OwnedAppsInput) (store.OwnedAppsOutput, error) {
	return store.OwnedAppsOutput{Page: in.Page, Count: len(f.apps), TotalCount: len(f.apps), Results: f.apps}, nil
}
func (f *fakeCommerce) Purchase(in store.PurchaseInput) error {
	f.calls++
	if f.change {
		f.apps = append(f.apps, in.App)
	}

	return f.purchaseErr
}
func TestPurchaseEvidence(t *testing.T) {
	c := CatalogApp{App: store.App{ID: 123, BundleID: "test.app"}, Currency: "USD", CheckedAt: time.Now()}
	a := store.Account{DirectoryServicesID: "12345"}

	for _, tc := range []struct {
		name          string
		owned, change bool
		purchaseErr   error
		outcome       string
		wantErr       bool
		calls         int
	}{
		{"acquired", false, true, nil, "purchase-verified", false, 1},
		{"already", true, false, nil, "already-owned", false, 0},
		{"ambiguous", false, false, errors.New("network"), "pending-or-unknown", true, 1},
		{"race", false, true, store.ErrLicenseAlreadyExists, "owned-after-race", false, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeCommerce{change: tc.change, purchaseErr: tc.purchaseErr}
			if tc.owned {
				f.apps = []store.App{c.App}
			}

			dir := t.TempDir()

			ev, err := Purchase(context.Background(), f, a, c, dir)
			if (err != nil) != tc.wantErr || ev.Outcome != tc.outcome || f.calls != tc.calls {
				t.Fatalf("%+v %v calls=%d", ev, err, f.calls)
			}

			if tc.calls > 0 {
				matches, _ := filepath.Glob(filepath.Join(dir, "purchases", "*", "before.json"))
				if len(matches) != 1 {
					t.Fatal("missing immutable before evidence")
				}
			}
		})
	}

	f := &fakeCommerce{}

	c.App.Price = 1
	if _, err := Purchase(context.Background(), f, a, c, t.TempDir()); err == nil || f.calls != 0 {
		t.Fatal("paid purchase allowed")
	}
}
func TestStateLockAndPermissions(t *testing.T) {
	dir := t.TempDir()

	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	if second, err := Open(dir); err == nil {
		second.Close()
		t.Fatal("concurrent state access allowed")
	}

	keys := diskKeys(filepath.Join(dir, "keys"))
	if err = keys.Set("test", []byte("secret")); err != nil {
		t.Fatal(err)
	}

	st, err := os.Stat(keys.path("test"))
	if err != nil || st.Mode().Perm() != 0600 {
		t.Fatal(st, err)
	}
}
