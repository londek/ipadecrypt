package main

import (
	"errors"
	"testing"

	"github.com/londek/ipadecrypt/internal/macstore"
	store "github.com/majd/ipatool/v2/pkg/appstore"
)

func TestMacMissingLicenseRecoveryIsBounded(t *testing.T) {
	unknown := errors.New("purchase outcome unknown")
	for _, tc := range []struct {
		name                         string
		price                        float64
		currency                     string
		initial, purchase, retry     error
		wantDownloads, wantPurchases int
		wantError                    bool
	}{
		{"owned", 0, "USD", nil, nil, nil, 1, 0, false},
		{"free missing license", 0, "USD", store.ErrLicenseRequired, nil, nil, 2, 1, false},
		{"paid", 2, "USD", store.ErrLicenseRequired, nil, nil, 1, 0, true},
		{"unknown price", 0, "", store.ErrLicenseRequired, nil, nil, 1, 0, true},
		{"other failure", 0, "USD", store.ErrPasswordTokenExpired, nil, nil, 1, 0, true},
		{"uncertain purchase", 0, "USD", store.ErrLicenseRequired, unknown, nil, 1, 1, true},
		{"license still missing", 0, "USD", store.ErrLicenseRequired, nil, store.ErrLicenseRequired, 2, 1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			downloads, purchases := 0, 0
			catalog := macstore.CatalogApp{App: store.App{Price: tc.price}, OfferPrice: tc.price, Currency: tc.currency}

			path, err := downloadWithMacLicense(catalog, func(force bool) (string, error) {
				downloads++
				if force != (downloads == 2) {
					t.Fatal("retry must request a fresh ticket")
				}

				e := tc.initial
				if downloads == 2 {
					e = tc.retry
				}

				if e != nil {
					return "", e
				}

				return "encrypted.ipa", nil
			}, func() error { purchases++; return tc.purchase })
			if (err != nil) != tc.wantError || downloads != tc.wantDownloads || purchases != tc.wantPurchases {
				t.Fatalf("path=%q err=%v downloads=%d purchases=%d", path, err, downloads, purchases)
			}

			if tc.purchase == unknown && !errors.Is(err, unknown) {
				t.Fatal("purchase error lost")
			}
		})
	}
}
