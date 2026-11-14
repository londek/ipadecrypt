package appstore

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"
)

func TestStoreAMDUsesSnapshotWithoutProvisioningState(t *testing.T) {
	calls := 0
	providerErr := errors.New("snapshot unavailable")
	client := &Client{anisette: nativeProviderFunc(func(time.Time) (map[string]string, error) {
		calls++
		if calls == 2 {
			return nil, providerErr
		}

		return map[string]string{"X-Apple-AMD": "snapshot-proof", "X-Apple-AMD-M": "snapshot-mid"}, nil
	})}
	endpoint := "https://downloaddispatch.itunes.apple.com/r/redownload?guid=phone-udid"

	headers, err := client.storeAMDProof(context.Background(), endpoint, nil)
	if err != nil || headers["X-Apple-AMD"] != "snapshot-proof" || headers["X-Apple-AMD-M"] != "snapshot-mid" {
		t.Fatalf("snapshot proof: %v, %v", headers, err)
	}

	if _, err := client.storeAMDProof(context.Background(), endpoint, nil); !errors.Is(err, providerErr) {
		t.Fatalf("snapshot failure = %v", err)
	}

	if _, err := client.storeAMDProof(context.Background(), "https://example.com/", nil); err == nil || calls != 2 {
		t.Fatalf("untrusted endpoint reached provider: calls=%d err=%v", calls, err)
	}
}

func TestStoreAMDAllowlistAndDSIDFallback(t *testing.T) {
	for url, want := range map[string]bool{
		"https://p25-buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/volumeStoreDownloadProduct?guid=A": true,
		"https://buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/volumeStoreDownloadProduct?guid=A":     true,
		"https://downloaddispatch.itunes.apple.com/r/redownload?guid=A":                                  true,
		"https://downloaddispatch.itunes.apple.com" + entDownloadPath + "?guid=A":                        true,
		"https://evil.example/WebObjects/MZFinance.woa/wa/volumeStoreDownloadProduct?guid=A":             false,
		"https://pX-buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/volumeStoreDownloadProduct?guid=A":  false,
		"https://buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/buyProduct?guid=A":                     false,
		"https://downloaddispatch.itunes.apple.com/r/redownload?guid=A&x=1":                              false,
		"https://downloaddispatch.itunes.apple.com/r/redownload":                                         false,
		"http://downloaddispatch.itunes.apple.com/r/redownload?guid=A":                                   false,
	} {
		if got := isStoreAMDCommerceURL(url); got != want {
			t.Errorf("isStoreAMDCommerceURL(%q) = %v, want %v", url, got, want)
		}
	}

	h := http.Header{}
	h.Add("Set-Cookie", "itspod=25; Path=/")
	h.Add("Set-Cookie", "mz_at0-1234567890=abc; Path=/")

	if got := authenticationResponseDSID(h); got != "1234567890" {
		t.Errorf("DSID from cookie = %q", got)
	}

	h.Set("X-Dsid", "42")

	if got := authenticationResponseDSID(h); got != "42" {
		t.Errorf("DSID from X-Dsid = %q", got)
	}

	if a := authenticationMachineAction(http.Header{"X-Apple-Amd-Action": {"SP"}, "X-Apple-Amd-Data": {"d"}}); a == nil || a.action != "SP" || a.data != "d" {
		t.Errorf("machine action = %+v", a)
	}
}
