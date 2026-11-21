package appstore

import (
	"net/http"
	"testing"
)

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

func TestTestFlightAMDAllowlist(t *testing.T) {
	for endpoint, want := range map[string]bool{
		"https://testflight.apple.com/v4/accounts/account/apps":        true,
		"https://testflight.apple.com/v1/session/authenticate":         true,
		"https://testflight.apple.com/":                                false,
		"https://testflight.apple.com/v4/accounts/account/apps?x=1":    false,
		"https://testflight.apple.com.evil.example/v4/accounts/a/apps": false,
		"http://testflight.apple.com/v4/accounts/account/apps":         false,
	} {
		if got := isTestFlightAPIURL(endpoint); got != want {
			t.Errorf("isTestFlightAPIURL(%q) = %v, want %v", endpoint, got, want)
		}
	}
}
