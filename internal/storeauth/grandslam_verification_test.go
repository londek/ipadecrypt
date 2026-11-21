package storeauth

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

type verificationTransport func(*http.Request) (*http.Response, error)

func (f verificationTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestVerifyGrandSlam(t *testing.T) {
	for _, test := range []struct {
		name, code, endpoint, result string
		wantError                    bool
	}{
		{"request code", "", "https://gsa.apple.com/auth/verify", "", false},
		{"validate code", "123456", "https://gsa.apple.com/auth/verify", `<plist><dict><key>Status</key><dict><key>ec</key><integer>0</integer></dict></dict></plist>`, false},
		{"validate code with top-level status", "123456", "https://gsa.apple.com/auth/verify", `<plist><dict><key>ec</key><integer>0</integer></dict></plist>`, false},
		{"wrong code", "123456", "https://gsa.apple.com/auth/verify", `<plist><dict><key>Status</key><dict><key>ec</key><integer>-1</integer></dict></dict></plist>`, true},
		{"missing status", "123456", "https://gsa.apple.com/auth/verify", `<plist><dict/></plist>`, true},
		{"foreign endpoint", "", "https://example.com/verify", "", true},
		{"plaintext endpoint", "", "http://gsa.apple.com/verify", "", true},
		{"endpoint credentials", "", "https://user@gsa.apple.com/verify", "", true},
		{"invalid code", "abcdef", "https://gsa.apple.com/auth/verify", "", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			client := &http.Client{Transport: verificationTransport(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.Method != http.MethodGet || r.URL.Host != "gsa.apple.com" {
					t.Fatal("verification credentials sent to untrusted target")
				}
				body := test.result
				if calls == 1 {
					if r.URL.Path != "/grandslam/GsService2/lookup" {
						t.Error("wrong lookup URL")
					}
					body = `<plist><dict><key>urls</key><dict><key>trustedDeviceSecondaryAuth</key><string>` + test.endpoint + `</string><key>validateCode</key><string>` + test.endpoint + `</string></dict></dict></plist>`
				} else {
					if calls != 2 || r.Header.Get("X-Apple-Identity-Token") != "YWNjb3VudDp0b2tlbg==" || r.Header.Get("security-code") != test.code {
						t.Error("wrong verification request")
					}
				}
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
			})}
			err := VerifyGrandSlam(context.Background(), client, make(http.Header), GrandSlamAccount{ADSID: "account", VerificationToken: "token"}, test.code)
			if (err != nil) != test.wantError {
				t.Fatalf("got error %v", err)
			}
			if !test.wantError && calls != 2 {
				t.Fatalf("got %d requests, want 2", calls)
			}
			if test.name == "invalid code" && calls != 0 {
				t.Fatal("invalid code sent to server")
			}
		})
	}
}
