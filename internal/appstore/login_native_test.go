package appstore

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/londek/ipadecrypt/internal/storeauth"
)

type nativeRoundTripFunc func(*http.Request) (*http.Response, error)

func (f nativeRoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

type nativeTestSigner struct{}

func (nativeTestSigner) Sign([]byte) ([]byte, error) { return []byte{0xAA}, nil }
func (nativeTestSigner) Close() error                { return nil }

type nativeProviderFunc func(time.Time) (map[string]string, error)

func (f nativeProviderFunc) Headers(at time.Time) (map[string]string, error) { return f(at) }

type nativeSignerFunc func([]byte) ([]byte, error)

func (f nativeSignerFunc) Sign(body []byte) ([]byte, error) { return f(body) }
func (nativeSignerFunc) Close() error                       { return nil }

func TestNativeLoginRejectsMissingAMDWithoutNetwork(t *testing.T) {
	for _, headers := range []map[string]string{{}, {"X-Apple-AMD": "proof"}, {"X-Apple-AMD-M": "mid"}} {
		client := &Client{
			anisette: nativeProviderFunc(func(time.Time) (map[string]string, error) { return headers, nil }),
			http: &http.Client{Transport: nativeRoundTripFunc(func(*http.Request) (*http.Response, error) {
				t.Fatal("incomplete Store proof must fail before any network request")
				return nil, errors.New("unexpected request")
			})},
		}
		if _, err := client.LoginNative("test@example.com", "unused", ""); err == nil || !strings.Contains(err.Error(), "requires an AMD snapshot") {
			t.Fatalf("missing AMD pair: %v", err)
		}
	}
}

func TestNativeStoreActionAndFreshProofAfterSigning(t *testing.T) {
	for _, fromHeader := range []bool{false, true} {
		signed, sent, generated := false, 0, 0
		client := &Client{anisette: nativeProviderFunc(func(time.Time) (map[string]string, error) {
			if !signed {
				t.Fatal("proof generated before signing completed")
			}

			generated++

			return map[string]string{"X-Apple-AMD": "fresh-proof", "X-Apple-AMD-M": "fresh-mid"}, nil
		})}
		client.http = &http.Client{Transport: nativeRoundTripFunc(func(req *http.Request) (*http.Response, error) {
			sent++

			if req.Header.Get("X-Apple-AMD") != "fresh-proof" || req.Header.Get("X-Apple-AMD-M") != "fresh-mid" {
				t.Fatal("sent stale proof")
			}

			headers := http.Header{}
			headers.Set("X-Apple-AMD-Data", "secret-challenge")

			message := "AMD-Action::SP"

			if fromHeader {
				headers.Set("X-Apple-AMD-Action", "SP")

				message = "Store action required"
			}

			return &http.Response{StatusCode: 200, Header: headers, Body: io.NopCloser(strings.NewReader(
				`<plist version="1.0"><dict><key>customerMessage</key><string>` + message + `</string></dict></plist>`))}, nil
		})}
		signer := nativeSignerFunc(func([]byte) ([]byte, error) { signed = true; return []byte{0xaa}, nil })
		_, err := client.bridgeNativeSession(context.Background(), "test@example.com", "guid",
			&storeauth.GrandSlamSession{PET: "secret-pet"}, http.Header{}, signer)

		var action *NativeMachineActionError
		if !errors.As(err, &action) || action.Action != "SP" || !action.AMDPresent || !action.ProvisioningDataPresent {
			t.Fatalf("expected typed Store action with proof and challenge presence: %v", err)
		}

		if strings.Contains(err.Error(), "secret-") {
			t.Fatal("authentication secret leaked")
		}

		if sent != 1 || generated != 1 {
			t.Fatalf("unexpected automatic retry: sent=%d generated=%d", sent, generated)
		}
	}
}

func TestBridgeNativeSessionSendsAMDHeaders(t *testing.T) {
	const responseBody = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>status</key><integer>0</integer>
  <key>dsPersonId</key><string>42</string>
  <key>passwordToken</key><string>token</string>
  <key>accountInfo</key><dict>
    <key>appleId</key><string>test@example.com</string>
    <key>address</key><dict><key>firstName</key><string>Test</string></dict>
  </dict>
</dict></plist>`

	var amd, amdMid, clientApplication, profile, requestBody, endpoint string

	client := &Client{http: &http.Client{Transport: nativeRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		amd = req.Header.Get("X-Apple-AMD")
		endpoint = req.URL.String()
		body, _ := io.ReadAll(req.Body)
		requestBody = string(body)
		amdMid = req.Header.Get("X-Apple-AMD-M")
		clientApplication = req.Header.Get("X-Apple-Client-Application")
		profile = req.Header.Get("User-Agent") + "|" + req.Header.Get("x-apple-age-area-compliance-id") + "|" + req.Header.Get("Accept-Language") + "|" + req.Header.Get("X-Apple-Tz")

		return &http.Response{
			StatusCode: http.StatusOK,
			Header: http.Header{
				"Content-Type": {"application/x-apple-plist"},
				hdrStoreFront:  {"143441-16,29"},
				hdrPod:         {"29"},
			},
			Body: io.NopCloser(strings.NewReader(responseBody)),
		}, nil
	})}}
	headers := http.Header{}
	headers.Set("X-Apple-AMD", "amd-value")
	headers.Set("X-Apple-AMD-M", "amd-mid-value")
	headers.Set("X-Apple-I-TimeZone", "Europe/Moscow")
	headers.Set("User-Agent", "captured-static-user-agent")

	session := &storeauth.GrandSlamSession{ADSID: "adsid", PET: "pet", DSID: 42}

	account, err := client.bridgeNativeSession(context.Background(), "test@example.com", "guid", session, headers, nativeTestSigner{})
	if err != nil {
		t.Fatal(err)
	}

	if account.PasswordToken != "token" || account.DirectoryServicesID != "42" {
		t.Fatalf("unexpected account: %+v", account)
	}

	if amd != "amd-value" || amdMid != "amd-mid-value" {
		t.Fatalf("AMD headers = %q / %q", amd, amdMid)
	}

	if clientApplication != "com.apple.accountsd" {
		t.Fatalf("client application = %q", clientApplication)
	}

	if profile != nativeUserAgent+"|US|en-US,en;q=0.9|Europe/Moscow" {
		t.Fatalf("native profile = %q", profile)
	}

	if !strings.Contains(requestBody, "<key>accountKind</key><integer>0</integer>") {
		t.Fatalf("native body lacks accountKind: %s", requestBody)
	}

	if endpoint != nativeAuthEndpoint {
		t.Fatalf("endpoint = %q", endpoint)
	}
}

func TestBridgeNativeSessionReportsResponseLayer(t *testing.T) {
	client := &Client{http: &http.Client{Transport: nativeRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header: http.Header{
				"Server":     {"Apple"},
				"Set-Cookie": {"secret-cookie-value"},
			},
			Body: io.NopCloser(strings.NewReader("")),
		}, nil
	})}}
	session := &storeauth.GrandSlamSession{ADSID: "adsid", PET: "pet", DSID: 42}

	_, err := client.bridgeNativeSession(context.Background(), "test@example.com", "guid", session, http.Header{}, nativeTestSigner{})
	if err == nil || !strings.Contains(err.Error(), "layer=edge") {
		t.Fatalf("error = %v, want response layer", err)
	}

	if strings.Contains(err.Error(), "secret-cookie-value") {
		t.Fatal("cookie value leaked into error")
	}
}
