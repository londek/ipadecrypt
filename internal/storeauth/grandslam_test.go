package storeauth

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"howett.net/plist"
)

func TestDecodeGrandSlamAccount(t *testing.T) {
	now := time.Unix(1800000000, 0)
	for _, test := range []struct {
		name                    string
		change                  func(map[string]any)
		wantError, verification bool
	}{
		{name: "Store credential"},
		{name: "secondary authentication", verification: true, change: func(v map[string]any) {
			v["status-code"] = 409
			v["GsIdmsToken"] = "verification-token"
			delete(v, "t")
		}},
		{name: "expired credential", wantError: true, change: func(v map[string]any) {
			v["t"].(map[string]any)["com.apple.gs.idms.pet"].(map[string]any)["expiry"] = now.UnixMilli()
		}},
		{name: "missing credential", wantError: true, change: func(v map[string]any) { delete(v, "t") }},
		{name: "missing account", wantError: true, change: func(v map[string]any) { delete(v, "adsid") }},
		{name: "invalid account", wantError: true, change: func(v map[string]any) { v["DsPrsId"] = "12\n34" }},
		{name: "missing status", wantError: true, change: func(v map[string]any) { delete(v, "status-code") }},
		{name: "unexpected status", wantError: true, change: func(v map[string]any) { v["status-code"] = 500 }},
		{name: "missing verification token", wantError: true, change: func(v map[string]any) { v["status-code"] = 409 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			values := map[string]any{
				"adsid": "account-id", "DsPrsId": "12345", "status-code": 200,
				"t": map[string]any{"com.apple.gs.idms.pet": map[string]any{"token": "store-token", "expiry": now.Add(time.Hour).UnixMilli()}},
			}
			if test.change != nil {
				test.change(values)
			}
			data, err := plist.Marshal(values, plist.XMLFormat)
			if err != nil {
				t.Fatal(err)
			}
			for _, fragment := range []bool{false, true} {
				input := data
				if fragment {
					start := strings.Index(string(data), "<dict>")
					end := strings.LastIndex(string(data), "</dict>") + len("</dict>")
					input = data[start:end]
				}
				account, err := decodeGrandSlamAccount(input, now)
				if (err != nil) != test.wantError {
					t.Fatalf("fragment=%v: got error %v", fragment, err)
				}
				if err != nil {
					continue
				}
				if account.ADSID != "account-id" {
					t.Fatal("wrong account")
				}
				if test.verification {
					if account.PasswordToken != "" || account.VerificationToken != "verification-token" {
						t.Fatal("wrong verification state")
					}
				} else if account.PasswordToken != "store-token" || account.DSID != "12345" || !account.Expires.Equal(now.Add(time.Hour)) {
					t.Fatal("wrong Store credential")
				}
			}
		})
	}
}

func TestGrandSlamRequest(t *testing.T) {
	headers := make(http.Header)
	for _, key := range []string{"X-Apple-I-MD", "X-Apple-I-MD-M", "X-Apple-I-MD-LU", "X-Apple-I-MD-RINFO", "X-Mme-Device-Id", "X-MMe-Client-Info", "X-Apple-I-Client-Time", "X-Apple-I-TimeZone", "X-Apple-Locale"} {
		headers.Set(key, "machine-value")
	}
	for _, test := range []struct {
		name, body string
		status     int
		wantError  bool
	}{
		{"success", `<plist><dict><key>Response</key><dict><key>Status</key><dict><key>ec</key><integer>0</integer></dict><key>c</key><string>challenge</string></dict></dict></plist>`, 200, false},
		{"invalid credentials", `<plist><dict><key>Response</key><dict><key>Status</key><dict><key>ec</key><integer>-22406</integer></dict></dict></dict></plist>`, 200, true},
		{"missing status", `<plist><dict><key>Response</key><dict><key>c</key><string>challenge</string></dict></dict></plist>`, 200, true},
		{"malformed", "not a plist", 200, true},
		{"oversized", strings.Repeat("x", anisetteLimit+1), 200, true},
		{"HTTP failure", "server-secret", 403, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost || r.Header.Get("X-Apple-I-MD") != "machine-value" {
					t.Error("missing authentication request")
				}
				var request struct{ Request map[string]any }
				data, readErr := io.ReadAll(r.Body)
				if readErr != nil {
					t.Error(readErr)
				}
				if _, err := plist.Unmarshal(data, &request); err != nil {
					t.Error(err)
				}
				if request.Request["o"] != "init" || request.Request["cpd"] == nil {
					t.Error("missing GrandSlam payload")
				}
				w.WriteHeader(test.status)
				_, _ = fmt.Fprint(w, test.body)
			}))
			defer server.Close()
			result, err := grandSlamRequest(context.Background(), server.Client(), server.URL, headers, map[string]any{"o": "init"})
			if (err != nil) != test.wantError {
				t.Fatalf("got error %v", err)
			}
			if err == nil && result["c"] != "challenge" {
				t.Fatal("wrong challenge")
			}
			if err != nil && strings.Contains(err.Error(), "server-secret") {
				t.Fatal("server response leaked into error")
			}
		})
	}
	t.Run("redirect does not forward credentials", func(t *testing.T) {
		forwarded := false
		target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { forwarded = true }))
		defer target.Close()
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
		}))
		defer server.Close()
		_, err := grandSlamRequest(context.Background(), server.Client(), server.URL, headers, map[string]any{"o": "init"})
		if err == nil || forwarded {
			t.Fatal("authentication redirect was followed")
		}
	})
}
