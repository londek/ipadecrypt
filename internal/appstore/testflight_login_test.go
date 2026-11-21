package appstore

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"howett.net/plist"
)

func TestValidateTestFlightStoreLogin(t *testing.T) {
	for _, test := range []struct {
		name      string
		change    func(map[string]any)
		wantError bool
	}{
		{name: "authenticated account"},
		{name: "different account", wantError: true, change: func(v map[string]any) { v["dsPersonId"] = "67890" }},
		{name: "missing status", wantError: true, change: func(v map[string]any) { delete(v, "status") }},
		{name: "rejected login", wantError: true, change: func(v map[string]any) { v["status"] = 1 }},
		{name: "missing credential", wantError: true, change: func(v map[string]any) { delete(v, "passwordToken") }},
	} {
		t.Run(test.name, func(t *testing.T) {
			values := map[string]any{"status": 0, "dsPersonId": "12345", "passwordToken": "example-token"}
			if test.change != nil {
				test.change(values)
			}

			data, err := plist.Marshal(values, plist.XMLFormat)
			if err != nil {
				t.Fatal(err)
			}

			err = validateTestFlightStoreLogin(data, "12345")
			if (err != nil) != test.wantError {
				t.Fatalf("got error %v", err)
			}

			if err != nil && strings.Contains(err.Error(), "example-token") {
				t.Fatal("credential included in error")
			}
		})
	}

	if err := validateTestFlightStoreLogin([]byte("invalid plist"), "12345"); err == nil {
		t.Fatal("accepted malformed login")
	}
}

func TestReadTestFlightStoreResponse(t *testing.T) {
	for _, test := range []struct {
		name, body string
		status     int
		wantError  bool
	}{
		{"success", "response", http.StatusOK, false},
		{"HTTP error", "private server response", http.StatusForbidden, true},
		{"oversized", strings.Repeat("x", (1<<20)+1), http.StatusOK, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			body := io.NopCloser(strings.NewReader(test.body))

			data, err := readTestFlightStoreResponse(&http.Response{StatusCode: test.status, Body: body})
			if (err != nil) != test.wantError {
				t.Fatalf("got error %v", err)
			}

			if err == nil && string(data) != test.body {
				t.Fatal("response changed")
			}

			if err != nil && strings.Contains(err.Error(), "private server response") {
				t.Fatal("server response included in error")
			}
		})
	}
}
