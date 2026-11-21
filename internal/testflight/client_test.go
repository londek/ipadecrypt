package testflight

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sync/atomic"
	"testing"
)

func TestSessionDigest(t *testing.T) {
	got := sessionDigest("example-session", "example-request", "123", "example-suffix")

	want := "d4c015bd6ce3077426c371f042ce57bec452933c"
	if got != want {
		t.Fatalf("sessionDigest() = %q, want %q", got, want)
	}
}

func TestSessionDigestMatchesNativeFormat(t *testing.T) {
	// Calculated independently from TestFlightServices 4.4.1's NSString format
	// with synthetic identifiers, rather than from the Go implementation.
	got := sessionDigest("example-session", "00000000-0000-4000-8000-000000000001", "12345", requestDigestSuffix)

	const want = "87432f2cecb8a6c1abba83c6e5b17e3e55a6deee"
	if got != want {
		t.Fatalf("sessionDigest() = %q, want %q", got, want)
	}
}

func TestSendRequiresSession(t *testing.T) {
	client := Client{}
	if err := client.send(t.Context(), http.MethodGet, "/v4/accounts/example/apps", nil, nil); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("send error = %v, want ErrSessionExpired", err)
	}
}

func TestNewUUID(t *testing.T) {
	got, err := newUUID()
	if err != nil {
		t.Fatal(err)
	}

	if !regexp.MustCompile(`^[0-9A-F]{8}-[0-9A-F]{4}-4[0-9A-F]{3}-[89AB][0-9A-F]{3}-[0-9A-F]{12}$`).MatchString(got) {
		t.Fatalf("newUUID() = %q", got)
	}
}

func TestHTTPClientDoesNotForwardTestFlightHeadersThroughRedirects(t *testing.T) {
	var forwarded atomic.Bool

	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { forwarded.Store(true) }))
	defer target.Close()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Session-Id") != "example-session" {
			t.Error("source request lost its session header")
		}

		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer server.Close()

	request, err := http.NewRequest(http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}

	request.Header.Set("X-Session-Id", "example-session")

	response, err := newHTTPClient().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusTemporaryRedirect || forwarded.Load() {
		t.Fatal("TestFlight authentication headers were forwarded through a redirect")
	}
}

func TestDecodeResponse(t *testing.T) {
	for _, test := range []struct {
		name, body      string
		read, wantError bool
	}{
		{"read data", `{"data":{"name":"Example"},"error":false}`, true, false},
		{"accepted", `{}`, false, false},
		{"empty acknowledgement", ``, false, false},
		{"rejected acknowledgement", `{"error":true}`, false, true},
		{"rejected read", `{"data":{"name":"Example"},"error":{"code":"rejected"}}`, true, true},
		{"error message", `{"messages":[{"messageType":"ERROR"}]}`, false, true},
		{"alternate error message", `{"messages":[{"type":"error"}]}`, false, true},
		{"missing data", `{}`, true, true},
		{"null data", `{"data":null}`, true, true},
		{"invalid response", `not JSON`, false, true},
		{"null response", `null`, false, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var (
				output struct {
					Data struct {
						Name string `json:"name"`
					} `json:"data"`
				}
				target any
			)
			if test.read {
				target = &output
			}

			err := decodeResponse([]byte(test.body), target)
			if (err != nil) != test.wantError {
				t.Fatalf("got error %v", err)
			}

			if err == nil && test.read && output.Data.Name != "Example" {
				t.Fatal("response data not decoded")
			}
		})
	}
}
