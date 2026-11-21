package testflight

import "testing"

func TestDecodeSession(t *testing.T) {
	for _, test := range []struct {
		name, body string
		wantError  bool
	}{
		{"authenticated", `{"data":{"sessionId":"example-session","accountId":"example-account"},"error":false}`, false},
		{"missing session", `{"data":{"accountId":"example-account"}}`, true},
		{"missing account", `{"data":{"sessionId":"example-session"}}`, true},
		{"invalid header value", `{"data":{"sessionId":"example\nsession","accountId":"example-account"}}`, true},
		{"error envelope", `{"data":{"sessionId":"example-session","accountId":"example-account"},"error":true}`, true},
		{"malformed", `not JSON`, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			session, err := decodeSession([]byte(test.body))
			if (err != nil) != test.wantError {
				t.Fatalf("got error %v", err)
			}

			if err == nil && (session.SessionID != "example-session" || session.AccountID != "example-account") {
				t.Fatal("wrong session decoded")
			}
		})
	}
}
