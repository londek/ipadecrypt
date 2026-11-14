package http

import (
	"net/http"
	"strings"
	"testing"
)

func TestResponseDescriptionOmitsRedirectAndCookieSecrets(t *testing.T) {
	response := &http.Response{StatusCode: http.StatusFound, Header: http.Header{
		"Location": {"https://user:password@example.test/redirect?token=private"},
		"Set-Cookie": {"session=secret"},
	}}
	description := DescribeResponse(response)
	for _, secret := range []string{"password", "token=", "private", "session=", "secret"} {
		if strings.Contains(description, secret) {
			t.Fatalf("response description exposed %q", secret)
		}
	}
	if !strings.Contains(description, "location=present") || !strings.Contains(description, "set-cookie=present") {
		t.Fatal("response description lost redirect/cookie presence")
	}
}
