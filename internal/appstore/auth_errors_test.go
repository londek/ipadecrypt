package appstore

import (
	"errors"
	"net/http"
	"testing"
)

func TestAuthenticateLayerError(t *testing.T) {
	edge := http.Header{"Server": {"Apple"}}
	short := http.Header{"Server": {"Apple"}, "X-Responding-Instance": {"MZFinance:12345:01:abc"}}
	full := http.Header{"Server": {"Apple"}, "Apple-Originating-System": {"MZFinance"}}
	daiquiri := http.Header{"Server": {"Apple"}, "X-Daiquiri-Instance": {"a", "b"}}

	tests := []struct {
		name   string
		status int
		header http.Header
		want   error
	}{
		{"edge 204", http.StatusNoContent, edge, ErrEdgeRejected},
		{"edge 301 decoy", http.StatusMovedPermanently, edge, ErrEdgeRejected},
		{"edge 404 stub", http.StatusNotFound, edge, ErrEdgeRejected},
		{"daiquiri 504", http.StatusGatewayTimeout, daiquiri, ErrEdgeRejected},
		{"backend short 403", http.StatusForbidden, short, ErrAuthRequestRejected},
		{"backend pod redirect", http.StatusFound, withLocation(short), nil},
		{"backend full 200", http.StatusOK, full, nil},
		{"backend full 302", http.StatusFound, withLocation(full), nil},
		{"backend short 200 verdict", http.StatusOK, short, nil},
		{"edge 200 html stub", http.StatusOK, edge, ErrEdgeRejected},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := authenticateLayerError(&http.Response{StatusCode: tt.status, Header: tt.header})
			if tt.want == nil {
				if err != nil {
					t.Fatalf("got %v, want nil", err)
				}

				return
			}

			if !errors.Is(err, tt.want) {
				t.Fatalf("got %v, want %v", err, tt.want)
			}
		})
	}
}

func withLocation(h http.Header) http.Header {
	c := h.Clone()
	c.Set("Location", "https://p46-buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/authenticate")

	return c
}
