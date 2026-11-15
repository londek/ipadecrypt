package store

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/londek/ipadecrypt/internal/anisette"
	"github.com/londek/ipadecrypt/internal/store/emulator"
)

type testAnisetteProvider struct {
	headers map[string]string
	err     error
	calls   atomic.Int32
}

func (p *testAnisetteProvider) Headers(time.Time) (map[string]string, error) {
	p.calls.Add(1)
	return p.headers, p.err
}

func TestRequestTransportInjectsAnisette(t *testing.T) {
	received := make(chan http.Header, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received <- r.Header.Clone()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	provider := &testAnisetteProvider{headers: map[string]string{
		anisette.HeaderMD:  "generated-md",
		anisette.HeaderMDM: "generated-mid",
	}}
	backend := New(nil, nil, provider)
	pointTransportAt(backend.transport, server)

	request := newClientRequest(t, http.MethodGet, "http://p73-buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/authenticate", nil)
	request.Header.Set(anisette.HeaderMD, "existing-md")

	response, err := backend.requestTransport(emulator.Request{})(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()

	headers := <-received
	if got := headers.Get(anisette.HeaderMD); got != "existing-md" {
		t.Fatalf("MD = %q, want existing header", got)
	}
	if got := headers.Get(anisette.HeaderMDM); got != "generated-mid" {
		t.Fatalf("MD-M = %q, want generated header", got)
	}
	if provider.calls.Load() != 1 {
		t.Fatalf("provider calls = %d, want 1", provider.calls.Load())
	}
}

func TestRequestTransportSkipsNonAppleHost(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(anisette.HeaderMD) != "" {
			t.Error("anisette header sent to a non-Apple host")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	provider := &testAnisetteProvider{headers: map[string]string{anisette.HeaderMD: "generated-md"}}
	backend := New(nil, nil, provider)
	pointTransportAt(backend.transport, server)

	request := newClientRequest(t, http.MethodGet, "http://example.com/resource", nil)
	response, err := backend.requestTransport(emulator.Request{})(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()

	if provider.calls.Load() != 0 {
		t.Fatalf("provider calls = %d, want 0", provider.calls.Load())
	}
}

func TestRequestTransportReturnsAnisetteError(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	provider := &testAnisetteProvider{err: errors.New("generator failed")}
	backend := New(nil, nil, provider)
	pointTransportAt(backend.transport, server)

	request := newClientRequest(t, http.MethodGet, "http://gsa.apple.com/grandslam/GsService2", nil)
	if _, err := backend.requestTransport(emulator.Request{})(request); err == nil || !strings.Contains(err.Error(), "anisette") {
		t.Fatalf("error = %v, want anisette failure", err)
	}
	if requests.Load() != 0 {
		t.Fatal("request reached the server after an anisette failure")
	}
}

func TestAppleHost(t *testing.T) {
	for _, host := range []string{"buy.itunes.apple.com", "P73-BUY.ITUNES.APPLE.COM", "gsa.apple.com"} {
		if !appleHost(host) {
			t.Errorf("%q should receive anisette", host)
		}
	}

	for _, host := range []string{"example.com", "buy.itunes.apple.com.example", "p-buy.itunes.apple.com", "pod-buy.itunes.apple.com", "auth.itunes.apple.com"} {
		if appleHost(host) {
			t.Errorf("%q should not receive anisette", host)
		}
	}
}

func newClientRequest(t *testing.T, method, url string, body io.Reader) *http.Request {
	t.Helper()

	request, err := http.NewRequest(method, url, body)
	if err != nil {
		t.Fatal(err)
	}

	return request
}

func pointTransportAt(transport *http.Transport, server *httptest.Server) {
	transport.Proxy = nil
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}
}
