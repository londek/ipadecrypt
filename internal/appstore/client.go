package appstore

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/londek/ipadecrypt/internal/store"
	"github.com/londek/ipadecrypt/internal/storeauth"
	cookiejar "github.com/juju/persistent-cookiejar"
)

type Client struct {
	jar                 *cookiejar.Jar
	http                *http.Client
	backend             *store.Backend
	actionSignerFactory ActionSignerFactory
	kbsync              kbsyncStore

	// Anisette (Apple device-identity) state, persisted next to the cookies.
	// authMu guards it and authHeaders, which only live for one Login.
	authHTTP      *http.Client
	anisettePath  string
	authMu        sync.Mutex
	anisetteState []byte
	authHeaders   http.Header
}

func New(cookiesFile string) (*Client, error) {
	jar, err := cookiejar.New(&cookiejar.Options{Filename: cookiesFile})
	if err != nil {
		return nil, err
	}

	// Plain client for CDN byte transfers (signed URLs; no attestation needed).
	hc := &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if strings.TrimSuffix(req.Referer(), "/") == authURL {
				return http.ErrUseLastResponse
			}

			return nil
		},
	}

	// Store API requests are built and attested by the emulated AppleMediaServices
	// framework in the backend; the SAP signer (used for authenticate) sends its
	// setup/cert exchange directly through the backend's "sap" executor.
	backend := store.New(jar, macAddress)

	return &Client{
		jar:                 jar,
		http:                hc,
		backend:             backend,
		actionSignerFactory: frameworkActionSignerFactory(backend.Client("sap")),
		authHTTP:            storeauth.NewHTTPClient(jar),
		anisettePath:        filepath.Join(filepath.Dir(cookiesFile), "anisette"),
	}, nil
}

// loadAnisette reads the persisted Anisette state once; a missing file just
// means the machine has not been provisioned yet. Callers hold authMu.
func (c *Client) loadAnisette() {
	if len(c.anisetteState) == 0 {
		c.anisetteState, _ = os.ReadFile(c.anisettePath)
	}
}

// saveAnisette persists the rotated Anisette state. Callers hold authMu.
func (c *Client) saveAnisette(state []byte) error {
	if err := os.WriteFile(c.anisettePath, state, 0o600); err != nil {
		return fmt.Errorf("save Apple authentication state: %w", err)
	}

	c.anisetteState = state

	return nil
}

// guid returns the Configurator-shaped GUID: uppercase MAC address, no colons.
func guid() (string, error) {
	mac, err := macAddress()
	if err != nil {
		return "", err
	}

	return strings.ReplaceAll(strings.ToUpper(mac), ":", ""), nil
}

func macAddress() (string, error) {
	if iface, err := net.InterfaceByName("en0"); err == nil && iface.HardwareAddr != nil {
		if s := iface.HardwareAddr.String(); s != "" {
			return s, nil
		}
	}

	ifs, err := net.Interfaces()
	if err != nil {
		return "", err
	}

	for _, ni := range ifs {
		if s := ni.HardwareAddr.String(); s != "" {
			return s, nil
		}
	}

	return "", errors.New("no network interface with a MAC address")
}
