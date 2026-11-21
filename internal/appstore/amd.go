package appstore

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"

	apphttp "github.com/londek/ipadecrypt/internal/apphttp"
	"github.com/londek/ipadecrypt/internal/storeauth"
)

// downloadClient decodes Store download responses: a redirect comes back as an
// empty result and a non-plist body as *apphttp.UnexpectedResponseError.
func (c *Client) downloadClient() apphttp.Client[downloadResult] {
	return apphttp.NewClient[downloadResult](apphttp.Args{CookieJar: c.jar, Executor: c.backend.Client("request")})
}

// sendCommerce posts a download request with the single-use Store AMD proof
// Apple requires on commerce endpoints. Requests are built with NoRedirects,
// so X-Token never reaches another host.
func (c *Client) sendCommerce(ctx context.Context, request apphttp.Request, g string) (apphttp.Result[downloadResult], error) {
	hardwareID, err := hex.DecodeString(g)
	if err != nil || len(hardwareID) != 6 {
		return apphttp.Result[downloadResult]{}, errors.New("store download requires a six-byte device GUID")
	}

	proof, err := c.storeAMDProof(ctx, request.URL, hardwareID)
	if err != nil {
		return apphttp.Result[downloadResult]{}, err
	}

	for key, value := range proof {
		request.Headers[key] = value
	}

	return c.downloadClient().Send(request)
}

// storeAMDProof derives single-use AMD headers from the persisted Anisette
// state (created by Login) and rotates that state. A missing or unreadable
// state maps to ErrPasswordTokenExpired so callers re-Login, which provisions
// it again.
func (c *Client) storeAMDProof(ctx context.Context, endpoint string, hardwareID []byte) (map[string]string, error) {
	if !isStoreAMDCommerceURL(endpoint) {
		return nil, errors.New("store AMD proof endpoint is not allowlisted")
	}

	return c.amdProof(ctx, endpoint, hardwareID)
}

// TestFlightAMDHeaders derives the same single-use AppleMediaServices proof
// TestFlight requests on its API calls. Only the exact TestFlight API origin
// may receive the proof.
func (c *Client) TestFlightAMDHeaders(ctx context.Context, endpoint string) (map[string]string, error) {
	if !isTestFlightAPIURL(endpoint) {
		return nil, errors.New("TestFlight AMD proof endpoint is not allowlisted")
	}

	mac, err := macAddress()
	if err != nil {
		return nil, err
	}

	_, hardwareID, err := machineIdentity(mac)
	if err != nil {
		return nil, err
	}

	return c.amdProof(ctx, endpoint, hardwareID)
}

func (c *Client) amdProof(ctx context.Context, endpoint string, hardwareID []byte) (map[string]string, error) {
	c.authMu.Lock()
	defer c.authMu.Unlock()

	c.loadAnisette()

	proof, state, err := storeauth.StoreAMDHeaders(ctx, c.anisetteState, endpoint, hardwareID)
	if errors.Is(err, storeauth.ErrNotProvisioned) || errors.Is(err, storeauth.ErrInvalidState) {
		return nil, fmt.Errorf("%w: generate Store AMD proof: %w", ErrPasswordTokenExpired, err)
	}

	if err != nil {
		return nil, fmt.Errorf("generate Store AMD proof: %w; run `ipadecrypt bootstrap` to sign in again", err)
	}

	if err := c.saveAnisette(state); err != nil {
		return nil, err
	}

	return proof, nil
}

func isTestFlightAPIURL(endpoint string) bool {
	if strings.Contains(endpoint, "#") {
		return false
	}

	parsed, err := url.ParseRequestURI(endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.User != nil || parsed.Fragment != "" ||
		parsed.RawPath != "" || parsed.Opaque != "" || parsed.RawQuery != "" || parsed.ForceQuery ||
		(parsed.Port() != "" && parsed.Port() != "443") || strings.ToLower(parsed.Hostname()) != "testflight.apple.com" {
		return false
	}

	parts := strings.Split(strings.TrimPrefix(parsed.Path, "/"), "/")
	if len(parts) < 2 || len(parts[0]) != 2 || parts[0][0] != 'v' || parts[0][1] < '1' || parts[0][1] > '9' {
		return false
	}

	return true
}

// isStoreAMDCommerceURL allowlists the exact download endpoints, each with a
// single guid query parameter, that may receive a device proof.
func isStoreAMDCommerceURL(endpoint string) bool {
	if strings.Contains(endpoint, "#") {
		return false
	}

	parsed, err := url.ParseRequestURI(endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.User != nil || parsed.Fragment != "" ||
		parsed.RawPath != "" || parsed.Opaque != "" || (parsed.Port() != "" && parsed.Port() != "443") {
		return false
	}

	query, err := url.ParseQuery(parsed.RawQuery)
	if err != nil || parsed.ForceQuery || len(query) != 1 {
		return false
	}

	if values, ok := query["guid"]; !ok || len(values) != 1 || values[0] == "" {
		return false
	}

	host := strings.ToLower(parsed.Hostname())
	if host == downloadDispatchDomain {
		switch parsed.Path {
		case entDownloadPath, redownloadProductPath, updateProductPath:
			return true
		}

		return false
	}

	return isStoreBuyHost(host) && parsed.Path == downloadPath
}

// isStoreBuyHost matches buy.itunes.apple.com and its pNN-buy pod hosts.
func isStoreBuyHost(host string) bool {
	if host == storeDomain {
		return true
	}

	pod := strings.TrimSuffix(host, "-"+storeDomain)
	if pod == host || len(pod) < 2 || pod[0] != 'p' {
		return false
	}

	for _, digit := range pod[1:] {
		if digit < '0' || digit > '9' {
			return false
		}
	}

	return true
}
