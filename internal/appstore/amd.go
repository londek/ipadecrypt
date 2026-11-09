package appstore

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	apphttp "github.com/londek/ipadecrypt/internal/apphttp"
	"github.com/londek/ipadecrypt/internal/storeauth"
)

// maxCommerceRedirects bounds the pod redirects one commerce request follows.
const maxCommerceRedirects = 4

// sendCommerce posts a download request with the Store AMD proof Apple now
// requires on commerce endpoints. The guest does not follow redirects, so
// X-Token never reaches another host; sendCommerce follows them itself, only to
// allowlisted commerce URLs and with a fresh single-use proof for each hop.
// Ported from ipatool v2.8.0 sendCommerceDownloadRequest.
func (c *Client) sendCommerce(endpoint, g string, headers map[string]string, payload map[string]any, out *downloadResult) (*http.Response, error) {
	hardwareID, err := hex.DecodeString(g)
	if err != nil || len(hardwareID) != 6 {
		return nil, errors.New("store download requires a six-byte device GUID")
	}

	headers["User-Agent"] = storeUserAgent

	for redirects := 0; ; redirects++ {
		proof, err := c.storeAMDProof(context.Background(), endpoint, hardwareID)
		if err != nil {
			return nil, err
		}

		for key, value := range proof {
			headers[key] = value
		}

		*out = downloadResult{}

		res, err := c.sendRequest("request", apphttp.Request{
			Method:      http.MethodPost,
			URL:         endpoint,
			Headers:     headers,
			Payload:     &apphttp.XMLPayload{Content: payload},
			NoRedirects: true,
		}, formatXML, out)
		if res == nil || res.StatusCode < http.StatusMultipleChoices || res.StatusCode >= http.StatusBadRequest {
			return res, err
		}

		location := res.Header.Get("Location")

		if !apphttp.IsAuthenticationRedirect(res.StatusCode) {
			return nil, fmt.Errorf("unsupported Store redirect (HTTP %d) to %s", res.StatusCode, redactURL(location))
		}

		if redirects == maxCommerceRedirects {
			return nil, fmt.Errorf("too many Store redirects (HTTP %d) to %s", res.StatusCode, redactURL(location))
		}

		next, err := resolveRedirect(endpoint, location)
		if err != nil || !isStoreAMDCommerceURL(next) {
			return nil, fmt.Errorf("refusing Store redirect (HTTP %d) to %s", res.StatusCode, redactURL(location))
		}

		debugf("commerce %s: HTTP %d redirect to %s", redactURL(endpoint), res.StatusCode, redactURL(next))

		endpoint = next
	}
}

// storeAMDProof derives single-use AMD headers from the persisted Anisette
// state (created by Login) and rotates that state. A missing or unreadable
// state maps to ErrPasswordTokenExpired so callers re-Login, which provisions
// it again.
func (c *Client) storeAMDProof(ctx context.Context, endpoint string, hardwareID []byte) (map[string]string, error) {
	if !isStoreAMDCommerceURL(endpoint) {
		return nil, errors.New("store AMD proof endpoint is not allowlisted")
	}

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

// resolveRedirect resolves a Location header, which may be relative, against
// the request URL.
func resolveRedirect(endpoint, location string) (string, error) {
	base, err := url.Parse(endpoint)
	if err != nil {
		return "", errors.New("invalid redirect base URL")
	}

	location = strings.TrimSpace(location)

	reference, err := url.Parse(location)
	if err != nil || location == "" {
		return "", errors.New("invalid redirect location")
	}

	return base.ResolveReference(reference).String(), nil
}

// redactURL keeps only scheme, host and path for diagnostics.
func redactURL(value string) string {
	parsed, err := url.Parse(value)
	if err != nil {
		return "invalid URL"
	}

	return (&url.URL{Scheme: parsed.Scheme, Host: parsed.Host, Path: parsed.Path}).String()
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
