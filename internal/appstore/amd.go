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

// sendCommerce posts a download request with the Store AMD proof Apple now
// requires on commerce endpoints. Redirects are not followed so X-Token never
// reaches another host. Ported from ipatool v2.8.0 sendCommerceDownloadRequest.
func (c *Client) sendCommerce(endpoint, g string, headers map[string]string, payload map[string]any, out *downloadResult) (*http.Response, error) {
	hardwareID, err := hex.DecodeString(g)
	if err != nil || len(hardwareID) != 6 {
		return nil, errors.New("store download requires a six-byte device GUID")
	}

	proof, err := c.storeAMDProof(context.Background(), endpoint, hardwareID)
	if err != nil {
		return nil, err
	}

	for key, value := range proof {
		headers[key] = value
	}

	headers["User-Agent"] = storeUserAgent

	return c.sendRequest("request", apphttp.Request{
		Method:      http.MethodPost,
		URL:         endpoint,
		Headers:     headers,
		Payload:     &apphttp.XMLPayload{Content: payload},
		NoRedirects: true,
	}, formatXML, out)
}

// storeAMDProof derives single-use AMD headers from the persisted Anisette
// state (created by Login) and rotates that state.
func (c *Client) storeAMDProof(ctx context.Context, endpoint string, hardwareID []byte) (map[string]string, error) {
	if !isStoreAMDCommerceURL(endpoint) {
		return nil, errors.New("store AMD proof endpoint is not allowlisted")
	}

	c.authMu.Lock()
	defer c.authMu.Unlock()

	c.loadAnisette()

	proof, state, err := storeauth.StoreAMDHeaders(ctx, c.anisetteState, endpoint, hardwareID)
	if err != nil {
		return nil, fmt.Errorf("generate Store AMD proof: %w; run `ipadecrypt bootstrap` to sign in again", err)
	}

	if err := c.saveAnisette(state); err != nil {
		return nil, err
	}

	return proof, nil
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
