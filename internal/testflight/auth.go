package testflight

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/londek/ipadecrypt/internal/appstore"
)

// Authenticate creates a TestFlight session using the saved Apple credentials.
// The caller validates the session with a catalog request before persisting it.
func (c *Client) Authenticate(ctx context.Context, email, password string, verify func() (string, error)) (Session, error) {
	store, err := c.store.LoginTestFlightStore(ctx, email, password, c.dsid, verify)
	if err != nil {
		return Session{}, err
	}

	vendorID, err := newUUID()
	if err != nil {
		return Session{}, err
	}

	body, err := json.Marshal(map[string]any{
		"deviceModel": "Mac", "deviceName": "ipadecrypt", "dsId": json.Number(store.DSID),
		"deviceVendorId": strings.ToUpper(vendorID), "storeFrontIdentifier": strings.Split(store.Storefront, ",")[0],
		"storeCookies": store.Cookies,
	})
	if err != nil {
		return Session{}, errors.New("encode TestFlight authentication")
	}
	defer clear(body)

	endpoint := apiOrigin + "/v1/session/authenticate"

	proof, err := c.store.TestFlightAMDHeaders(ctx, endpoint)
	if err != nil {
		return Session{}, err
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return Session{}, err
	}

	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Accept-Language", "en-US")
	request.Header.Set("User-Agent", appstore.TestFlightStoreUserAgent)
	request.Header.Set("X-Apple-AMD-M", proof["X-Apple-AMD-M"])
	request.Header.Set("X-Apple-Store-Front", store.Storefront)
	request.Header.Set("X-Apple-Device-Model", "Mac")
	request.Header.Set("X-Apple-TA-Device", "Mac")
	request.Header.Set("X-Apple-TestFlight-iOS", "0")
	request.Header.Set("X-Apple-Rosetta-Available", "0")

	response, err := c.http.Do(request)
	if err != nil {
		return Session{}, fmt.Errorf("authenticate TestFlight: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return Session{}, fmt.Errorf("TestFlight authentication returned HTTP %d", response.StatusCode)
	}

	data, err := io.ReadAll(io.LimitReader(response.Body, maxResponse+1))
	if err != nil {
		return Session{}, fmt.Errorf("read TestFlight authentication: %w", err)
	}
	defer clear(data)

	if len(data) > maxResponse {
		return Session{}, errors.New("TestFlight authentication response exceeds size limit")
	}

	return decodeSession(data)
}

func decodeSession(data []byte) (Session, error) {
	var result struct {
		Data struct {
			SessionID string `json:"sessionId"`
			AccountID string `json:"accountId"`
		}
	}
	if err := decodeResponse(data, &result); err != nil {
		return Session{}, err
	}

	if !validSessionID(result.Data.SessionID) || !validSessionID(result.Data.AccountID) {
		return Session{}, errors.New("invalid TestFlight authentication session")
	}

	return Session{SessionID: result.Data.SessionID, AccountID: result.Data.AccountID}, nil
}

func validSessionID(value string) bool {
	if value == "" || len(value) > 4096 {
		return false
	}

	for i := 0; i < len(value); i++ {
		if value[i] < 0x21 || value[i] > 0x7e {
			return false
		}
	}

	return true
}
