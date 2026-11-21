package testflight

import (
	"bytes"
	"context"
	"crypto/sha1" //nolint:gosec // TestFlight's protocol requires SHA-1.
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/londek/ipadecrypt/internal/appstore"
)

const (
	apiOrigin   = "https://testflight.apple.com"
	maxResponse = 10 << 20
	// Virtual iPhone Duo profile, independent of the credential-minting device.
	testFlightDeviceModel = "iPhone19,4"
	testFlightUA          = "Oasis/4.4.1 iOS/27.2.1 model/" + testFlightDeviceModel
)

// Client constant appended to sessionID + requestID + DSID before SHA-1.
// Verified against TFAuthSessionInfo in TestFlightServices 4.4.1.
// Recheck it and the native-format test when updating the TestFlight client version.
const requestDigestSuffix = "LWzxL71nAUJTbK9X54DDQU5KC6oTcBFuibEJXIZglPRkhCSmh68PREebiNDZXctOKXpIcOfbnndI2FjMveKfRYOLPfYFRTgua1vg"

var ErrSessionExpired = errors.New("TestFlight session expired")

type Client struct {
	store      *appstore.Client
	http       *http.Client
	dsid       string
	storefront string
	session    Session
}

type Session struct {
	SessionID string
	AccountID string
}

func New(store *appstore.Client, account *appstore.Account, session Session) (*Client, error) {
	if store == nil || account == nil {
		return nil, errors.New("TestFlight requires an App Store client and account")
	}

	if dsid, err := strconv.ParseUint(account.DirectoryServicesID, 10, 64); err != nil || dsid == 0 {
		return nil, errors.New("TestFlight requires a numeric App Store account identifier")
	}

	if account.StoreFront == "" {
		return nil, errors.New("TestFlight requires an App Store storefront")
	}

	return &Client{
		store:      store,
		http:       newHTTPClient(),
		dsid:       account.DirectoryServicesID,
		storefront: account.StoreFront,
		session:    session,
	}, nil
}

func newHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func (c *Client) send(ctx context.Context, method, path string, payload any, output any) error {
	if c.session.SessionID == "" || c.session.AccountID == "" {
		return ErrSessionExpired
	}

	endpoint := apiOrigin + path

	requestID, err := newUUID()
	if err != nil {
		return err
	}

	var body []byte
	if payload != nil {
		body, err = json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("encode TestFlight request: %w", err)
		}
	}

	request, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create TestFlight request: %w", err)
	}

	request.Header.Set("Accept", "application/json")
	request.Header.Set("Accept-Language", "en")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("User-Agent", testFlightUA)
	request.Header.Set("X-Apple-Device-Model", testFlightDeviceModel)
	request.Header.Set("X-Apple-TA-Device", testFlightDeviceModel)
	request.Header.Set("X-Apple-Store-Front", c.storefront)
	request.Header.Set("X-Request-Id", requestID)
	request.Header.Set("X-Session-Id", c.session.SessionID)
	request.Header.Set("X-Session-Digest", sessionDigest(c.session.SessionID, requestID, c.dsid, requestDigestSuffix))

	proof, err := c.store.TestFlightAMDHeaders(ctx, endpoint)
	if err != nil {
		return fmt.Errorf("prepare TestFlight request: %w", err)
	}

	for name, value := range proof {
		request.Header.Set(name, value)
	}

	response, err := c.http.Do(request)
	if err != nil {
		return fmt.Errorf("send TestFlight request: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
		return ErrSessionExpired
	}

	data, err := io.ReadAll(io.LimitReader(response.Body, maxResponse+1))
	if err != nil {
		return fmt.Errorf("read TestFlight response: %w", err)
	}

	if len(data) > maxResponse {
		return errors.New("TestFlight response is unexpectedly large")
	}

	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return responseError(response.StatusCode, data)
	}

	return decodeResponse(data, output)
}

func decodeResponse(data []byte, output any) error {
	data = bytes.TrimSpace(data)
	if len(data) == 0 && output == nil {
		return nil
	}

	var envelope struct {
		Data     json.RawMessage `json:"data"`
		Error    json.RawMessage `json:"error"`
		Messages []struct {
			Type        string `json:"type"`
			MessageType string `json:"messageType"`
		} `json:"messages"`
	}
	if len(data) == 0 || data[0] != '{' || json.Unmarshal(data, &envelope) != nil {
		return errors.New("decode TestFlight response: invalid API envelope")
	}

	apiError := string(bytes.TrimSpace(envelope.Error))
	if apiError != "" && apiError != "null" && apiError != "false" {
		return errors.New("TestFlight reported an API error")
	}

	for _, message := range envelope.Messages {
		if strings.EqualFold(message.Type, "error") || strings.EqualFold(message.MessageType, "error") {
			return errors.New("TestFlight reported an API error")
		}
	}

	if output == nil {
		return nil
	}

	if len(envelope.Data) == 0 || bytes.Equal(bytes.TrimSpace(envelope.Data), []byte("null")) {
		return errors.New("TestFlight response is missing data")
	}

	if err := json.Unmarshal(data, output); err != nil {
		return fmt.Errorf("decode TestFlight response: %w", err)
	}

	return nil
}

func sessionDigest(sessionID, requestID, dsid, suffix string) string {
	digest := sha1.Sum([]byte(sessionID + requestID + dsid + suffix))
	return hex.EncodeToString(digest[:])
}

func responseError(status int, body []byte) error {
	var response struct {
		Messages []struct {
			Code string `json:"code"`
		} `json:"messages"`
	}

	_ = json.Unmarshal(body, &response)

	codes := make([]string, 0, len(response.Messages))
	for _, message := range response.Messages {
		code := strings.TrimSpace(message.Code)
		if code != "" && len(code) <= 128 && !strings.ContainsAny(code, "\r\n") {
			codes = append(codes, code)
		}
	}

	if len(codes) != 0 {
		return fmt.Errorf("TestFlight returned HTTP %d (%s)", status, strings.Join(codes, ", "))
	}

	return fmt.Errorf("TestFlight returned HTTP %d", status)
}

func newUUID() (string, error) {
	value, err := uuid.NewRandom()
	if err != nil {
		return "", fmt.Errorf("generate request identifier: %w", err)
	}

	return strings.ToUpper(value.String()), nil
}
