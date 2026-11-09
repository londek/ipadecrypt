package appstore

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	apphttp "github.com/londek/ipadecrypt/internal/apphttp"
	"github.com/londek/ipadecrypt/internal/storeauth"
)

type loginResult struct {
	FailureType         string `plist:"failureType,omitempty"`
	CustomerMessage     string `plist:"customerMessage,omitempty"`
	DirectoryServicesID string `plist:"dsPersonId,omitempty"`
	PasswordToken       string `plist:"passwordToken,omitempty"`

	Account struct {
		Email   string `plist:"appleId,omitempty"`
		Address struct {
			FirstName string `plist:"firstName,omitempty"`
			LastName  string `plist:"lastName,omitempty"`
		} `plist:"address,omitempty"`
	} `plist:"accountInfo,omitempty"`
}

// machineActionError is Apple asking the client to act on its machine
// identity before authenticating: "RP" resets it, "SP" provisions it.
type machineActionError struct {
	action string
	data   string
}

func (e *machineActionError) Error() string {
	return "apple requested an authentication machine action: " + e.action
}

var storeCookieDSIDPattern = regexp.MustCompile(`(?:^|[ ,])mz_at(?:0|_ssl)-([0-9]+)=`)

// Login authenticates against the App Store and returns the account.
// Pass authCode when a prior call returned ErrAuthCodeRequired (2FA).
//
// Apple only accepts authenticate requests carrying Anisette (machine
// identity) headers. Login reuses the persisted Anisette state when it can,
// otherwise provisions this machine, answering Apple's reset ("RP") and Store
// provisioning ("SP") requests. Ported from ipatool v2.8.0 nativeLogin.
func (c *Client) Login(email, password, authCode string) (*Account, error) {
	c.authMu.Lock()
	defer c.authMu.Unlock()
	defer func() { c.authHeaders = nil }()

	c.loadAnisette()

	ctx := context.Background()

	mac, err := macAddress()
	if err != nil {
		return nil, err
	}

	g, hardwareID, err := machineIdentity(mac)
	if err != nil {
		return nil, err
	}

	config, err := c.bag()
	if err != nil {
		return nil, fmt.Errorf("get Store authentication bag: %w", err)
	}

	if len(c.anisetteState) != 0 {
		proof, state, proofErr := storeauth.StoreAMDHeaders(ctx, c.anisetteState, config.AuthEndpoint, hardwareID)
		if proofErr == nil {
			if err := c.saveAnisette(state); err != nil {
				return nil, err
			}

			c.authHeaders = headerFromMap(proof)

			return c.legacyLogin(email, password, authCode)
		}
	}

	headers, state, err := storeauth.AnisetteHeaders(ctx, c.authHTTP, c.anisetteState)
	if err != nil {
		return nil, fmt.Errorf("prepare Apple authentication: %w", err)
	}

	if err := c.saveAnisette(state); err != nil {
		return nil, err
	}

	c.authHeaders = headers.Clone()

	acc, err := c.legacyLogin(email, password, authCode)

	var action *machineActionError
	if !errors.As(err, &action) || action.action != "RP" {
		return acc, err
	}

	for _, key := range []string{"X-Apple-I-MD", "X-Apple-I-MD-M", "X-Apple-I-MD-RINFO"} {
		c.authHeaders.Del(key)
	}

	acc, err = c.legacyLogin(email, password, authCode)
	if !errors.As(err, &action) || action.action != "SP" {
		return acc, err
	}

	kbsync, err := c.generateKBSync(ctx, hardwareID, ^uint64(1), g)
	if err != nil {
		return nil, fmt.Errorf("generate Apple Store provisioning kbsync: %w", err)
	}

	state, err = storeauth.ProvisionStoreAnisette(ctx, c.authHTTP, state, action.data, provisioningURL, storeUserAgent, kbsync, hardwareID, headers)
	if err != nil {
		return nil, fmt.Errorf("complete Apple Store provisioning: %w", err)
	}

	if err := c.saveAnisette(state); err != nil {
		return nil, err
	}

	proof, state, err := storeauth.StoreAMDHeaders(ctx, state, config.AuthEndpoint, hardwareID)
	if err != nil {
		return nil, fmt.Errorf("prepare Store AMD proof: %w", err)
	}

	if err := c.saveAnisette(state); err != nil {
		return nil, err
	}

	c.authHeaders = headerFromMap(proof)

	return c.legacyLogin(email, password, authCode)
}

// legacyLogin runs the signed MZFinance authenticate exchange, sending the
// Anisette headers Login prepared in c.authHeaders.
//
// It fetches the bag to obtain the current SAP signing config, establishes a
// machine-signing session, and signs the authenticate request body with it.
func (c *Client) legacyLogin(email, password, authCode string) (*Account, error) {
	mac, err := macAddress()
	if err != nil {
		return nil, err
	}

	guid, machineID, err := machineIdentity(mac)
	if err != nil {
		return nil, err
	}

	config, err := c.bag()
	if err != nil {
		return nil, err
	}

	signer, err := c.actionSignerFactory(config, machineID)
	if err != nil {
		return nil, fmt.Errorf("initialize SAP action signer: %w", err)
	}

	// Teardown frees the machine-signing session on every exit path.
	defer func() { _ = signer.Close() }()

	url := config.AuthEndpoint

	var (
		res *http.Response
		out loginResult
	)

	redirect := false

	for attempt := 1; attempt <= 4; attempt++ {
		// The pod redirect is part of the same authentication attempt: Apple
		// expects the original XML plist body, including its attempt value.
		requestAttempt := attempt
		if redirect {
			requestAttempt = 1
		}

		out = loginResult{}

		res, err = c.sendRequest("authenticate", apphttp.Request{
			Method:       http.MethodPost,
			URL:          url,
			Headers:      c.loginHeaders(),
			ActionSigner: signer,
			NoRedirects:  true,
			Payload: &apphttp.XMLPayload{Content: map[string]any{
				"appleId":  email,
				"attempt":  strconv.Itoa(requestAttempt),
				"guid":     guid,
				"password": password + strings.ReplaceAll(authCode, " ", ""),
				"rmp":      "0",
				"why":      "signIn",
			}},
		}, formatXML, &out)

		// A machine action can arrive with a body that is not a plist, so it
		// is checked before the decode error.
		if res != nil {
			if action := authenticationMachineAction(res.Header); action != nil {
				return nil, action
			}
		}

		if err != nil {
			return nil, fmt.Errorf("login: %w", err)
		}

		next, retry, err := interpretLogin(res, &out, attempt, authCode)
		if err != nil {
			return nil, err
		}

		if !retry {
			break
		}

		url = next
		redirect = true
	}

	if out.PasswordToken == "" {
		return nil, errors.New("login: no token after retries")
	}

	dsid := out.DirectoryServicesID
	if dsid == "" {
		dsid = authenticationResponseDSID(res.Header)
	}

	if dsid == "" {
		return nil, errors.New("login: apple returned no directory services identifier")
	}

	storeFront := res.Header.Get(hdrStoreFront)
	if storeFront == "" {
		storeFront = res.Header.Get(hdrRequestStoreFront)
	}

	accountEmail := out.Account.Email
	if accountEmail == "" {
		accountEmail = email
	}

	addr := out.Account.Address

	return &Account{
		Email:               accountEmail,
		PasswordToken:       out.PasswordToken,
		DirectoryServicesID: dsid,
		StoreFront:          storeFront,
		Password:            password,
		Pod:                 res.Header.Get(hdrPod),
		Name:                strings.TrimSpace(addr.FirstName + " " + addr.LastName),
	}, nil
}

// loginHeaders builds the authenticate headers. Anisette's X-Apple-I-MD and
// X-Apple-I-MD-M are sent under the Store names X-Apple-AMD and X-Apple-AMD-M.
func (c *Client) loginHeaders() map[string]string {
	headers := map[string]string{
		"Content-Type": "application/x-apple-plist",
		"User-Agent":   storeUserAgent,
	}

	for key, values := range c.authHeaders {
		if strings.EqualFold(key, "X-Apple-I-MD") || strings.EqualFold(key, "X-Apple-I-MD-M") {
			continue
		}

		headers[key] = strings.Join(values, ", ")
	}

	if value := c.authHeaders.Get("X-Apple-I-MD"); value != "" {
		headers["X-Apple-AMD"] = value
	}

	if value := c.authHeaders.Get("X-Apple-I-MD-M"); value != "" {
		headers["X-Apple-AMD-M"] = value
	}

	return headers
}

func headerFromMap(values map[string]string) http.Header {
	header := make(http.Header, len(values))
	for key, value := range values {
		header.Set(key, value)
	}

	return header
}

func authenticationMachineAction(header http.Header) *machineActionError {
	action := strings.TrimSpace(header.Get("X-Apple-AMD-Action"))
	if action == "" {
		return nil
	}

	return &machineActionError{action: action, data: strings.TrimSpace(header.Get("X-Apple-AMD-Data"))}
}

// authenticationResponseDSID recovers the account DSID when the authenticate
// body omits dsPersonId: from X-Dsid, else from the mz_at session cookie name.
func authenticationResponseDSID(header http.Header) string {
	if dsid := strings.TrimSpace(header.Get("X-Dsid")); dsid != "" {
		return dsid
	}

	for _, cookie := range header.Values("Set-Cookie") {
		if match := storeCookieDSIDPattern.FindStringSubmatch(cookie); len(match) == 2 {
			return match[1]
		}
	}

	return ""
}

// interpretLogin classifies an authenticate response.
// Returns (nextURL, retry, err):
//   - retry=true with nextURL set: follow the 302 redirect to a store pod.
//   - retry=true with empty nextURL: server said "try again" (invalid-cred on attempt 1).
//   - retry=false, err=nil: login succeeded.
//   - retry=false, err!=nil: login failed permanently.
func interpretLogin(res *http.Response, out *loginResult, attempt int, authCode string) (string, bool, error) {
	if res.StatusCode == http.StatusFound {
		loc := res.Header.Get("Location")
		if loc == "" {
			return "", false, errors.New("login: redirect without Location")
		}

		if err := validateAuthenticationEndpoint(loc); err != nil {
			return "", false, err
		}

		return loc, true, nil
	}

	if attempt == 1 && out.FailureType == failureInvalidCredentials {
		return "", true, nil
	}

	if out.FailureType == "" && authCode == "" && out.CustomerMessage == custMsgBadLogin {
		return "", false, ErrAuthCodeRequired
	}

	if out.FailureType == "" && out.CustomerMessage == custMsgAccountDisabled {
		return "", false, errors.New("account disabled")
	}

	if out.FailureType != "" {
		if out.CustomerMessage != "" {
			return "", false, errors.New(out.CustomerMessage)
		}

		return "", false, fmt.Errorf("login failed (failureType %s)", out.FailureType)
	}

	// The DSID may come from headers instead of the body; legacyLogin checks it.
	if res.StatusCode != http.StatusOK || out.PasswordToken == "" {
		return "", false, fmt.Errorf("login failed (HTTP %d)", res.StatusCode)
	}

	return "", false, nil
}
