package appstore

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	apphttp "github.com/londek/ipadecrypt/internal/apphttp"
	"github.com/londek/ipadecrypt/internal/storeauth"
)

const (
	// maxMachineActions bounds the RP/SP requests answered in one Login.
	maxMachineActions = 4

	// maxAuthenticationRedirects bounds the pod redirects of one request.
	maxAuthenticationRedirects = 4
)

type loginDialogAction struct {
	Kind string `plist:"kind,omitempty"`
	URL  string `plist:"url,omitempty"`
}

// loginDialog is the server dialog Apple returns instead of a token when the
// account needs attention (locked, new to the Store, pending terms...).
type loginDialog struct {
	Message            string            `plist:"message,omitempty"`
	Explanation        string            `plist:"explanation,omitempty"`
	OKButtonString     string            `plist:"okButtonString,omitempty"`
	OKButtonAction     loginDialogAction `plist:"okButtonAction,omitempty"`
	CancelButtonString string            `plist:"cancelButtonString,omitempty"`
}

type loginResult struct {
	FailureType         string      `plist:"failureType,omitempty"`
	CustomerMessage     string      `plist:"customerMessage,omitempty"`
	DirectoryServicesID string      `plist:"dsPersonId,omitempty"`
	PasswordToken       string      `plist:"passwordToken,omitempty"`
	Dialog              loginDialog `plist:"dialog,omitempty"`

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

// proofError is a failure to derive the Anisette headers themselves, as
// opposed to Apple rejecting the request.
type proofError struct{ err error }

func (e *proofError) Error() string { return e.err.Error() }

func (e *proofError) Unwrap() error { return e.err }

// loginProof returns the Anisette headers for one authenticate request.
type loginProof func(endpoint string) (http.Header, error)

// loginRequest is what every authenticate request of one Login shares.
type loginRequest struct {
	email, password, authCode, guid, endpoint string
	signer                                    ActionSigner
}

var storeCookieDSIDPattern = regexp.MustCompile(`(?:^|[ ,])mz_at(?:0|_ssl)-([0-9]+)=`)

// Login authenticates against the App Store and returns the account.
// Pass authCode when a prior call returned ErrAuthCodeRequired (2FA).
//
// Apple only accepts authenticate requests carrying Anisette (machine
// identity) headers. Login reuses the persisted Anisette state when it still
// yields a Store AMD proof, otherwise provisions this machine, answering
// Apple's reset ("RP") and Store provisioning ("SP") requests in whatever
// order they come. Ported from ipatool v2.8.0 nativeLogin.
func (c *Client) Login(email, password, authCode string) (*Account, error) {
	c.authMu.Lock()
	defer c.authMu.Unlock()

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

	signer, err := c.actionSignerFactory(config, hardwareID)
	if err != nil {
		return nil, fmt.Errorf("initialize SAP action signer: %w", err)
	}

	// Teardown frees the machine-signing session on every exit path.
	defer func() { _ = signer.Close() }()

	login := loginRequest{email: email, password: password, authCode: authCode, guid: g, endpoint: config.AuthEndpoint, signer: signer}
	storeProof := c.storeAMDLoginProof(ctx, hardwareID)

	// general holds this Login's general Anisette headers once provisioned;
	// nil means the request runs on the persisted state's Store AMD proof.
	var (
		general http.Header
		proof   loginProof
	)

	if len(c.anisetteState) != 0 {
		proof = storeProof
	}

	for actions := 0; ; actions++ {
		if proof == nil {
			general, err = c.provisionAnisette(ctx)
			if err != nil {
				return nil, err
			}

			proof = staticLoginProof(general)
		}

		acc, err := c.legacyLogin(login, proof)

		var (
			unusable *proofError
			action   *machineActionError
		)

		switch {
		case general == nil && errors.As(err, &unusable):
			// The persisted state no longer yields a proof: provision again.
			proof = nil
		case !errors.As(err, &action) || actions == maxMachineActions:
			return acc, err
		case general == nil:
			// Apple rejected the persisted state's proof (e.g. it predates Store
			// provisioning, or the hardware identity changed): provision again.
			proof = nil
		case action.action == "RP":
			headers := general.Clone()
			for _, key := range []string{"X-Apple-I-MD", "X-Apple-I-MD-M", "X-Apple-I-MD-RINFO"} {
				headers.Del(key)
			}

			proof = staticLoginProof(headers)
		case action.action == "SP":
			if err := c.provisionStore(ctx, action.data, hardwareID, g, general); err != nil {
				return nil, err
			}

			proof = storeProof
		default:
			return nil, err
		}
	}
}

// provisionAnisette runs general machine provisioning and returns its
// headers. An unreadable persisted state, e.g. one left by an interrupted
// write before saves were atomic, is replaced. Callers hold authMu.
func (c *Client) provisionAnisette(ctx context.Context) (http.Header, error) {
	headers, state, err := storeauth.AnisetteHeaders(ctx, c.authHTTP, c.anisetteState)
	if errors.Is(err, storeauth.ErrInvalidState) {
		headers, state, err = storeauth.AnisetteHeaders(ctx, c.authHTTP, nil)
	}

	if err != nil {
		return nil, fmt.Errorf("prepare Apple authentication: %w", err)
	}

	if err := c.saveAnisette(state); err != nil {
		return nil, err
	}

	return headers, nil
}

// provisionStore answers an "SP" machine action, provisioning the persisted
// state for Store AMD proofs. Callers hold authMu.
func (c *Client) provisionStore(ctx context.Context, data string, hardwareID []byte, g string, general http.Header) error {
	kbsync, err := c.generateKBSync(ctx, hardwareID, ^uint64(1), g)
	if err != nil {
		return fmt.Errorf("generate Apple Store provisioning kbsync: %w", err)
	}

	state, err := storeauth.ProvisionStoreAnisette(ctx, c.authHTTP, c.anisetteState, data, provisioningURL, storeUserAgent, kbsync, hardwareID, general)
	if err != nil {
		return fmt.Errorf("complete Apple Store provisioning: %w", err)
	}

	return c.saveAnisette(state)
}

// storeAMDLoginProof derives a fresh single-use Store AMD proof, bound to the
// request's endpoint, for every authenticate request. Callers hold authMu.
func (c *Client) storeAMDLoginProof(ctx context.Context, hardwareID []byte) loginProof {
	return func(endpoint string) (http.Header, error) {
		proof, state, err := storeauth.StoreAMDHeaders(ctx, c.anisetteState, endpoint, hardwareID)
		if err != nil {
			return nil, &proofError{fmt.Errorf("prepare Store AMD proof: %w", err)}
		}

		if err := c.saveAnisette(state); err != nil {
			return nil, err
		}

		return headerFromMap(proof), nil
	}
}

// staticLoginProof reuses general Anisette headers for every request; they
// carry a time-based OTP rather than a single-use proof.
func staticLoginProof(headers http.Header) loginProof {
	return func(string) (http.Header, error) {
		return headers, nil
	}
}

// legacyLogin runs the signed MZFinance authenticate exchange, following pod
// redirects and Apple's routine invalid-credentials retry, with the Anisette
// headers proof gives for each request.
func (c *Client) legacyLogin(login loginRequest, proof loginProof) (*Account, error) {
	endpoint := login.endpoint

	var (
		res *http.Response
		out loginResult
	)

	for attempt, redirects := 1, 0; ; {
		headers, err := proof(endpoint)
		if err != nil {
			return nil, err
		}

		out = loginResult{}

		// A pod redirect is part of the same authentication attempt: Apple
		// expects the original XML plist body, including its attempt value.
		res, err = c.sendRequest("authenticate", apphttp.Request{
			Method:       http.MethodPost,
			URL:          endpoint,
			Headers:      loginHeaders(headers),
			ActionSigner: login.signer,
			NoRedirects:  true,
			Payload: &apphttp.XMLPayload{Content: map[string]any{
				"appleId":  login.email,
				"attempt":  strconv.Itoa(attempt),
				"guid":     login.guid,
				"password": login.password + strings.ReplaceAll(login.authCode, " ", ""),
				"rmp":      "0",
				"why":      "signIn",
			}},
		}, formatXML, &out)

		// A machine action or redirect can arrive with a body that is not a
		// plist, so both are checked before the decode error.
		if res != nil {
			if action := authenticationMachineAction(res.Header); action != nil {
				return nil, action
			}

			if res.StatusCode >= http.StatusMultipleChoices && res.StatusCode < http.StatusBadRequest {
				if redirects == maxAuthenticationRedirects {
					return nil, fmt.Errorf("login: too many redirects (HTTP %d)", res.StatusCode)
				}

				if endpoint, err = authenticationRedirect(res, endpoint); err != nil {
					return nil, err
				}

				redirects++

				continue
			}
		}

		if err != nil {
			return nil, fmt.Errorf("login: %w", err)
		}

		retry, err := interpretLogin(res, &out, attempt, login.authCode)
		if err != nil {
			return nil, err
		}

		if !retry {
			break
		}

		attempt++
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
		accountEmail = login.email
	}

	addr := out.Account.Address

	return &Account{
		Email:               accountEmail,
		PasswordToken:       out.PasswordToken,
		DirectoryServicesID: dsid,
		StoreFront:          storeFront,
		Password:            login.password,
		Pod:                 res.Header.Get(hdrPod),
		Name:                strings.TrimSpace(addr.FirstName + " " + addr.LastName),
	}, nil
}

// loginHeaders builds the authenticate headers. Anisette's X-Apple-I-MD and
// X-Apple-I-MD-M are sent under the Store names X-Apple-AMD and X-Apple-AMD-M.
func loginHeaders(anisette http.Header) map[string]string {
	headers := map[string]string{
		"Content-Type": "application/x-apple-plist",
		"User-Agent":   storeUserAgent,
	}

	for key, values := range anisette {
		if strings.EqualFold(key, "X-Apple-I-MD") || strings.EqualFold(key, "X-Apple-I-MD-M") {
			continue
		}

		headers[key] = strings.Join(values, ", ")
	}

	if value := anisette.Get("X-Apple-I-MD"); value != "" {
		headers["X-Apple-AMD"] = value
	}

	if value := anisette.Get("X-Apple-I-MD-M"); value != "" {
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

// authenticationRedirect validates a 3xx authenticate response and returns its
// absolute destination. The redirect resends the POST body, so 303 (which
// turns it into a GET) is not followed.
func authenticationRedirect(res *http.Response, endpoint string) (string, error) {
	location := res.Header.Get("Location")

	if !apphttp.IsAuthenticationRedirect(res.StatusCode) {
		return "", fmt.Errorf("login: unsupported redirect (HTTP %d) to %s", res.StatusCode, redactURL(location))
	}

	next, err := resolveRedirect(endpoint, location)
	if err != nil {
		return "", fmt.Errorf("login: %w (HTTP %d)", err, res.StatusCode)
	}

	if err := validateAuthenticationEndpoint(next); err != nil {
		return "", fmt.Errorf("login: redirect (HTTP %d): %w", res.StatusCode, err)
	}

	return next, nil
}

// interpretLogin classifies a non-redirect authenticate response.
//   - retry=true: Apple answered the first attempt with invalid credentials,
//     which it does routinely; send the next attempt to the same URL.
//   - retry=false, err=nil: login succeeded.
//   - retry=false, err!=nil: login failed permanently.
func interpretLogin(res *http.Response, out *loginResult, attempt int, authCode string) (bool, error) {
	if attempt == 1 && out.FailureType == failureInvalidCredentials {
		return true, nil
	}

	if out.FailureType == "" && authCode == "" && out.CustomerMessage == custMsgBadLogin {
		return false, ErrAuthCodeRequired
	}

	// A dialog alongside a token is informational; only a tokenless one
	// explains why sign-in stopped.
	if out.PasswordToken == "" {
		if err := authenticationDialogError(out); err != nil {
			return false, err
		}
	}

	if out.FailureType == "" && out.CustomerMessage == custMsgAccountDisabled {
		return false, errors.New("account disabled")
	}

	if out.FailureType != "" {
		if out.CustomerMessage != "" {
			return false, errors.New(out.CustomerMessage)
		}

		return false, fmt.Errorf("login failed (failureType %s)", out.FailureType)
	}

	// The DSID may come from headers instead of the body; legacyLogin checks it.
	if res.StatusCode != http.StatusOK || out.PasswordToken == "" {
		return false, fmt.Errorf("login failed (HTTP %d)", res.StatusCode)
	}

	return false, nil
}

// authenticationDialogError turns a server dialog into an error in Apple's
// own words, with its action URL when that is a trusted Apple page.
// Ported from ipatool 8563232.
func authenticationDialogError(out *loginResult) error {
	dialog := out.Dialog
	if strings.TrimSpace(dialog.Message) == "" && strings.TrimSpace(dialog.Explanation) == "" &&
		strings.TrimSpace(dialog.OKButtonString) == "" && strings.TrimSpace(dialog.CancelButtonString) == "" &&
		strings.TrimSpace(dialog.OKButtonAction.Kind) == "" && strings.TrimSpace(dialog.OKButtonAction.URL) == "" {
		return nil
	}

	message := strings.TrimSpace(dialog.Message)
	explanation := strings.TrimSpace(dialog.Explanation)

	if message == "" {
		message = strings.TrimSpace(out.CustomerMessage)
	}

	actionURL := trustedDialogURL(dialog.OKButtonAction)
	if message == "" && explanation == "" && actionURL == "" {
		return nil
	}

	parts := make([]string, 0, 2)
	if message != "" {
		parts = append(parts, message)
	}

	if explanation != "" && explanation != message {
		parts = append(parts, explanation)
	}

	detail := strings.Join(parts, ": ")
	if detail == "" {
		detail = "Apple requires action before sign-in can continue"
	}

	if actionURL != "" {
		label := strings.TrimSpace(dialog.OKButtonString)
		if label == "" {
			label = "Continue"
		}

		detail += fmt.Sprintf(" (%s: %s)", label, actionURL)
	}

	return errors.New(detail)
}

// trustedDialogURL returns the dialog's OpenURL target only when it is a plain
// https apple.com page, so a dialog cannot point the user anywhere else.
func trustedDialogURL(action loginDialogAction) string {
	if !strings.EqualFold(strings.TrimSpace(action.Kind), "OpenURL") {
		return ""
	}

	value, err := url.Parse(strings.TrimSpace(action.URL))
	if err != nil || value.Scheme != "https" || value.User != nil || value.Fragment != "" || value.Port() != "" && value.Port() != "443" {
		return ""
	}

	host := strings.ToLower(value.Hostname())
	if host != "apple.com" && !strings.HasSuffix(host, ".apple.com") {
		return ""
	}

	return value.String()
}
