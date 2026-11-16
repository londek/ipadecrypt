package appstore

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode"

	apphttp "github.com/londek/ipadecrypt/internal/apphttp"
	"github.com/londek/ipadecrypt/internal/sap/assets"
	"github.com/londek/ipadecrypt/internal/sap/unicorn"
	"github.com/londek/ipadecrypt/internal/storeauth"
)

const (
	// maxAuthenticationRequestAttempts bounds the sends of one authenticate
	// request that fails transiently.
	maxAuthenticationRequestAttempts = 3

	// maxAuthenticationRedirects bounds the pod redirects of one request.
	maxAuthenticationRedirects = 4

	// authenticationRetryDelay is the first retry backoff; it doubles per
	// retry up to maxAuthenticationRetryDelay.
	authenticationRetryDelay    = 10 * time.Second
	maxAuthenticationRetryDelay = 30 * time.Second
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

var storeCookieDSIDPattern = regexp.MustCompile(`(?:^|[ ,])mz_at(?:0|_ssl)-([0-9]+)=`)

// Login authenticates against the App Store and returns the account.
// Pass authCode when a prior call returned ErrAuthCodeRequired (2FA).
//
// Apple only accepts authenticate requests carrying Anisette (machine
// identity) headers. Login signs in with a Store AMD proof from the persisted
// Anisette state when it yields one; otherwise it provisions this machine and
// answers Apple's reset ("RP") and then Store provisioning ("SP") requests.
//
// If onStage is non-nil it is called with a short description each time Login
// moves to another step, so callers can show what a slow sign-in is doing.
func (c *Client) Login(email, password, authCode string, onStage func(stage string)) (*Account, error) {
	stage := func(s string) {
		if onStage != nil {
			onStage(s)
		}
	}

	c.authMu.Lock()
	defer c.authMu.Unlock()

	c.loadAnisette()

	ctx := context.Background()

	stage("preparing the emulator (slow on first run)")

	if err := prepareEmulator(ctx); err != nil {
		return nil, err
	}

	mac, err := macAddress()
	if err != nil {
		return nil, err
	}

	_, hardwareID, err := machineIdentity(mac)
	if err != nil {
		return nil, err
	}

	config, err := c.bag()
	if err != nil {
		return nil, fmt.Errorf("get Store authentication bag: %w", err)
	}

	var action *machineActionError

	if len(c.anisetteState) != 0 {
		proof, state, proofErr := storeauth.StoreAMDHeaders(ctx, c.anisetteState, config.AuthEndpoint, hardwareID)
		if proofErr == nil {
			if err := c.saveAnisette(state); err != nil {
				return nil, err
			}

			// A machine action here means Apple rejected the persisted state
			// (e.g. it predates Store provisioning, or the hardware identity
			// changed), so this machine is provisioned again.
			stage("signing in")

			acc, err := c.legacyLogin(email, password, authCode, headerFromMap(proof))
			if !errors.As(err, &action) {
				return acc, err
			}
		}
	}

	stage("registering this Mac with Apple")

	general, err := c.provisionAnisette(ctx)
	if err != nil {
		return nil, err
	}

	headers := general.Clone()

	stage("signing in")

	acc, err := c.legacyLogin(email, password, authCode, headers)
	if !errors.As(err, &action) || action.action != "RP" {
		return acc, err
	}

	for _, key := range []string{"X-Apple-I-MD", "X-Apple-I-MD-M", "X-Apple-I-MD-RINFO"} {
		headers.Del(key)
	}

	acc, err = c.legacyLogin(email, password, authCode, headers)
	if !errors.As(err, &action) || action.action != "SP" {
		return acc, err
	}

	stage("completing App Store registration")

	kbsync, err := c.generateKBSync(ctx, hardwareID, ^uint64(1))
	if err != nil {
		return nil, fmt.Errorf("generate Apple Store provisioning kbsync: %w", err)
	}

	state, err := storeauth.ProvisionStoreAnisette(ctx, c.authHTTP, c.anisetteState, action.data, provisioningURL, storeUserAgent, kbsync, hardwareID, general)
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

	stage("signing in")

	return c.legacyLogin(email, password, authCode, headerFromMap(proof))
}

// prepareEmulator loads the Apple frameworks and the Unicorn runtime before
// they are first needed. Both are downloaded and cached on the first run, so
// doing it up front lets Login report that slow step on its own.
func prepareEmulator(ctx context.Context) error {
	if _, err := assets.Load(ctx); err != nil {
		return fmt.Errorf("prepare emulator: %w", err)
	}

	engine, err := unicorn.New(ctx)
	if err != nil {
		return fmt.Errorf("prepare emulator: %w", err)
	}

	return engine.Close()
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

// legacyLogin signs in with the given Anisette headers, establishing a fresh
// SAP signing session from the current bag and closing it afterwards.
func (c *Client) legacyLogin(email, password, authCode string, anisette http.Header) (*Account, error) {
	authCode, err := normalizeAuthCode(authCode)
	if err != nil {
		return nil, err
	}

	if countryCode := phoneNumberStorefrontCountryCode(email); countryCode != "" {
		if _, err := c.discoverStorefrontID(countryCode); err != nil {
			return nil, fmt.Errorf("discover storefronts: %w", err)
		}
	}

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

	acc, loginErr := c.login(email, password, authCode, g, config.AuthEndpoint, signer, anisette)

	closeErr := signer.Close()
	if closeErr != nil {
		closeErr = fmt.Errorf("close SAP action signer: %w", closeErr)
	}

	if loginErr != nil {
		if closeErr != nil {
			return nil, errors.Join(loginErr, closeErr)
		}

		return nil, loginErr
	}

	return acc, closeErr
}

// normalizeAuthCode strips a bracketed-paste wrapper and whitespace from a
// 2FA code.
func normalizeAuthCode(code string) (string, error) {
	if code == "" {
		return "", nil
	}

	// Terminals may wrap pasted input in bracketed-paste markers. Strip only
	// a matched outer pair; other escape sequences are invalid input.
	code = strings.TrimSpace(code)
	if strings.HasPrefix(code, "\x1b[200~") && strings.HasSuffix(code, "\x1b[201~") {
		code = strings.TrimSuffix(strings.TrimPrefix(code, "\x1b[200~"), "\x1b[201~")
	}

	code = strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}

		return r
	}, code)

	if len(code) != 6 || strings.IndexFunc(code, func(r rune) bool { return r < '0' || r > '9' }) != -1 {
		return "", errors.New("2FA code must contain exactly six digits")
	}

	return code, nil
}

// login runs the signed MZFinance authenticate exchange, following pod
// redirects and Apple's routine invalid-credentials retry.
func (c *Client) login(email, password, authCode, g, endpoint string, signer ActionSigner, anisette http.Header) (*Account, error) {
	request := c.loginRequest(email, password, authCode, g, endpoint, 1, signer, anisette)
	redirects := 0

	var (
		err error
		res apphttp.Result[loginResult]
	)

	for attempt := 1; ; {
		res, err = c.sendAuthenticationRequest(request)
		if err != nil {
			return nil, fmt.Errorf("login: %w", err)
		}

		retry, redirect, err := parseLoginResponse(&res, attempt, authCode, request.URL)
		if err != nil {
			return nil, err
		}

		if !retry {
			break
		}

		if redirect != "" {
			if redirects == maxAuthenticationRedirects {
				return nil, authenticationRedirectError(errors.New("too many redirects"), res.StatusCode, redirect)
			}

			redirects++
			// Only the destination changes: redirects belong to the same login
			// attempt and must retain its payload, including the attempt value.
			request.URL = redirect

			continue
		}

		attempt++
		request = c.loginRequest(email, password, authCode, g, request.URL, attempt, signer, anisette)
	}

	storeFront, err := res.GetHeader(hdrStoreFront)
	if errors.Is(err, apphttp.ErrHeaderNotFound) {
		storeFront, err = res.GetHeader(hdrRequestStoreFront)
	}

	if err != nil {
		return nil, fmt.Errorf("login: storefront header: %w", err)
	}

	pod, _ := res.GetHeader(hdrPod)

	dsid := res.Data.DirectoryServicesID
	if dsid == "" {
		dsid = authenticationResponseDSID(headerFromMap(res.Headers))
	}

	if dsid == "" {
		return nil, errors.New("login: apple returned no directory services identifier")
	}

	accountEmail := res.Data.Account.Email
	if accountEmail == "" {
		accountEmail = email
	}

	addr := res.Data.Account.Address

	return &Account{
		Email:               accountEmail,
		PasswordToken:       res.Data.PasswordToken,
		DirectoryServicesID: dsid,
		StoreFront:          storeFront,
		Password:            password,
		Pod:                 pod,
		Name:                strings.TrimSpace(addr.FirstName + " " + addr.LastName),
	}, nil
}

// sendAuthenticationRequest sends an authenticate request, retrying transient
// failures with backoff.
func (c *Client) sendAuthenticationRequest(request apphttp.Request) (apphttp.Result[loginResult], error) {
	client := apphttp.NewClient[loginResult](apphttp.Args{CookieJar: c.jar, Authentication: true, Executor: c.backend.Client("authenticate")})
	statuses := make([]string, 0, maxAuthenticationRequestAttempts)
	onlyHTTP := true

	for attempt := 1; ; attempt++ {
		result, err := client.Send(request)

		status, retry := retryableAuthenticationError(err)
		if !retry {
			if err != nil {
				return result, authenticationRequestError(err)
			}

			return result, nil
		}

		outcome := fmt.Sprintf("HTTP %d", status)
		if status == 0 {
			outcome = "transport error"
			onlyHTTP = false
		}

		statuses = append(statuses, outcome)

		if attempt == maxAuthenticationRequestAttempts {
			summary := strings.Join(statuses, ", ")
			if onlyHTTP {
				// Preserve the existing diagnostic format for HTTP-only failures.
				summary = strings.ReplaceAll(summary, ", HTTP ", ", ")
			}

			return result, fmt.Errorf(
				"authentication request failed after %d attempts (%s): %w",
				maxAuthenticationRequestAttempts, summary, authenticationRequestError(err),
			)
		}

		delay := min(authenticationRetryDelay<<(attempt-1), maxAuthenticationRetryDelay)

		var (
			responseErr  *apphttp.UnexpectedResponseError
			transportErr *apphttp.TransportError
			retryAfter   string
		)

		if errors.As(err, &responseErr) {
			retryAfter = responseErr.RetryAfter
		} else if errors.As(err, &transportErr) {
			retryAfter = transportErr.RetryAfter
		}

		if requested, ok := authenticationRetryAfter(retryAfter, time.Now()); ok {
			if requested > maxAuthenticationRetryDelay {
				return result, fmt.Errorf("apple requested a wait longer than %s: %w", maxAuthenticationRetryDelay, err)
			}

			// Retry-After takes precedence over the fallback backoff.
			delay = max(requested, time.Second)
		}

		time.Sleep(delay)
	}
}

func retryableAuthenticationError(err error) (int, bool) {
	var responseErr *apphttp.UnexpectedResponseError

	if !errors.As(err, &responseErr) {
		var transportErr *apphttp.TransportError

		if !errors.As(err, &transportErr) || errors.Is(err, context.Canceled) {
			return 0, false
		}

		// A url.Error can report Timeout false when its cause is wrapped by
		// the framework transport, so inspect each underlying error as well.
		for cause := transportErr.Err; cause != nil; cause = errors.Unwrap(cause) {
			if networkErr, ok := cause.(net.Error); ok && networkErr.Timeout() {
				return 0, true
			}
		}

		return 0, errors.Is(transportErr, io.EOF) || errors.Is(transportErr, io.ErrUnexpectedEOF) ||
			errors.Is(transportErr, syscall.ECONNRESET) || errors.Is(transportErr, syscall.EPIPE)
	}

	status := responseErr.StatusCode
	// A Store pod can transiently return an HTML 403 page. Populated Apple
	// credential errors are decoded normally and never reach this branch.
	retry := status == http.StatusNoContent ||
		status == http.StatusForbidden ||
		status == http.StatusNotFound ||
		status == http.StatusTooManyRequests ||
		status/100 == 5

	return status, retry
}

func authenticationRequestError(err error) error {
	var responseErr *apphttp.UnexpectedResponseError

	if errors.As(err, &responseErr) && responseErr.StatusCode == http.StatusTooManyRequests {
		return fmt.Errorf("rate limited by Apple: %w", err)
	}

	return err
}

func authenticationRetryAfter(value string, now time.Time) (time.Duration, bool) {
	value = strings.TrimSpace(value)
	if seconds, err := strconv.ParseUint(value, 10, 64); err == nil {
		// Saturate before converting to Duration to avoid overflow. A wait over
		// the budget ends this login rather than retrying before Apple's deadline.
		if seconds > uint64(maxAuthenticationRetryDelay/time.Second) {
			return maxAuthenticationRetryDelay + time.Second, true
		}

		return time.Duration(seconds) * time.Second, true
	}

	if date, err := http.ParseTime(value); err == nil {
		return max(time.Duration(0), date.Sub(now)), true
	}

	return 0, false
}

// loginRequest builds one authenticate request. Phone-number Apple Accounts
// in mainland China and India get a storefront routing hint.
func (c *Client) loginRequest(email, password, authCode, g, endpoint string, attempt int, signer ActionSigner, anisette http.Header) apphttp.Request {
	request := apphttp.Request{
		Method:         http.MethodPost,
		URL:            endpoint,
		ResponseFormat: apphttp.ResponseFormatXML,
		ActionSigner:   signer,
		NoRedirects:    true,
		Headers:        loginHeaders(anisette),
		Payload: &apphttp.XMLPayload{Content: map[string]any{
			"appleId":  email,
			"attempt":  strconv.Itoa(attempt),
			"guid":     g,
			"password": password + strings.ReplaceAll(authCode, " ", ""),
			"rmp":      "0",
			"why":      "signIn",
		}},
	}

	if storefront := c.storefrontID(phoneNumberStorefrontCountryCode(email)); storefront != "" {
		request.Headers["X-Apple-Store-Front"] = storefront
	}

	return request
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
	if _, ok := header["X-Dsid"]; ok {
		return strings.TrimSpace(header.Get("X-Dsid"))
	}

	for _, cookie := range header.Values("Set-Cookie") {
		if match := storeCookieDSIDPattern.FindStringSubmatch(cookie); len(match) == 2 {
			return match[1]
		}
	}

	return ""
}

// resolveAuthenticationRedirect returns the validated absolute destination of
// a redirect Location.
func resolveAuthenticationRedirect(endpoint, location string) (string, error) {
	base, err := url.Parse(endpoint)
	if err != nil {
		return "", errors.New("invalid redirect base URL")
	}

	reference, err := url.Parse(strings.TrimSpace(location))
	if err != nil || strings.TrimSpace(location) == "" {
		return "", errors.New("invalid redirect location")
	}

	destination := base.ResolveReference(reference).String()
	if err := validateAuthenticationEndpoint(destination); err != nil {
		return "", fmt.Errorf("redirect: %w", err)
	}

	return destination, nil
}

// authenticationRedirectError adds the HTTP status to a redirect failure. The
// destination is logged instead of returned, without URL credentials, query
// parameters or fragments.
func authenticationRedirectError(err error, status int, location string) error {
	destination := "invalid URL"
	if parsed, parseErr := url.Parse(location); parseErr == nil {
		destination = (&url.URL{Scheme: parsed.Scheme, Host: parsed.Host, Path: parsed.Path}).String()
	}

	debugf("authentication redirect (HTTP %d) to %s", status, destination)

	return fmt.Errorf("login: %w (HTTP %d)", err, status)
}

// parseLoginResponse classifies an authenticate response: retry is set for a
// pod redirect (with its destination) and for Apple's routine
// invalid-credentials answer to the first attempt.
func parseLoginResponse(res *apphttp.Result[loginResult], attempt int, authCode, endpoint string) (bool, string, error) {
	var (
		retry    bool
		redirect string
		err      error
	)

	if action := authenticationMachineAction(headerFromMap(res.Headers)); action != nil {
		err = action
	} else if dialogErr := authenticationDialogError(&res.Data); dialogErr != nil {
		err = dialogErr
	} else if res.StatusCode >= http.StatusMultipleChoices && res.StatusCode < http.StatusBadRequest {
		if redirect, err = res.GetHeader("location"); err != nil {
			err = errors.New("invalid redirect location")
		} else if !apphttp.IsAuthenticationRedirect(res.StatusCode) {
			err = errors.New("unsupported redirect")
		} else {
			redirect, err = resolveAuthenticationRedirect(endpoint, redirect)
		}

		if err != nil {
			location, _ := res.GetHeader("location")

			return false, "", authenticationRedirectError(err, res.StatusCode, location)
		}

		retry = true
	} else if attempt == 1 && res.Data.FailureType == failureInvalidCredentials {
		retry = true
	} else if res.Data.FailureType == "" && res.Data.CustomerMessage == custMsgBadLogin {
		if authCode == "" {
			err = ErrAuthCodeRequired
		} else {
			err = errors.New("auth code rejected")
		}
	} else if res.Data.FailureType == "" && res.Data.CustomerMessage == custMsgAccountDisabled {
		err = errors.New("account disabled")
	} else if res.Data.FailureType != "" {
		if res.Data.CustomerMessage != "" {
			err = errors.New(res.Data.CustomerMessage)
		} else {
			err = fmt.Errorf("login failed (failureType %s)", res.Data.FailureType)
		}
	} else if res.StatusCode != http.StatusOK || res.Data.PasswordToken == "" {
		err = fmt.Errorf("login failed (HTTP %d)", res.StatusCode)
	}

	return retry, redirect, err
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
