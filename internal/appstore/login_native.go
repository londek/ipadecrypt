package appstore

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	apphttp "github.com/londek/ipadecrypt/internal/apphttp"
	"github.com/londek/ipadecrypt/internal/storeauth"
	"howett.net/plist"
)

// nativeAuthEndpoint is the modern App Store sign-in endpoint. The flow is:
// GrandSlam SRP (email+password -> PET) then this endpoint with the PET as the
// password, signed by the iPhone Mescal session and carrying GSA anisette. Ported from the reference
// implementation in blacktop/ipsw (https://github.com/blacktop/ipsw, MIT).
// nativeAuthEndpoint is the exact path a captured device request uses
// (auth/v1/native, no trailing /fast). The bag advertises /auth/v1/native/fast
// (PrivateAuthPathNative) but the live POST is to /auth/v1/native.
const nativeAuthEndpoint = "https://auth.itunes.apple.com/auth/v1/native"
const nativeUserAgent = "com.apple.accountsd/1.0 iOS/26.0 model/iPhone12,1 hwp/t8030 build/23A341 (6; dt:203) AMS/1"

const maxNativeAuthBody = 1 << 20

// NativeMachineActionError keeps Store state actions distinct from GSA/password
// failures. Challenge data and authentication tokens are never included.
type NativeMachineActionError struct {
	Action                  string
	AMDPresent              bool
	ProvisioningDataPresent bool
}

func (e *NativeMachineActionError) Error() string {
	return fmt.Sprintf("native Store requested AMD action %s (AMD proof sent=%t, provisioning data supplied=%t); Store sign-in is not complete", e.Action, e.AMDPresent, e.ProvisioningDataPresent)
}

func nativeMachineAction(headers http.Header, message string) string {
	action := strings.TrimSpace(headers.Get("X-Apple-AMD-Action"))
	if action == "" && strings.HasPrefix(message, "AMD-Action::") {
		action = strings.TrimPrefix(message, "AMD-Action::")
	}

	switch action {
	case "SP", "RP", "SM":
		return action
	}

	return ""
}

// nativeAuthRequest is the modern native authenticate body (XML plist). Field
// set confirmed against a captured device request.
type nativeAuthRequest struct {
	AccountKind            int    `plist:"accountKind"`
	AppleID                string `plist:"appleId"`
	CreateSession          bool   `plist:"createSession"`
	CredentialSource       int    `plist:"credentialSource"`
	GUID                   string `plist:"guid"`
	IsSilentAuthentication bool   `plist:"isSilentAuthentication"`
	Password               string `plist:"password"`
	PasswordSettings       struct {
		Free string `plist:"free"`
		Paid string `plist:"paid"`
	} `plist:"passwordSettings"`
	RMP string `plist:"rmp"`
}

// SignIn authenticates using the modern native flow (GrandSlam + auth/v1/native)
// when offline anisette is configured, otherwise the legacy MZFinance
// authenticate. The offline-anisette provider is exactly what the native path
// needs, so its presence selects the path.
func (c *Client) SignIn(email, password, authCode string) (*Account, error) {
	if c.anisette != nil {
		return c.LoginNative(email, password, authCode)
	}

	return c.Login(email, password, authCode)
}

// LoginNative authenticates via the modern GrandSlam + native App Store flow and
// returns the account. Pass authCode when a prior call returned ErrAuthCodeRequired
// (2FA). Unlike Login (legacy MZFinance authenticate), this hits auth/v1/native
// with a GrandSlam PET and GSA anisette. The provider must also supply
// Store AMD headers from the captured device state.
func (c *Client) LoginNative(email, password, authCode string) (*Account, error) {
	if c.anisette == nil {
		return nil, errors.New("native login requires an anisette provider (offline anisette mode)")
	}

	anisetteHeaders, err := c.anisetteHeader()
	if err != nil {
		return nil, err
	}

	if anisetteHeaders.Get("X-Apple-AMD") == "" || anisetteHeaders.Get("X-Apple-AMD-M") == "" {
		return nil, errors.New("native Store login requires an AMD snapshot; run bootstrap with the iPhone connected to prepare it")
	}

	if c.deviceSigner == nil {
		return nil, errors.New("native login requires a configured iPhone signing session")
	}

	ctx := context.Background()

	gsa, err := storeauth.NewGrandSlamClient(c.http, anisetteHeaders)
	if err != nil {
		return nil, fmt.Errorf("native login: %w", err)
	}

	session, err := gsa.Login(ctx, email, password)
	if err != nil {
		var challenge *storeauth.GrandSlamChallenge
		if errors.As(err, &challenge) {
			if authCode == "" {
				// Ask Apple to push the verification code to the trusted devices.
				_ = gsa.TriggerTwoFactor(ctx, challenge)
				return nil, ErrAuthCodeRequired
			}

			if err := gsa.SubmitTwoFactor(ctx, challenge, authCode); err != nil {
				return nil, fmt.Errorf("native login 2FA: %w", err)
			}

			if session, err = gsa.Login(ctx, email, password); err != nil {
				return nil, fmt.Errorf("native login after 2FA: %w", err)
			}
		} else {
			return nil, fmt.Errorf("GrandSlam login: %w", err)
		}
	}

	if session == nil || session.PET == "" {
		return nil, errors.New("GrandSlam returned no usable App Store credential")
	}

	account, err := c.bridgeNativeSession(ctx, email, c.deviceGUID, session, nil, c.deviceSigner)
	if err != nil {
		return nil, err
	}

	account.Password = password

	return account, nil
}

// anisetteHeader renders the current-window anisette headers as an http.Header.
func (c *Client) anisetteHeader() (http.Header, error) {
	values, err := c.anisette.Headers(time.Now())
	if err != nil {
		return nil, fmt.Errorf("anisette: %w", err)
	}

	header := http.Header{}
	for name, value := range values {
		header.Set(name, value)
	}

	return header, nil
}

func (c *Client) bridgeNativeSession(ctx context.Context, email, guid string,
	session *storeauth.GrandSlamSession, anisetteHeaders http.Header, signer ActionSigner) (*Account, error) {
	payload := nativeAuthRequest{
		AppleID: email, CreateSession: true, CredentialSource: 2,
		GUID: guid, Password: session.PET, RMP: "0",
	}
	payload.PasswordSettings.Free, payload.PasswordSettings.Paid = "always", "always"

	body, err := plist.Marshal(payload, plist.XMLFormat)
	if err != nil {
		return nil, fmt.Errorf("encode native login: %w", err)
	}

	signature, err := signer.Sign(body)
	if err != nil {
		return nil, fmt.Errorf("sign native login: %w", err)
	}

	if len(signature) == 0 {
		return nil, errors.New("native login signature is empty")
	}
	// Initial device signing may take longer than an OTP window. Render fresh
	// headers after signing, immediately before constructing the Store request.
	if c.anisette != nil {
		anisetteHeaders, err = c.anisetteHeader()
		if err != nil {
			return nil, fmt.Errorf("refresh Store proof after signing: %w", err)
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, nativeAuthEndpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/x-apple-plist")
	req.Header.Set("x-apple-age-area-compliance-id", "US")
	req.Header.Set("X-Apple-Client-Application", "com.apple.accountsd")
	req.Header.Set("X-Apple-Ignore-Account-Conversion", "true")
	req.Header.Set("X-Apple-ActionSignature", base64.StdEncoding.EncodeToString(signature))
	req.Header.Set("X-Apple-ADSID", session.ADSID)
	req.Header.Set("X-Apple-Connection-Type", "WiFi")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")

	if session.DSID != 0 {
		dsid := strconv.FormatInt(session.DSID, 10)
		req.Header.Set("X-DSID", dsid)
		req.Header.Set("iCloud-DSID", dsid)
	}

	for name, values := range anisetteHeaders {
		for _, value := range values {
			req.Header.Set(name, value)
		}
	}

	req.Header.Set("User-Agent", nativeUserAgent)
	req.Header.Set("X-Apple-I-Locale", anisetteHeaders.Get("X-Apple-Locale"))

	timeZone := anisetteHeaders.Get("X-Apple-I-TimeZone")
	if timeZone == "" {
		timeZone = "GMT+3"
	}

	req.Header.Set("X-Apple-Tz", timeZone)

	client := *c.http
	if client.Timeout <= 0 || client.Timeout > 30*time.Second {
		client.Timeout = 30 * time.Second
	}

	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	res, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("native login request failed: %w", err)
	}
	defer res.Body.Close()

	data, err := io.ReadAll(io.LimitReader(res.Body, maxNativeAuthBody+1))
	if err != nil {
		return nil, fmt.Errorf("read native login response: %w", err)
	}

	if len(data) > maxNativeAuthBody {
		return nil, errors.New("native login response exceeds size limit")
	}

	var out loginResult
	if _, err := plist.Unmarshal(normalizePlist(data), &out); err != nil {
		return nil, fmt.Errorf("native login HTTP %d: response is not a valid plist; %s", res.StatusCode, apphttp.DescribeResponse(res))
	}

	if res.StatusCode < 200 || res.StatusCode >= 300 || out.FailureType != "" ||
		out.PasswordToken == "" || out.DirectoryServicesID == "" {
		if action := nativeMachineAction(res.Header, out.CustomerMessage); action != "" {
			return nil, &NativeMachineActionError{
				Action:                  action,
				AMDPresent:              req.Header.Get("X-Apple-AMD") != "" && req.Header.Get("X-Apple-AMD-M") != "",
				ProvisioningDataPresent: res.Header.Get("X-Apple-AMD-Data") != "",
			}
		}

		msg := out.CustomerMessage
		if msg == "" {
			var raw map[string]any

			_, _ = plist.Unmarshal(normalizePlist(data), &raw)
			accountInfo, _ := raw["accountInfo"].(map[string]any)
			msg = fmt.Sprintf("dsidPresent=%t; %s; HTTP %d status=%d jingleDocType=%q failureType=%q contentType=%q contentLength=%d keys=%v accountInfoKeys=%v",
				session.DSID != 0, apphttp.DescribeResponse(res), res.StatusCode, out.Status, out.JingleDocType, out.FailureType, res.Header.Get("Content-Type"), res.ContentLength, nativeResponseKeys(raw), nativeResponseKeys(accountInfo))
		}

		return nil, fmt.Errorf("native login rejected: %s", msg)
	}

	addr := out.Account.Address

	return &Account{
		Email:                   out.Account.Email,
		PasswordToken:           out.PasswordToken,
		PasswordEquivalentToken: session.PET,
		ADSID:                   session.ADSID,
		DirectoryServicesID:     out.DirectoryServicesID,
		StoreFront:              res.Header.Get(hdrStoreFront),
		Pod:                     res.Header.Get(hdrPod),
		Name:                    namePart(addr.FirstName, addr.LastName),
	}, nil
}

func nativeResponseKeys(values map[string]any) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}

	sort.Strings(keys)

	return keys
}

func namePart(first, last string) string {
	name := first
	if last != "" {
		if name != "" {
			name += " "
		}

		name += last
	}

	return name
}
