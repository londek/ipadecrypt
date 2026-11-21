package appstore

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/londek/ipadecrypt/internal/storeauth"
	"howett.net/plist"
)

// TestFlightStoreUserAgent selects Apple's native Mac Store authentication
// protocol. A generic agent is rejected by both the Store and session API.
const TestFlightStoreUserAgent = "MacAppStore/3.0 TestFlight/4.4.0 (Macintosh; OS X 13.1; 22C65) AppleWebKit/8614.3.7.1.5 AMS/1 (dt:1)"

const testFlightBagURL = "https://bag.itunes.apple.com/bag.xml?os=OS%20X&osVersion=13.1&deviceClass=Macintosh&product=TestFlight&productVersion=4.4.0&profile=Accounts&profileVersion=1&format=json"

// AccountAnisetteFile stores the independent GrandSlam machine provisioning.
const AccountAnisetteFile = "anisette.account"

type TestFlightStoreSession struct {
	DSID, Storefront string
	Cookies          map[string]string
}

// LoginTestFlightStore establishes the native Store cookies TestFlight needs.
// It keeps both cookies and GrandSlam provisioning separate from App Store auth.
// verify may be nil to skip interactive secondary authentication.
func (c *Client) LoginTestFlightStore(ctx context.Context, email, password, expectedDSID string, verify func() (string, error)) (TestFlightStoreSession, error) {
	if err := prepareEmulator(ctx); err != nil {
		return TestFlightStoreSession{}, err
	}

	headers, err := c.accountHeaders(ctx)
	if err != nil {
		return TestFlightStoreSession{}, err
	}

	account, err := storeauth.SignInGrandSlam(ctx, c.authHTTP, headers, email, password)
	if err != nil {
		return TestFlightStoreSession{}, err
	}

	if account.VerificationToken != "" {
		if verify == nil {
			return TestFlightStoreSession{}, ErrAuthCodeRequired
		}

		if err := storeauth.VerifyGrandSlam(ctx, c.authHTTP, headers, account, ""); err != nil {
			return TestFlightStoreSession{}, err
		}

		code, err := verify()
		if err != nil {
			return TestFlightStoreSession{}, err
		}

		code, err = normalizeAuthCode(code)
		if err != nil || code == "" {
			return TestFlightStoreSession{}, errors.New("2FA code must contain exactly six digits")
		}

		headers, err = c.accountHeaders(ctx)
		if err != nil {
			return TestFlightStoreSession{}, err
		}

		if err := storeauth.VerifyGrandSlam(ctx, c.authHTTP, headers, account, code); err != nil {
			return TestFlightStoreSession{}, err
		}

		headers, err = c.accountHeaders(ctx)
		if err != nil {
			return TestFlightStoreSession{}, err
		}

		account, err = storeauth.SignInGrandSlam(ctx, c.authHTTP, headers, email, password)
		if err != nil {
			return TestFlightStoreSession{}, err
		}
	}

	if account.VerificationToken != "" {
		return TestFlightStoreSession{}, ErrAuthCodeRequired
	}

	if account.PasswordToken == "" || account.DSID != expectedDSID {
		return TestFlightStoreSession{}, errors.New("TestFlight authentication does not match the App Store account")
	}

	return c.exchangeTestFlightStore(ctx, email, account, headers)
}

func (c *Client) accountHeaders(ctx context.Context) (http.Header, error) {
	c.authMu.Lock()
	defer c.authMu.Unlock()

	path := filepath.Join(filepath.Dir(c.anisettePath), AccountAnisetteFile)

	state, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read account machine state: %w", err)
	}

	headers, updated, err := storeauth.AccountHeaders(ctx, c.authHTTP, state)
	if err != nil {
		return nil, err
	}

	file, err := os.CreateTemp(filepath.Dir(path), ".account-*")
	if err != nil {
		return nil, fmt.Errorf("save account machine state: %w", err)
	}
	defer os.Remove(file.Name())

	_, writeErr := file.Write(updated)
	if writeErr == nil {
		writeErr = file.Sync()
	}

	closeErr := file.Close()

	if writeErr != nil {
		return nil, fmt.Errorf("save account machine state: %w", writeErr)
	}

	if closeErr != nil {
		return nil, fmt.Errorf("save account machine state: %w", closeErr)
	}

	if err := os.Rename(file.Name(), path); err != nil {
		return nil, fmt.Errorf("save account machine state: %w", err)
	}

	return headers, nil
}

func (c *Client) exchangeTestFlightStore(ctx context.Context, email string, account storeauth.GrandSlamAccount, headers http.Header) (TestFlightStoreSession, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return TestFlightStoreSession{}, err
	}

	client := *c.authHTTP
	client.Jar = jar
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, testFlightBagURL, nil)
	if err != nil {
		return TestFlightStoreSession{}, err
	}

	response, err := client.Do(request)
	if err != nil {
		return TestFlightStoreSession{}, fmt.Errorf("fetch TestFlight Store bag: %w", err)
	}

	data, err := readTestFlightStoreResponse(response)
	if err != nil {
		return TestFlightStoreSession{}, err
	}

	var bag map[string]any
	if json.Unmarshal(data, &bag) != nil {
		if _, err = plist.Unmarshal(data, &bag); err != nil {
			return TestFlightStoreSession{}, errors.New("decode TestFlight Store bag")
		}
	}

	if nested, ok := bag["urlBag"].(map[string]any); ok {
		bag = nested
	}

	config := SAPConfig{Version: supportedSAPVersion}
	config.AuthEndpoint, _ = bag["authenticateAccount"].(string)
	config.SetupURL, _ = bag["sign-sap-setup"].(string)

	config.CertificateURL, _ = bag["sign-sap-setup-cert"].(string)
	if err := validateSAPConfig(config); err != nil {
		return TestFlightStoreSession{}, err
	}
	// These unsigned bag fields must never direct the signer to another origin.
	for _, endpoint := range []struct{ raw, host, path string }{
		{config.SetupURL, "fpinit.itunes.apple.com", "/v1/signSapSetup/legacy"},
		{config.CertificateURL, "s.mzstatic.com", "/sap/setupCert.plist"},
	} {
		parsed, err := url.Parse(endpoint.raw)
		if err != nil || parsed.Scheme != "https" || parsed.Host != endpoint.host || parsed.Path != endpoint.path || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
			return TestFlightStoreSession{}, errors.New("untrusted TestFlight Store signing endpoint")
		}
	}

	g, err := guid()
	if err != nil {
		return TestFlightStoreSession{}, err
	}

	hardware, err := hex.DecodeString(g)
	if err != nil {
		return TestFlightStoreSession{}, err
	}

	signer, err := c.actionSignerFactory(config, hardware)
	if err != nil {
		return TestFlightStoreSession{}, err
	}
	defer signer.Close()

	body, err := plist.Marshal(map[string]any{
		"createSession": true, "credentialSource": 5, "guid": g, "isSilentAuthentication": false,
		"password": account.PasswordToken, "rmp": "0", "appleId": email, "deviceOffersCheck": "true",
		"passwordSettings": map[string]string{"free": "always", "paid": "always"},
	}, plist.XMLFormat)
	if err != nil {
		return TestFlightStoreSession{}, errors.New("encode TestFlight Store login")
	}
	defer clear(body)

	endpoint := config.AuthEndpoint

	for attempt := 0; attempt < maxAuthenticationRedirects; attempt++ {
		if !account.Expires.After(time.Now()) {
			return TestFlightStoreSession{}, errors.New("TestFlight Store credential has expired")
		}

		proof, err := c.amdProof(ctx, endpoint, hardware)
		if err != nil {
			return TestFlightStoreSession{}, err
		}

		signature, err := signer.Sign(body)
		if err != nil {
			return TestFlightStoreSession{}, err
		}

		request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
		if err != nil {
			return TestFlightStoreSession{}, err
		}

		request.Header = headers.Clone()
		request.Header.Set("Content-Type", "application/x-apple-plist")
		request.Header.Set("User-Agent", TestFlightStoreUserAgent)
		request.Header.Set("X-Apple-Client-Application", "com.apple.TestFlight")
		request.Header.Set("X-DSID", account.ADSID)
		request.Header.Set("X-Apple-Tz", "0")
		request.Header.Set("X-Apple-ActionSignature", base64.StdEncoding.EncodeToString(signature))

		for name, value := range proof {
			request.Header.Set(name, value)
		}

		response, err := client.Do(request)
		if err != nil {
			return TestFlightStoreSession{}, fmt.Errorf("authenticate TestFlight Store: %w", err)
		}

		if response.StatusCode == http.StatusFound || response.StatusCode == http.StatusTemporaryRedirect {
			response.Body.Close()

			endpoint, err = resolveAuthenticationRedirect(endpoint, response.Header.Get("Location"))
			if err != nil {
				return TestFlightStoreSession{}, err
			}

			continue
		}

		data, err := readTestFlightStoreResponse(response)
		if err != nil {
			return TestFlightStoreSession{}, err
		}

		loginErr := validateTestFlightStoreLogin(data, account.DSID)
		clear(data)

		if loginErr != nil {
			return TestFlightStoreSession{}, loginErr
		}

		storefront := response.Header.Get("X-Set-Apple-Store-Front")
		if storefront == "" {
			storefront = response.Header.Get("X-Apple-Store-Front")
		}

		if storefront == "" || strings.ContainsAny(storefront, "\r\n") {
			return TestFlightStoreSession{}, errors.New("missing TestFlight Store storefront")
		}

		root, _ := url.Parse("https://apple.com/")

		cookies := make(map[string]string)
		for _, cookie := range jar.Cookies(root) {
			cookies[cookie.Name] = cookie.Value
		}

		if len(cookies) == 0 {
			return TestFlightStoreSession{}, errors.New("missing TestFlight Store cookies")
		}

		return TestFlightStoreSession{DSID: account.DSID, Storefront: storefront, Cookies: cookies}, nil
	}

	return TestFlightStoreSession{}, errors.New("TestFlight Store redirect limit exceeded")
}

func validateTestFlightStoreLogin(data []byte, dsid string) error {
	var result struct {
		Status        *int   `plist:"status"`
		DSID          string `plist:"dsPersonId"`
		PasswordToken string `plist:"passwordToken"`
	}
	if _, err := plist.Unmarshal(data, &result); err != nil {
		return errors.New("decode TestFlight Store login")
	}

	if result.Status == nil || *result.Status != 0 || result.DSID != dsid || result.PasswordToken == "" {
		return errors.New("TestFlight Store login rejected")
	}

	return nil
}

func readTestFlightStoreResponse(response *http.Response) ([]byte, error) {
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("TestFlight Store returned HTTP %d", response.StatusCode)
	}

	data, err := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
	if err != nil {
		return nil, fmt.Errorf("read TestFlight Store response: %w", err)
	}

	if len(data) > 1<<20 {
		return nil, errors.New("TestFlight Store response exceeds size limit")
	}

	return data, nil
}
