package appstore

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	apphttp "github.com/londek/ipadecrypt/internal/apphttp"
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

// Login authenticates against the App Store and returns the account.
// Pass authCode when a prior call returned ErrAuthCodeRequired (2FA).
//
// It fetches the bag to obtain the current SAP signing config, establishes a
// machine-signing session, and signs the authenticate request body with it.
func (c *Client) Login(email, password, authCode string) (*Account, error) {
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

		res, err = c.send("authenticate", http.MethodPost, url, map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
		}, &apphttp.XMLPayload{Content: map[string]any{
			"appleId":  email,
			"attempt":  strconv.Itoa(requestAttempt),
			"guid":     guid,
			"password": password + strings.ReplaceAll(authCode, " ", ""),
			"rmp":      "0",
			"why":      "signIn",
		}}, signer, formatXML, &out)
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

	if out.PasswordToken == "" || out.DirectoryServicesID == "" {
		return nil, errors.New("login: no token after retries")
	}

	addr := out.Account.Address

	return &Account{
		Email:               out.Account.Email,
		PasswordToken:       out.PasswordToken,
		DirectoryServicesID: out.DirectoryServicesID,
		StoreFront:          res.Header.Get(hdrStoreFront),
		Password:            password,
		Pod:                 res.Header.Get(hdrPod),
		Name:                strings.TrimSpace(addr.FirstName + " " + addr.LastName),
	}, nil
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

	if res.StatusCode != http.StatusOK || out.PasswordToken == "" || out.DirectoryServicesID == "" {
		return "", false, fmt.Errorf("login failed (HTTP %d)", res.StatusCode)
	}

	return "", false, nil
}
