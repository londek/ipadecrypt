package storeauth

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"howett.net/plist"
)

const grandSlamURL = "https://gsa.apple.com/grandslam/GsService2"

// GrandSlamAccount contains short-lived credentials for Store authentication.
// It is deliberately separate from App Store cookies and password tokens.
type GrandSlamAccount struct {
	DSID, ADSID, PasswordToken string
	Expires                    time.Time
	VerificationToken          string
}

// SignInGrandSlam authenticates using fresh machine headers. When secondary
// authentication is needed, VerificationToken is set and PasswordToken is empty.
func SignInGrandSlam(ctx context.Context, client *http.Client, headers http.Header, user, password string) (GrandSlamAccount, error) {
	return signInGrandSlam(ctx, client, grandSlamURL, headers, user, password)
}

func signInGrandSlam(ctx context.Context, client *http.Client, endpoint string, headers http.Header, user, password string) (GrandSlamAccount, error) {
	if ctx == nil || client == nil || user == "" || password == "" || len(user) > 4096 || len(password) > 4096 {
		return GrandSlamAccount{}, errors.New("invalid GrandSlam sign-in arguments")
	}
	srp, err := newGrandSlamSRP()
	if err != nil {
		return GrandSlamAccount{}, fmt.Errorf("initialize GrandSlam: %w", err)
	}
	initial, err := grandSlamRequest(ctx, client, endpoint, headers, map[string]any{
		"o": "init", "u": user, "A2k": srp.public.Bytes(), "ps": []string{"s2k", "s2k_fo"},
	})
	if err != nil {
		return GrandSlamAccount{}, err
	}
	salt, _ := initial["s"].([]byte)
	server, _ := initial["B"].([]byte)
	iterations, _ := initial["i"].(uint64)
	protocol, _ := initial["sp"].(string)
	challenge, ok := initial["c"].(string)
	if !ok || !headerValue(challenge, 32768) {
		return GrandSlamAccount{}, errors.New("missing GrandSlam challenge identifier")
	}
	proof, err := srp.complete(user, password, salt, server, iterations, protocol)
	if err != nil {
		return GrandSlamAccount{}, err
	}
	defer clear(proof.key)
	complete, err := grandSlamRequest(ctx, client, endpoint, headers, map[string]any{
		"o": "complete", "u": user, "c": challenge, "M1": proof.client,
	})
	if err != nil {
		return GrandSlamAccount{}, err
	}
	serverProof, _ := complete["M2"].([]byte)
	encrypted, _ := complete["spd"].([]byte)
	plain, err := proof.decrypt(serverProof, encrypted)
	if err != nil {
		return GrandSlamAccount{}, err
	}
	defer clear(plain)

	return decodeGrandSlamAccount(plain, time.Now())
}

func grandSlamRequest(ctx context.Context, client *http.Client, endpoint string, headers http.Header, fields map[string]any) (map[string]any, error) {
	cpd := map[string]any{"bootstrap": true, "icscrec": true, "loc": "en_US", "pbe": false, "prkgen": true, "svct": "iCloud"}
	for _, key := range []string{"X-Apple-I-MD", "X-Apple-I-MD-M", "X-Apple-I-MD-LU", "X-Apple-I-MD-RINFO", "X-Mme-Device-Id", "X-MMe-Client-Info", "X-Apple-I-Client-Time", "X-Apple-I-TimeZone", "X-Apple-Locale"} {
		value := headers.Get(key)
		if !headerValue(value, 32768) {
			return nil, fmt.Errorf("missing GrandSlam machine header %s", key)
		}
		cpd[key] = value
	}
	fields["cpd"] = cpd
	body, err := plist.Marshal(map[string]any{
		"Header": map[string]any{"Version": "1.0.1"}, "Request": fields,
	}, plist.XMLFormat)
	if err != nil {
		return nil, errors.New("encode GrandSlam request")
	}
	defer clear(body)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, errors.New("create GrandSlam request")
	}
	request.Header = headers.Clone()
	request.Header.Set("Content-Type", "text/x-xml-plist")
	request.Header.Set("Accept", "*/*")
	// Do not let callers accidentally forward credentials to a redirect target.
	isolated := *client
	isolated.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := isolated.Do(request)
	if err != nil {
		return nil, fmt.Errorf("send GrandSlam request: %w", err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, anisetteLimit+1))
	if err != nil {
		return nil, fmt.Errorf("read GrandSlam response: %w", err)
	}
	defer clear(data)
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GrandSlam returned HTTP %d", response.StatusCode)
	}
	if len(data) > anisetteLimit {
		return nil, errors.New("GrandSlam response exceeds size limit")
	}
	var envelope struct{ Response map[string]any }
	if _, err = plist.Unmarshal(data, &envelope); err != nil || envelope.Response == nil {
		return nil, errors.New("decode GrandSlam response")
	}
	status, ok := envelope.Response["Status"].(map[string]any)
	if !ok || status["ec"] == nil {
		return nil, errors.New("missing GrandSlam response status")
	}
	code, err := strconv.ParseInt(fmt.Sprint(status["ec"]), 10, 64)
	if err != nil {
		return nil, errors.New("invalid GrandSlam response status")
	}
	if code != 0 {
		return nil, fmt.Errorf("GrandSlam authentication failed (code %d)", code)
	}
	return envelope.Response, nil
}

func decodeGrandSlamAccount(data []byte, now time.Time) (GrandSlamAccount, error) {
	if bytes.HasPrefix(bytes.TrimSpace(data), []byte("<dict>")) {
		data = append(append([]byte(`<plist version="1.0">`), data...), []byte("</plist>")...)
		defer clear(data)
	}
	var values map[string]any
	if _, err := plist.Unmarshal(data, &values); err != nil {
		return GrandSlamAccount{}, errors.New("decode GrandSlam account")
	}
	account := GrandSlamAccount{}
	account.ADSID, _ = values["adsid"].(string)
	if !headerValue(account.ADSID, 256) {
		return GrandSlamAccount{}, errors.New("missing GrandSlam account identifier")
	}
	switch fmt.Sprint(values["status-code"]) {
	case "409":
		account.VerificationToken, _ = values["GsIdmsToken"].(string)
		if !headerValue(account.VerificationToken, 32768) {
			return GrandSlamAccount{}, errors.New("missing GrandSlam verification token")
		}
		return account, nil
	case "200":
	default:
		return GrandSlamAccount{}, errors.New("GrandSlam account authentication failed")
	}
	account.DSID = fmt.Sprint(values["DsPrsId"])
	if _, err := strconv.ParseUint(account.DSID, 10, 64); err != nil || account.DSID == "0" {
		return GrandSlamAccount{}, errors.New("invalid GrandSlam Store account identifier")
	}
	tokens, _ := values["t"].(map[string]any)
	pet, _ := tokens["com.apple.gs.idms.pet"].(map[string]any)
	account.PasswordToken, _ = pet["token"].(string)
	expiry, err := strconv.ParseInt(fmt.Sprint(pet["expiry"]), 10, 64)
	if err != nil || !headerValue(account.PasswordToken, 32768) {
		return GrandSlamAccount{}, errors.New("missing GrandSlam Store credential")
	}
	account.Expires = time.UnixMilli(expiry)
	if !account.Expires.After(now) {
		return GrandSlamAccount{}, errors.New("GrandSlam Store credential has expired")
	}
	return account, nil
}
