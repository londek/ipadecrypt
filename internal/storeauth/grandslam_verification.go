package storeauth

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"

	"howett.net/plist"
)

// VerifyGrandSlam requests a trusted-device code when code is empty, or submits
// a six-digit code. Callers must sign in again after successful verification.
func VerifyGrandSlam(ctx context.Context, client *http.Client, headers http.Header, account GrandSlamAccount, code string) error {
	if ctx == nil || client == nil || !headerValue(account.ADSID, 256) || !headerValue(account.VerificationToken, 32768) {
		return errors.New("missing GrandSlam verification credentials")
	}
	if code != "" {
		if len(code) != 6 {
			return errors.New("verification code must contain six digits")
		}
		for _, c := range code {
			if c < '0' || c > '9' {
				return errors.New("verification code must contain six digits")
			}
		}
	}
	lookup, err := grandSlamVerificationRequest(ctx, client, grandSlamURL+"/lookup", headers)
	if err != nil {
		return err
	}
	var bag struct {
		URLs map[string]string `plist:"urls"`
	}
	if _, err = plist.Unmarshal(lookup, &bag); err != nil {
		return errors.New("decode GrandSlam verification lookup")
	}
	key := "trustedDeviceSecondaryAuth"
	if code != "" {
		key = "validateCode"
	}
	endpoint, err := url.Parse(bag.URLs[key])
	if err != nil || endpoint.Scheme != "https" || endpoint.Host != "gsa.apple.com" || endpoint.User != nil || endpoint.Fragment != "" {
		return errors.New("untrusted GrandSlam verification endpoint")
	}
	trusted := headers.Clone()
	trusted.Set("X-Apple-Identity-Token", base64.StdEncoding.EncodeToString([]byte(account.ADSID+":"+account.VerificationToken)))
	trusted.Set("X-Apple-App-Info", "com.apple.gs.xcode.auth")
	trusted.Set("User-Agent", "Xcode")
	trusted.Set("Accept", "text/x-xml-plist")
	if code != "" {
		trusted.Set("security-code", code)
	}
	data, err := grandSlamVerificationRequest(ctx, client, endpoint.String(), trusted)
	if err != nil || code == "" {
		return err
	}
	var result map[string]any
	if _, err = plist.Unmarshal(data, &result); err != nil {
		return errors.New("decode GrandSlam verification response")
	}
	if nested, ok := result["Status"].(map[string]any); ok {
		result = nested
	}
	status, err := strconv.ParseInt(fmt.Sprint(result["ec"]), 10, 64)
	if err != nil {
		return errors.New("invalid GrandSlam verification status")
	}
	if status != 0 {
		return fmt.Errorf("GrandSlam verification failed (code %d)", status)
	}
	return nil
}

func grandSlamVerificationRequest(ctx context.Context, client *http.Client, endpoint string, headers http.Header) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, errors.New("create GrandSlam verification request")
	}
	request.Header = headers.Clone()
	isolated := *client
	isolated.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := isolated.Do(request)
	if err != nil {
		return nil, fmt.Errorf("send GrandSlam verification request: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GrandSlam verification returned HTTP %d", response.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, anisetteLimit+1))
	if err != nil {
		return nil, fmt.Errorf("read GrandSlam verification response: %w", err)
	}
	if len(data) > anisetteLimit {
		return nil, errors.New("GrandSlam verification response exceeds size limit")
	}
	return data, nil
}
