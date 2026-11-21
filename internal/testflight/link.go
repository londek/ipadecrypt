package testflight

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"unicode"
)

const (
	PublicLinkOpen       = "OPEN"
	PublicLinkFull       = "FULL"
	PublicLinkDisabled   = "DISABLED"
	PublicLinkNoBuilds   = "NO_BUILDS"
	PublicLinkWithdrawn  = "WITHDRAWN"
	PublicLinkMissingApp = "MISSING_APP"
	PublicLinkInvalid    = "INVALID"
)

var publicLinkCode = regexp.MustCompile(`^[A-Za-z0-9]{1,128}$`)

type PublicLink struct {
	App    PublicLinkApp `json:"app"`
	Status string        `json:"status"`
}

type PublicLinkApp struct {
	ID           int64                `json:"appAdamId"`
	Name         string               `json:"name"`
	Platforms    []PublicLinkPlatform `json:"platforms"`
	ProviderName string               `json:"providerName"`
}

type PublicLinkPlatform struct {
	Build PublicLinkBuild `json:"build"`
}

type PublicLinkBuild struct {
	CompatibilityMessage string `json:"compatibilityMessage"`
	Compatible           bool   `json:"compatible"`
	ProviderName         string `json:"providerName"`
}

func ParsePublicLink(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if publicLinkCode.MatchString(raw) {
		return raw, nil
	}

	parsed, err := url.Parse(raw)
	if err != nil || parsed.User != nil || parsed.Port() != "" || parsed.RawQuery != "" || parsed.Fragment != "" ||
		(parsed.Scheme != "https" && parsed.Scheme != "itms-beta") ||
		!strings.EqualFold(parsed.Hostname(), "testflight.apple.com") {
		return "", errors.New("invalid TestFlight public link or code")
	}

	parts := strings.Split(strings.Trim(parsed.EscapedPath(), "/"), "/")
	if len(parts) != 2 || parts[0] != "join" {
		return "", errors.New("invalid TestFlight public link or code")
	}

	code, err := url.PathUnescape(parts[1])
	if err != nil || !publicLinkCode.MatchString(code) {
		return "", errors.New("invalid TestFlight public link or code")
	}

	return code, nil
}

func (c *Client) ResolvePublicLink(ctx context.Context, code string) (PublicLink, error) {
	code, err := ParsePublicLink(code)
	if err != nil {
		return PublicLink{}, err
	}

	var response struct {
		Data PublicLink `json:"data"`
	}
	if err := c.send(ctx, http.MethodGet, c.publicLinkPath(code), nil, &response); err != nil {
		return PublicLink{}, err
	}

	link, err := normalizePublicLink(response.Data)
	if err != nil {
		return PublicLink{}, err
	}

	return link, nil
}

func (c *Client) AcceptPublicLink(ctx context.Context, code string) error {
	code, err := ParsePublicLink(code)
	if err != nil {
		return err
	}

	payload := map[string]string{"userAction": "ACCEPTED"}

	return c.send(ctx, http.MethodPut, c.publicLinkPath(code), payload, nil)
}

func (c *Client) publicLinkPath(code string) string {
	return "/v3/accounts/" + url.PathEscape(c.session.AccountID) + "/ru/" + url.PathEscape(code)
}

func knownPublicLinkStatus(status string) bool {
	switch status {
	case PublicLinkOpen, PublicLinkFull, PublicLinkDisabled, PublicLinkNoBuilds,
		PublicLinkWithdrawn, PublicLinkMissingApp, PublicLinkInvalid:
		return true
	default:
		return false
	}
}

func normalizePublicLink(link PublicLink) (PublicLink, error) {
	if link.App.ProviderName == "" {
		for _, platform := range link.App.Platforms {
			if platform.Build.ProviderName != "" {
				link.App.ProviderName = platform.Build.ProviderName
				break
			}
		}
	}

	if link.App.ID <= 0 || !safeDisplayText(link.App.Name) ||
		!safeDisplayText(link.App.ProviderName) || !knownPublicLinkStatus(link.Status) {
		return PublicLink{}, errors.New("TestFlight returned an invalid public link preview")
	}

	return link, nil
}

func safeDisplayText(value string) bool {
	if value == "" || len(value) > 512 {
		return false
	}

	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}

	return true
}

func (l PublicLink) AvailabilityError() error {
	switch l.Status {
	case PublicLinkOpen:
		return nil
	case PublicLinkFull:
		return errors.New("this TestFlight beta is full")
	case PublicLinkDisabled:
		return errors.New("this TestFlight beta is not accepting new testers")
	case PublicLinkNoBuilds:
		return errors.New("this TestFlight beta has no available builds")
	case PublicLinkWithdrawn, PublicLinkMissingApp:
		return errors.New("this TestFlight beta is no longer available")
	case PublicLinkInvalid:
		return errors.New("this TestFlight public link is invalid")
	default:
		return fmt.Errorf("unknown TestFlight public link status %q", l.Status)
	}
}

func (l PublicLink) CompatibilityWarning() string {
	if len(l.App.Platforms) == 0 {
		return ""
	}

	for _, platform := range l.App.Platforms {
		if platform.Build.Compatible {
			return ""
		}
	}

	for _, platform := range l.App.Platforms {
		if safeDisplayText(platform.Build.CompatibilityMessage) {
			return platform.Build.CompatibilityMessage
		}
	}

	return "no compatible build is available for this TestFlight device"
}
