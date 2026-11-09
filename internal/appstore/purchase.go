package appstore

import (
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	apphttp "github.com/londek/ipadecrypt/internal/apphttp"
)

type purchaseResult struct {
	FailureType     string `plist:"failureType,omitempty"`
	CustomerMessage string `plist:"customerMessage,omitempty"`
	JingleDocType   string `plist:"jingleDocType,omitempty"`
	Status          int    `plist:"status,omitempty"`

	// Dialog is the server message Apple shows instead of completing the
	// purchase (e.g. the app is unavailable in the account's region).
	Dialog struct {
		Message     string `plist:"message,omitempty"`
		Explanation string `plist:"explanation,omitempty"`
	} `plist:"dialog,omitempty"`
}

// failure describes a failed purchase in Apple's own wording when present.
func (r purchaseResult) failure() error {
	var parts []string

	for _, s := range []string{r.CustomerMessage, r.Dialog.Message, r.Dialog.Explanation} {
		if s = strings.TrimSpace(s); s != "" && !slices.Contains(parts, s) {
			parts = append(parts, s)
		}
	}

	if len(parts) == 0 {
		return errors.New("purchase failed")
	}

	return errors.New(strings.Join(parts, ": "))
}

// Purchase acquires a license for the given app on the signed-in account.
// Tries the App Store pricing family first, falls back to Arcade.
func (c *Client) Purchase(acc *Account, app App) error {
	// if app.Price > 0 {
	// return ErrPaidAppNotOwned
	// }
	g, err := guid()
	if err != nil {
		return err
	}

	return c.purchaseWithParams(acc, app, g, pricingAppStore)
}

func (c *Client) purchaseWithParams(acc *Account, app App, g, params string) error {
	podPrefix := ""
	if acc.Pod != "" {
		podPrefix = "p" + acc.Pod + "-"
	}

	url := fmt.Sprintf("https://%s%s%s", podPrefix, storeDomain, purchasePath)
	headers := map[string]string{
		"Content-Type":        "application/x-apple-plist",
		"User-Agent":          storeUserAgent,
		"iCloud-DSID":         acc.DirectoryServicesID,
		"X-Dsid":              acc.DirectoryServicesID,
		"X-Apple-Store-Front": acc.StoreFront,
		"X-Token":             acc.PasswordToken,
	}

	payload := map[string]any{
		"appExtVrsId":               "0",
		"hasAskedToFulfillPreorder": "true",
		"buyWithoutAuthorization":   "true",
		"hasDoneAgeCheck":           "true",
		"guid":                      g,
		"needDiv":                   "0",
		"origPage":                  fmt.Sprintf("Software-%d", app.ID),
		"origPageLocation":          "Buy",
		"price":                     "0",
		"pricingParameters":         params,
		"productType":               "C",
		"salableAdamId":             app.ID,
	}

	var out purchaseResult

	res, err := c.send("purchase", http.MethodPost, url, headers, &apphttp.XMLPayload{Content: payload}, nil, formatXML, &out)
	if err != nil {
		return fmt.Errorf("purchase: %w", err)
	}

	switch {
	case out.FailureType == failureTemporarilyUnavailable:
		return ErrTemporarilyUnavailable
	case out.CustomerMessage == custMsgSubscriptionRequired:
		return ErrSubscriptionRequired
	case out.FailureType == failurePasswordTokenExpired,
		out.FailureType == failureSignInRequired,
		out.FailureType == failureDeviceVerificationFailed,
		out.CustomerMessage == custMsgPasswordChanged:
		return ErrPasswordTokenExpired
	case out.FailureType == failureLicenseAlreadyExists:
		return ErrLicenseAlreadyExists
	case out.FailureType != "":
		return out.failure()
	case res.StatusCode == http.StatusInternalServerError:
		return ErrLicenseAlreadyExists
	case out.JingleDocType != "purchaseSuccess" || out.Status != 0:
		return out.failure()
	}

	return nil
}
