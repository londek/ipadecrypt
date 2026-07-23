package appstore

import (
	"errors"
	"fmt"
	"net/http"
)

type purchaseResult struct {
	FailureType     string `plist:"failureType,omitempty"`
	CustomerMessage string `plist:"customerMessage,omitempty"`
	JingleDocType   string `plist:"jingleDocType,omitempty"`
	Status          int    `plist:"status,omitempty"`
}

// Purchase acquires a license for the given free app on the signed-in account.
// Tries the App Store pricing family first, falls back to Arcade.
func (c *Client) Purchase(acc *Account, app App) error {
	if app.Price > 0 {
		return ErrPaidAppNotOwned
	}

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
		"iCloud-DSID":         acc.DirectoryServicesID,
		"X-Dsid":              acc.DirectoryServicesID,
		"X-Apple-Store-Front": acc.StoreFront,
		"X-Token":             acc.PasswordToken,
	}

	body, err := plistBody(map[string]any{
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
	})
	if err != nil {
		return err
	}

	var out purchaseResult

	res, err := c.send(http.MethodPost, url, headers, body, formatXML, &out)
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
	case out.FailureType != "" && out.CustomerMessage != "":
		return errors.New(out.CustomerMessage)
	case out.FailureType != "":
		return errors.New("purchase failed")
	case res.StatusCode == http.StatusInternalServerError:
		return ErrLicenseAlreadyExists
	case out.JingleDocType != "purchaseSuccess" || out.Status != 0:
		return errors.New("purchase failed")
	}

	return nil
}
