package macstore

import (
	"errors"
	"fmt"
	"strings"

	store "github.com/majd/ipatool/v2/pkg/appstore"
)

const termsPath = "/WebObjects/MZFinance.woa/wa/com.apple.jingle.app.finance.DirectAction/termsPage"

// InteractionError contains instructions only, never a raw server message.
// TermsURL is populated exclusively from a validated Apple terms action.
type InteractionError struct {
	TermsURL          string
	EmailVerification bool
}

func (e *InteractionError) Error() string {
	if e.TermsURL != "" {
		return "Apple requires acceptance of its Media Services terms. Open this link in App Store, review the terms, then rerun bootstrap: " + e.TermsURL
	}

	return "Apple requires email verification. Confirm the address at https://account.apple.com, then sign in again with bootstrap --flow mac --reset"
}

func storeInteraction(values map[string]any) error {
	if link := termsAction(values, 0); link != "" {
		return &InteractionError{TermsURL: link}
	}

	message, _ := values["customerMessage"].(string)
	switch message {
	case store.CustomerMessagePasswordChanged:
		return SafeError(store.ErrPasswordTokenExpired)
	case store.CustomerMessageSubscriptionRequired:
		return store.ErrSubscriptionRequired
	}

	code, _ := values["failureType"].(string)
	if code == "" {
		if metrics, ok := values["metrics"].(map[string]any); ok && metrics["messageCode"] != nil {
			code = fmt.Sprint(metrics["messageCode"])
		}
	}

	switch code {
	case store.FailureTypePasswordTokenExpired, store.FailureTypeSignInRequired, store.FailureTypeDeviceVerificationFailed:
		return SafeError(store.ErrPasswordTokenExpired)
	case store.FailureTypeLicenseNotFound:
		return store.ErrLicenseRequired
	case store.FailureTypeLicenseAlreadyExists:
		return store.ErrLicenseAlreadyExists
	case store.FailureTypeTemporarilyUnavailable:
		return store.ErrTemporarilyUnavailable
	}

	lower := strings.ToLower(message)
	if strings.Contains(lower, "verify your email") || strings.Contains(lower, "email address has not been verified") {
		return &InteractionError{EmailVerification: true}
	}

	if code != "" {
		return errors.New("store request was rejected by Apple; account state was preserved")
	}

	return nil
}

func termsAction(value any, depth int) string {
	if depth > 8 {
		return ""
	}

	switch v := value.(type) {
	case map[string]any:
		action, _ := v["action"].(map[string]any)

		raw, _ := action["url"].(string)
		if action["kind"] == "Goto" {
			if u, err := storeEndpoint(raw, termsPath); err == nil {
				u.Scheme = "macappstores"
				return u.String()
			}
		}

		for _, item := range v {
			if link := termsAction(item, depth+1); link != "" {
				return link
			}
		}
	case []any:
		for _, item := range v {
			if link := termsAction(item, depth+1); link != "" {
				return link
			}
		}
	}

	return ""
}
