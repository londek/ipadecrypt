package appstore

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	apphttp "github.com/londek/ipadecrypt/internal/apphttp"
)

var (
	// ErrEdgeRejected marks a sign-in response without recognized backend markers.
	ErrEdgeRejected = errors.New("the Apple sign-in response has no recognized App Store backend markers")

	// ErrAuthRequestRejected marks an unsuccessful response with partial markers.
	ErrAuthRequestRejected = errors.New("the App Store rejected the sign-in request without a complete authentication response")
)

// Limit retries for responses without a usable authentication verdict.
var authEdgeRetryDelays = []time.Duration{15 * time.Second, 30 * time.Second}

// authSleep is swapped out in tests.
var authSleep = time.Sleep

// AuthRejectedError reports which layer refused an authenticate request.
type AuthRejectedError struct {
	Layer      apphttp.ResponseLayer
	StatusCode int
}

func (e *AuthRejectedError) Error() string {
	if e.Layer == apphttp.LayerBackendShort {
		return fmt.Sprintf("%s (HTTP %d)", ErrAuthRequestRejected, e.StatusCode)
	}

	return fmt.Sprintf("%s (HTTP %d, %s)", ErrEdgeRejected, e.StatusCode, e.Layer)
}

func (e *AuthRejectedError) Is(target error) bool {
	switch target {
	case ErrEdgeRejected:
		return e.Layer == apphttp.LayerEdge || e.Layer == apphttp.LayerDaiquiri
	case ErrAuthRequestRejected:
		return e.Layer == apphttp.LayerBackendShort
	}

	return false
}

// authenticateLayerError rejects marker sets observed on unusable sign-in
// responses before plist decoding. This is a routing heuristic, not a verdict
// about whether Apple evaluated the supplied password.
func authenticateLayerError(res *http.Response) error {
	layer := apphttp.ClassifyResponse(res.Header)

	switch layer {
	case apphttp.LayerEdge, apphttp.LayerDaiquiri:
		// Captured HTML stubs also used HTTP 200 with no backend markers.
		return &AuthRejectedError{Layer: layer, StatusCode: res.StatusCode}
	case apphttp.LayerBackendShort:
		// Keep pod redirects with a destination and successful plist responses.
		if apphttp.IsAuthenticationRedirect(res.StatusCode) {
			if res.Header.Get("Location") == "" {
				return &AuthRejectedError{Layer: layer, StatusCode: res.StatusCode}
			}

			return nil
		}

		if res.StatusCode == http.StatusOK {
			// Full login verdict relayed by a backend-short marker set; let
			// interpretLogin read the plist.
			return nil
		}

		return &AuthRejectedError{Layer: layer, StatusCode: res.StatusCode}
	}

	// The marker set is sufficient to proceed to response decoding.
	return nil
}
