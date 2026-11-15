package anisettecapture

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/londek/ipadecrypt/internal/device"
)

// CaptureStaticHeaders reads local AuthKit device metadata. It never signs in
// or requests an OTP, and does not attach to or restart adid.
func CaptureStaticHeaders(ctx context.Context, client *device.Client) (result map[string]string, retErr error) {
	if err := EnsureItunesstored(client); err != nil {
		return nil, err
	}

	assets, err := embeddedAssets()
	if err != nil {
		return nil, err
	}

	artifacts, err := ensureFridaArtifacts(ctx)
	if err != nil {
		return nil, err
	}

	server, err := startFridaServerAt(client, artifacts, "127.0.0.1:27042")
	if err != nil {
		return nil, err
	}

	defer func() { retErr = errors.Join(retErr, server.Close()) }()

	script, err := attachDeviceScript(ctx, client, "itunesstored", assets.triggerAgent, nil)
	if err != nil {
		return nil, err
	}
	defer script.Close()

	raw, _, err := script.Call(ctx, "staticHeaders")
	if err != nil {
		return nil, fmt.Errorf("read static device headers: %w", err)
	}

	var headers map[string]string
	if err = json.Unmarshal(raw, &headers); err != nil {
		return nil, err
	}

	return filterStaticHeaders(headers)
}

func filterStaticHeaders(headers map[string]string) (map[string]string, error) {
	out := make(map[string]string)

	for _, key := range []string{"X-Mme-Device-Id", "X-Apple-I-SRL-NO", "X-MMe-Client-Info", "X-Apple-I-MD-LU", "X-Apple-I-TimeZone", "X-Apple-Locale"} {
		value := headers[key]
		if value == "" {
			continue
		}

		if len(value) > 4096 || strings.ContainsAny(value, "\r\n\x00") {
			return nil, fmt.Errorf("invalid static header %s", key)
		}

		out[key] = value
	}

	for _, key := range RequiredIdentityHeaders {
		if out[key] == "" {
			return nil, fmt.Errorf("device did not provide static header %s", key)
		}
	}

	return out, nil
}

// These fields distinguish a complete local identity capture from routing-only
// snapshot metadata. This is our capture contract, not an Apple error-code map.
var RequiredIdentityHeaders = []string{"X-Mme-Device-Id", "X-MMe-Client-Info", "X-Apple-I-TimeZone", "X-Apple-Locale"}
