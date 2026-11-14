package anisettecapture

import (
	"context"
	"encoding/json"
	"os"
	"sort"
	"testing"
	"time"

	"github.com/londek/ipadecrypt/internal/config"
	"github.com/londek/ipadecrypt/internal/device"
)

func TestStaticHeadersExcludeTokens(t *testing.T) {
	headers := map[string]string{"Cookie": "secret", "X-Apple-I-MD": "otp", "X-Apple-AMD": "amd"}
	for _, key := range RequiredIdentityHeaders {
		headers[key] = "fixture"
	}

	out, err := filterStaticHeaders(headers)
	if err != nil {
		t.Fatal(err)
	}

	if len(out) != len(RequiredIdentityHeaders) {
		t.Fatal("unexpected captured headers")
	}

	headers["X-Mme-Device-Id"] = "bad\r\nInjected: header"
	if _, err := filterStaticHeaders(headers); err == nil {
		t.Fatal("accepted control characters")
	}

	delete(headers, "X-Mme-Device-Id")

	if _, err := filterStaticHeaders(headers); err == nil {
		t.Fatal("accepted incomplete identity")
	}
}

func TestLiveStaticIdentity(t *testing.T) {
	path := os.Getenv("IPADECRYPT_TEST_IDENTITY_CONFIG")
	if path == "" {
		t.Skip("requires explicit device configuration")
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	client, err := device.Connect(ctx, cfg.Device)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	headers, err := CaptureStaticHeaders(ctx, client)
	if err != nil {
		t.Fatal(err)
	}

	keys := make([]string, 0, len(headers))
	for key := range headers {
		keys = append(keys, key)
	}

	sort.Strings(keys)
	t.Logf("captured static fields (values private): %v", keys)

	if output := os.Getenv("IPADECRYPT_TEST_IDENTITY_OUTPUT"); output != "" {
		data, err := json.MarshalIndent(headers, "", "  ")
		if err != nil {
			t.Fatal(err)
		}

		f, err := os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()

		if _, err := f.Write(data); err != nil {
			t.Fatal(err)
		}
	}
}
