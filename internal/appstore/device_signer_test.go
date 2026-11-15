package appstore

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestDeviceSigningConfigurationIsIsolatedAndAtomic(t *testing.T) {
	agent := filepath.Join(t.TempDir(), "agent.js")
	if err := os.WriteFile(agent, []byte("rpc.exports = {};"), 0600); err != nil {
		t.Fatal(err)
	}

	first, second := &Client{}, &Client{}
	if err := first.ConfigureDeviceSigning("127.0.0.1:27042", agent, " device-a "); err != nil {
		t.Fatal(err)
	}

	if first.deviceGUID != "DEVICE-A" || second.deviceSigner != nil || second.deviceGUID != "" {
		t.Fatal("configuration escaped its client")
	}

	signer := first.deviceSigner
	if err := first.ConfigureDeviceSigning("127.0.0.1:27042", agent+".missing", "device-b"); err == nil {
		t.Fatal("missing agent accepted")
	}

	if first.deviceSigner != signer || first.deviceGUID != "DEVICE-A" {
		t.Fatal("failed configuration replaced a working session")
	}
}

func TestDeviceSignerPreservesBodyAndRejectsInvalidSignature(t *testing.T) {
	body := []byte{0, 1, 255, 2, 0}
	signer := &deviceActionSigner{sign: func(ctx context.Context, encoded string) (string, error) {
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("signing must be bounded")
		}

		decoded, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil || !bytes.Equal(decoded, body) {
			t.Fatal("body changed")
		}

		return base64.StdEncoding.EncodeToString([]byte("signature")), nil
	}}

	result, err := signer.Sign(body)
	if err != nil || string(result) != "signature" {
		t.Fatal(err)
	}

	for _, value := range []string{"", "not base64", base64.StdEncoding.EncodeToString(make([]byte, (64<<10)+1))} {
		signer.sign = func(context.Context, string) (string, error) { return value, nil }
		if _, err = signer.Sign(body); err == nil {
			t.Fatal("invalid signature accepted")
		}
	}

	signer.sign = func(context.Context, string) (string, error) { return "", errors.New("detached") }
	if _, err = signer.Sign(body); err == nil {
		t.Fatal("failed signing accepted")
	}

	if _, err = signer.Sign(nil); err == nil {
		t.Fatal("empty body accepted")
	}
}
