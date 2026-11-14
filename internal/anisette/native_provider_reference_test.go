package anisette

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNativeProviderAMDReference(t *testing.T) {
	dir := os.Getenv("IPADECRYPT_TEST_REFERENCE_SNAPSHOT")

	amdDir := os.Getenv("IPADECRYPT_TEST_AMD_SNAPSHOT")
	if dir == "" || amdDir == "" {
		t.Skip("set IPADECRYPT_TEST_REFERENCE_SNAPSHOT and IPADECRYPT_TEST_AMD_SNAPSHOT to run")
	}

	data, err := os.ReadFile(filepath.Join(amdDir, "ctx.json"))
	if err != nil {
		t.Fatal(err)
	}

	var ctx struct {
		RefEpoch30 int64  `json:"refEpoch30"`
		RefOTPB64  string `json:"refOtpB64"`
		RefMIDB64  string `json:"refMidB64"`
	}
	if err := json.Unmarshal(data, &ctx); err != nil {
		t.Fatal(err)
	}

	provider := &NativeProvider{Snapshot: dir, SnapshotAMD: amdDir}
	defer provider.Close()

	headers, err := provider.Headers(time.Unix(ctx.RefEpoch30*30+1, 0))
	if err != nil {
		t.Fatal(err)
	}

	generated, err := base64.StdEncoding.DecodeString(headers[HeaderAMD])
	if err != nil {
		t.Fatal(err)
	}

	reference, err := base64.StdEncoding.DecodeString(ctx.RefOTPB64)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(generated, reference) {
		t.Fatal("generated AMD does not match device reference")
	}

	if len(headers[HeaderAMDM]) != 80 {
		t.Fatalf("AMD-M base64 length = %d", len(headers[HeaderAMDM]))
	}

	if ctx.RefMIDB64 != "" && headers[HeaderAMDM] != ctx.RefMIDB64 {
		t.Fatal("generated AMD-M does not match device reference")
	}
}

func TestNativeProviderReference(t *testing.T) {
	dir := os.Getenv("IPADECRYPT_TEST_REFERENCE_SNAPSHOT")
	if dir == "" {
		t.Skip("set IPADECRYPT_TEST_REFERENCE_SNAPSHOT to a snapshot dir to run")
	}

	data, err := os.ReadFile(filepath.Join(dir, "ctx.json"))
	if err != nil {
		t.Fatal(err)
	}

	var ctx struct {
		RefEpoch30 int64  `json:"refEpoch30"`
		RefOTPB64  string `json:"refOtpB64"`
	}
	if err := json.Unmarshal(data, &ctx); err != nil {
		t.Fatal(err)
	}

	provider := &NativeProvider{Snapshot: dir}
	defer provider.Close()

	headers, err := provider.Headers(time.Unix(ctx.RefEpoch30*30+1, 0))
	if err != nil {
		t.Fatal(err)
	}

	generated, err := base64.StdEncoding.DecodeString(headers[HeaderMD])
	if err != nil {
		t.Fatal(err)
	}

	reference, err := base64.StdEncoding.DecodeString(ctx.RefOTPB64)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(generated, reference) {
		t.Fatal("generated MD does not match device reference")
	}
}
