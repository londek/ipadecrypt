package iphonesetup

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStoreAMDRejectsGSAReference(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"manifest.json", "stack.bin", "adidmem.bin", "fetched_pages.json"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("{}"), 0600); err != nil {
			t.Fatal(err)
		}
	}

	ref := base64.StdEncoding.EncodeToString(make([]byte, 28))
	if err := os.WriteFile(filepath.Join(dir, "ctx.json"), []byte(fmt.Sprintf(`{"refOtpB64":%q}`, ref)), 0600); err != nil {
		t.Fatal(err)
	}

	if err := verifyOfflineStoreAMD(dir); err == nil || !strings.Contains(err.Error(), "invalid type-4 reference") {
		t.Fatalf("GSA snapshot accepted as Store proof: %v", err)
	}
}

func TestStoreAMDReferenceOffline(t *testing.T) {
	dir := os.Getenv("IPADECRYPT_TEST_AMD_SNAPSHOT")
	if dir == "" {
		t.Skip("requires explicit local AMD snapshot; no device or network")
	}

	if err := verifyOfflineStoreAMD(dir); err != nil {
		t.Fatal(err)
	}
}
