package anisette

import (
	"encoding/base64"
	"os"
	"testing"
	"time"
)

func TestNativeProviderGolden(t *testing.T) {
	dir := os.Getenv("IPADECRYPT_TEST_SNAPSHOT")
	if dir == "" {
		t.Skip()
	}

	p := &NativeProvider{Snapshot: dir}
	defer p.Close()

	h, err := p.Headers(time.Unix(59808154*30+1, 0))
	if err != nil {
		t.Fatal(err)
	}

	md := h[HeaderMD]

	mdm := h[HeaderMDM]
	if md == "" || mdm == "" {
		t.Fatal("missing MD/MDM")
	}

	raw, _ := base64.StdEncoding.DecodeString(md)
	if len(raw) != 28 {
		t.Fatalf("MD len=%d", len(raw))
	}

	t.Logf("MD=%s MDM_len_b64=%d", md[:12]+"...", len(mdm))
}
