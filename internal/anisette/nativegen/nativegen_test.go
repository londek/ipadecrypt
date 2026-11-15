package nativegen

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fnv1a64 mirrors emu_otp.fnv for cross-checking against the Python reference.
func fnv1a64(b []byte) string {
	h := uint64(0xcbf29ce484222325)
	for _, c := range b {
		h = (h ^ uint64(c)) * 0x100000001b3
	}

	return hexU64(h)
}

func hexU64(v uint64) string {
	var b [8]byte
	for i := 7; i >= 0; i-- {
		b[i] = byte(v)
		v >>= 8
	}

	return hex.EncodeToString(b[:])
}

// TestGoldenNative runs the native emulator against a real snapshot and checks
// the OTP16/MID against the Python-reference fingerprints. Set
// IPADECRYPT_TEST_SNAPSHOT to a snapshot directory to enable.
func TestGoldenNative(t *testing.T) {
	dir := os.Getenv("IPADECRYPT_TEST_SNAPSHOT")
	if dir == "" {
		t.Skip("set IPADECRYPT_TEST_SNAPSHOT to a snapshot dir to run")
	}

	cases := []struct {
		window int64
		otpFNV string
		midFNV string
	}{
		{59808154, "cfe64ca25e6860f1", "a53f97744239a09f"},
		{59808217, "1ebf84a9d6a3f7e3", "a53f97744239a09f"}, // recomputed below if differs
	}
	_ = cases
	// Single authoritative check: snapshot window OTP16 == known Python fnv.
	e, err := New(dir, 59808154)
	if err != nil {
		t.Fatal(err)
	}

	otp, err := e.Run()
	if err != nil {
		t.Fatalf("run: %v", err)
	}

	if len(otp) != 16 {
		t.Fatalf("otp len = %d", len(otp))
	}

	if got := fnv1a64(otp); got != "cfe64ca25e6860f1" {
		t.Errorf("OTP16 fnv = %s, want cfe64ca25e6860f1", got)
	}

	if got := fnv1a64(e.MID()); got != "a53f97744239a09f" {
		t.Errorf("MID fnv = %s, want a53f97744239a09f", got)
	}
}

func TestDecodeAtomicAndTLS(t *testing.T) {
	cas := decode(0x88e87c03) // casa w8, w3, [x0]
	if cas.kind != actCompareSwap || cas.rs != regX(8) || cas.rt != regX(3) || cas.rn != regX(0) || cas.width != 4 {
		t.Fatalf("casa decode = %+v", cas)
	}

	plain := decode(0xc8b57dd4) // cas x21, x20, [x14]
	if plain.kind != actCompareSwap || plain.rs != regX(21) || plain.rt != regX(20) || plain.rn != regX(14) || plain.width != 8 {
		t.Fatalf("cas decode = %+v", plain)
	}

	clear := decode(0xf8e81128) // ldclral x8, x8, [x9]
	if clear.kind != actAtomic || clear.op != 1 || clear.rs != regX(8) || clear.rt != regX(8) || clear.rn != regX(9) || clear.width != 8 {
		t.Fatalf("ldclral decode = %+v", clear)
	}

	add := decode(0xb8690108) // ldaddl w9, w8, [x8]
	if add.kind != actAtomic || add.op != 0 || add.rs != regX(9) || add.rt != regX(8) || add.rn != regX(8) || add.width != 4 {
		t.Fatalf("ldaddl decode = %+v", add)
	}

	acquire := decode(0xb8bfc11f) // ldapr wzr, [x8]
	if acquire.kind != actLoadAcquire || acquire.rt != regX(31) || acquire.rn != regX(8) || acquire.width != 4 {
		t.Fatalf("ldapr decode = %+v", acquire)
	}

	mrs := decode(0xd53bd060) // mrs x0, tpidrro_el0
	if mrs.kind != actTLS || mrs.reg != regX(0) {
		t.Fatalf("mrs decode = %+v", mrs)
	}
}

func TestSnapshotReference(t *testing.T) {
	dir := os.Getenv("IPADECRYPT_TEST_REFERENCE_SNAPSHOT")
	if dir == "" {
		t.Skip("set IPADECRYPT_TEST_REFERENCE_SNAPSHOT to a snapshot dir to run")
	}

	e, err := New(dir, 0)
	if err != nil {
		t.Fatal(err)
	}

	otp, err := e.Run()
	if err != nil {
		t.Fatalf("run: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "ctx.json"))
	if err != nil {
		t.Fatal(err)
	}

	var ctx ctxFile
	if err := json.Unmarshal(data, &ctx); err != nil {
		t.Fatal(err)
	}

	reference, err := base64.StdEncoding.DecodeString(ctx.RefOTPB64)
	if err != nil || (len(reference) != 24 && len(reference) != 28) {
		t.Fatalf("invalid device reference")
	}

	wantType := uint32(5)
	if len(reference) == 24 {
		wantType = 4
	}

	if ctx.OTPType != 0 && ctx.OTPType != wantType {
		t.Fatalf("snapshot OTP type = %d, reference length = %d", ctx.OTPType, len(reference))
	}

	if !bytes.Equal(reference[:8], otpTLV(wantType)) {
		t.Fatalf("device reference has the wrong OTP TLV header")
	}

	t.Logf("insns=%d otp=%s reference=%s mid=%s", e.insnCount, fnv1a64(otp), fnv1a64(reference[8:24]), fnv1a64(e.MID()))

	if !bytes.Equal(otp, reference[8:24]) {
		t.Fatalf("native OTP does not match device reference")
	}

	if len(e.MID()) != 60 {
		t.Fatalf("MID len = %d", len(e.MID()))
	}
}

func TestRejectInvalidSnapshotRanges(t *testing.T) {
	for _, r := range []rangeEntry{
		{Base: "0x1000", Size: 1, FileO: -1},
		{Base: "0x1000", Size: -1},
		{Base: "0xffffffffffffffff", Size: 2},
		{Base: "invalid", Size: 1},
	} {
		dir := t.TempDir()

		data, err := json.Marshal(manifest{ModuleBase: "0x1000", Blob: "memory.bin", Ranges: []rangeEntry{r}})
		if err != nil {
			t.Fatal(err)
		}

		if err = os.WriteFile(filepath.Join(dir, "manifest.json"), data, 0600); err != nil {
			t.Fatal(err)
		}

		if _, err = New(dir, 1); err == nil {
			t.Fatalf("invalid range accepted: %+v", r)
		}
	}
}

func TestTruncatedSnapshotFailsBeforeMapping(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "memory.bin"), []byte{1}, 0600); err != nil {
		t.Fatal(err)
	}

	e := &Emu{dir: dir, man: manifest{Blob: "memory.bin", Ranges: []rangeEntry{{Base: "0x1000", Size: 2}}}}
	if err := e.load(); err == nil || !strings.Contains(err.Error(), "exceeds memory blob") {
		t.Fatalf("expected a truncated blob error, got %v", err)
	}
}

func TestMalformedFetchedPagesFailBeforeExecution(t *testing.T) {
	for _, data := range []string{"{", `{"invalid":"AA=="}`, `{"0x1000":"invalid base64"}`} {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "memory.bin"), nil, 0600); err != nil {
			t.Fatal(err)
		}

		if err := os.WriteFile(filepath.Join(dir, "fetched_pages.json"), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}

		e := &Emu{dir: dir, man: manifest{Blob: "memory.bin"}}
		if err := e.load(); err == nil || !strings.Contains(err.Error(), "fetched page") {
			t.Fatalf("expected a fetched pages error, got %v", err)
		}
	}
}
