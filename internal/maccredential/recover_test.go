package maccredential

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/londek/ipadecrypt/internal/macho"
)

func TestPlaintextComparisonAcceptsOnlyMatchingFatSlice(t *testing.T) {
	thin := make([]byte, 64)
	binary.LittleEndian.PutUint32(thin, macho.Magic64LE)
	binary.LittleEndian.PutUint32(thin[4:], 0x0100000c) // ARM64
	binary.LittleEndian.PutUint32(thin[8:], 0)
	copy(thin[32:], "decrypted bytes must match")
	fat := make([]byte, 32+len(thin))
	binary.BigEndian.PutUint32(fat, 0xcafebabe)
	binary.BigEndian.PutUint32(fat[4:], 1)
	binary.BigEndian.PutUint32(fat[8:], 0x0100000c)
	binary.BigEndian.PutUint32(fat[16:], 32)
	binary.BigEndian.PutUint32(fat[20:], uint32(len(thin)))
	copy(fat[32:], thin)

	for _, tc := range []struct {
		name   string
		modify func([]byte)
		want   bool
	}{
		{"matching slice", func([]byte) {}, true},
		{"different plaintext", func(b []byte) { b[len(b)-1] ^= 1 }, false},
		{"different architecture", func(b []byte) { binary.BigEndian.PutUint32(b[8:], 12) }, false},
		{"truncated slice", func(b []byte) { binary.BigEndian.PutUint32(b[20:], uint32(len(b))) }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reference := bytes.Clone(fat)
			tc.modify(reference)

			match, err := plaintextMatches(bytes.NewReader(thin), bytes.NewReader(reference))
			if tc.want && (err != nil || !match) || !tc.want && match {
				t.Fatalf("match=%t, error=%v, want %t", match, err, tc.want)
			}
		})
	}
}

func modelFixture() []byte {
	b := make([]byte, 4184)
	copy(b, "FPSENR2\x00")
	binary.LittleEndian.PutUint32(b[8:], 2)
	binary.LittleEndian.PutUint32(b[12:], 4184)

	for i := range 16 {
		b[56+i] = byte(i)
	}

	for i := 88; i < len(b); i++ {
		b[i] = byte((i - 88) % 256)
	}

	return b
}
func TestDirectCredentialRejectsUnsupportedCodec(t *testing.T) {
	b := modelFixture()

	c, err := directCredential(b)
	if err != nil {
		t.Fatal(err)
	}

	for i, v := range c {
		if v != byte(i)^0x30 {
			t.Fatal("unexpected key transform")
		}
	}

	for _, offset := range []int{0, 8, 12, 72, 88} {
		bad := append([]byte(nil), b...)

		bad[offset] ^= 1
		if _, err := directCredential(bad); err == nil {
			t.Fatalf("accepted bad model at %d", offset)
		}
	}

	if _, err := directCredential(b[:100]); err == nil {
		t.Fatal("accepted truncated model")
	}
}
func TestExtractRejectsDuplicateAndUnsafeExecutable(t *testing.T) {
	for _, name := range []string{"duplicate", "unsafe"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			ipa := filepath.Join(dir, "test.ipa")
			f, _ := os.Create(ipa)
			z := zip.NewWriter(f)
			w, _ := z.Create("Payload/App.app/Info.plist")

			exe := "App"
			if name == "unsafe" {
				exe = "../outside"
			}

			w.Write([]byte(`<?xml version="1.0"?><plist version="1.0"><dict><key>CFBundleExecutable</key><string>` + exe + `</string></dict></plist>`))

			if name == "duplicate" {
				z.Create("Payload/App.app/Info.plist")
			}

			z.Close()
			f.Close()

			want := "duplicate IPA member"
			if name == "unsafe" {
				want = "invalid root app executable"
			}

			if _, err := prepareCapture(ipa, "missing.sidb", "missing.iomac", filepath.Join(dir, "capture")); err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("prepareCapture error = %v, want %q", err, want)
			}
		})
	}
}
func TestPlaintextComparisonRejectsEncryptedByteDifferences(t *testing.T) {
	dir := t.TempDir()
	create := func(path, content string) {
		f, _ := os.Create(path)
		z := zip.NewWriter(f)
		w, _ := z.Create("Payload/App.app/App")
		w.Write([]byte(content))
		z.Close()
		f.Close()
	}
	a, b := filepath.Join(dir, "a.ipa"), filepath.Join(dir, "b.ipa")
	create(a, "plaintext one")
	create(b, "plaintext two")

	if err := comparePlaintext(a, b); err == nil {
		t.Fatal("accepted different plaintext")
	}

	create(b, "plaintext one")

	if err := comparePlaintext(a, b); err != nil {
		t.Fatal(err)
	}
}

func TestAccountBinding(t *testing.T) {
	for _, tc := range []struct {
		email           string
		duplicate, want bool
	}{{"owner@example.test", false, true}, {"other@example.test", false, false}, {"owner@example.test", true, false}} {
		dir := t.TempDir()
		ipa := filepath.Join(dir, "test.ipa")
		f, _ := os.Create(ipa)
		z := zip.NewWriter(f)
		write := func() {
			w, _ := z.Create("iTunesMetadata.plist")
			w.Write([]byte(`<?xml version="1.0"?><plist version="1.0"><dict><key>apple-id</key><string>owner@example.test</string></dict></plist>`))
		}
		write()

		if tc.duplicate {
			write()
		}

		z.Close()
		f.Close()

		err := MatchAccount(ipa, tc.email)
		if (err == nil) != tc.want {
			t.Fatalf("email=%s duplicate=%t err=%v", tc.email, tc.duplicate, err)
		}
	}
}
