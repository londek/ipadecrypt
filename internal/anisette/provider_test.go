package anisette

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"testing"
	"time"
)

func TestWindow(t *testing.T) {
	for _, test := range []struct {
		unix int64
		want int64
	}{
		{0, 0},
		{29, 0},
		{30, 1},
		{1794244620, 59808154},
	} {
		if got := Window(time.Unix(test.unix, 0)); got != test.want {
			t.Errorf("Window(%d) = %d, want %d", test.unix, got, test.want)
		}
	}
}

func TestEncodeMD(t *testing.T) {
	otp := make([]byte, 16)
	for i := range otp {
		otp[i] = byte(i)
	}

	encoded, err := EncodeMD(otp)
	if err != nil {
		t.Fatal(err)
	}

	got, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}

	want, err := hex.DecodeString("0000000500000010000102030405060708090a0b0c0d0e0f80000003")
	if err != nil {
		t.Fatal(err)
	}

	if string(got) != string(want) {
		t.Fatalf("MD = %x, want %x", got, want)
	}
}

func TestEncodeAMD(t *testing.T) {
	otp := make([]byte, 16)
	for i := range otp {
		otp[i] = byte(i)
	}

	encoded, err := EncodeAMD(otp)
	if err != nil {
		t.Fatal(err)
	}

	got, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}

	want, err := hex.DecodeString("0000000400000010000102030405060708090a0b0c0d0e0f")
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(got, want) {
		t.Fatalf("AMD = %x, want %x", got, want)
	}
}

func TestEncodeMDRejectsWrongOTPSize(t *testing.T) {
	if _, err := EncodeMD(make([]byte, 15)); err == nil {
		t.Fatal("expected an error")
	}
}

func TestEncodeMID(t *testing.T) {
	mid := make([]byte, 60)

	encoded, err := EncodeMID(mid)
	if err != nil {
		t.Fatal(err)
	}

	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}

	if len(decoded) != 60 {
		t.Fatalf("MID length = %d, want 60", len(decoded))
	}
}
