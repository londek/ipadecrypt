// Package anisette supplies adid-derived headers for App Store requests.
package anisette

import (
	"encoding/base64"
	"errors"
	"time"
)

const (
	HeaderMD   = "X-Apple-I-MD"
	HeaderMDM  = "X-Apple-I-MD-M"
	HeaderAMD  = "X-Apple-AMD"
	HeaderAMDM = "X-Apple-AMD-M"
	windowSize = 30
)

var mdPrefix = []byte{0, 0, 0, 5, 0, 0, 0, 16}
var mdSuffix = []byte{128, 0, 0, 3}

// Provider returns adid-derived anisette headers for the window containing t.
type Provider interface {
	Headers(t time.Time) (map[string]string, error)
}

func Window(t time.Time) int64 {
	return t.Unix() / windowSize
}

func EncodeMD(otp []byte) (string, error) {
	if len(otp) != 16 {
		return "", errors.New("anisette OTP must be 16 bytes")
	}

	raw := make([]byte, 0, 28)
	raw = append(raw, mdPrefix...)
	raw = append(raw, otp...)
	raw = append(raw, mdSuffix...)

	return base64.StdEncoding.EncodeToString(raw), nil
}

func EncodeAMD(otp []byte) (string, error) {
	if len(otp) != 16 {
		return "", errors.New("anisette OTP must be 16 bytes")
	}

	raw := make([]byte, 0, 24)
	raw = append(raw, 0, 0, 0, 4, 0, 0, 0, 16)
	raw = append(raw, otp...)

	return base64.StdEncoding.EncodeToString(raw), nil
}

func EncodeMID(mid []byte) (string, error) {
	if len(mid) != 60 {
		return "", errors.New("anisette MID must be 60 bytes")
	}

	return base64.StdEncoding.EncodeToString(mid), nil
}

func clone(headers map[string]string) map[string]string {
	out := make(map[string]string, len(headers))
	for key, value := range headers {
		out[key] = value
	}

	return out
}
