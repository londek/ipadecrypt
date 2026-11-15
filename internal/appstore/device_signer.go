package appstore

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"time"

	"github.com/londek/ipadecrypt/internal/fridarpc"
)

type deviceActionSigner struct {
	remote, source string
	sign           func(context.Context, string) (string, error)
}

// ConfigureDeviceSigning binds native sign-in to one prepared iPhone session.
// The caller owns the transport lifetime and must configure before using Client.
func (c *Client) ConfigureDeviceSigning(remote, agent, guid string) error {
	guid = strings.ToUpper(strings.TrimSpace(guid))
	if guid == "" {
		return errors.New("native signing requires a device GUID")
	}

	signer, err := newDeviceActionSigner(remote, agent)
	if err != nil {
		return err
	}

	c.deviceSigner, c.deviceGUID = signer, guid

	return nil
}

func newDeviceActionSigner(remote, path string) (*deviceActionSigner, error) {
	if remote == "" {
		return nil, errors.New("native signing requires a Frida endpoint")
	}

	source, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	s := &deviceActionSigner{remote: remote, source: string(source)}
	s.sign = func(ctx context.Context, body string) (string, error) {
		script, err := fridarpc.Attach(ctx, s.remote, "accountsd", s.source, nil)
		if err != nil {
			return "", err
		}
		defer script.Close()

		raw, _, err := script.Call(ctx, "sign", body)
		if err != nil {
			return "", err
		}

		var value string

		err = json.Unmarshal(raw, &value)

		return value, err
	}

	return s, nil
}
func (s *deviceActionSigner) Sign(body []byte) ([]byte, error) {
	if len(body) == 0 || len(body) > 4<<20 {
		return nil, errors.New("invalid device Mescal body length")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	value, err := s.sign(ctx, base64.StdEncoding.EncodeToString(body))
	if err != nil {
		return nil, err
	}

	signature, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || len(signature) == 0 || len(signature) > 64<<10 {
		return nil, errors.New("invalid device Mescal signature")
	}

	return signature, nil
}
func (s *deviceActionSigner) Close() error { return nil }
