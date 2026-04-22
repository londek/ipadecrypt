package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/londek/ipadecrypt/internal/appstore"
)

const SchemaVersion = 1

type Config struct {
	Version  int      `json:"version"`
	Apple    Apple    `json:"apple"`
	Device   Device   `json:"device"`
	Versions Versions `json:"versions,omitempty"`

	path string
}

type Versions struct {
	WarningAccepted bool `json:"warningAccepted,omitempty"`
}

type Apple struct {
	Email    string            `json:"email,omitempty"`
	Password string            `json:"password,omitempty"`
	Account  *appstore.Account `json:"account,omitempty"`
}

type Device struct {
	Host             string     `json:"host,omitempty"`
	Port             int        `json:"port,omitempty"`
	User             string     `json:"user,omitempty"`
	Auth             DeviceAuth `json:"auth,omitempty"`
	KnownHostsPath   string     `json:"knownHostsPath,omitempty"`
	AcceptNewHostKey bool       `json:"acceptNewHostKey,omitempty"`
}

type DeviceAuth struct {
	Kind          string `json:"kind,omitempty"`
	Password      string `json:"password,omitempty"`
	KeyPath       string `json:"keyPath,omitempty"`
	KeyPassphrase string `json:"keyPassphrase,omitempty"`
}

func New(path string) *Config {
	return &Config{Version: SchemaVersion, path: path}
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	cfg := &Config{path: path}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}

	if cfg.Version == 0 {
		cfg.Version = SchemaVersion
	}

	return cfg, nil
}

func (c *Config) Save() error {
	if c.path == "" {
		return errors.New("config: no path")
	}

	if err := os.MkdirAll(filepath.Dir(c.path), 0o755); err != nil {
		return fmt.Errorf("mkdir config dir: %w", err)
	}

	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	tmp := c.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("open %s: %w", tmp, err)
	}

	if _, err := f.Write(data); err != nil {
		f.Close()
		return fmt.Errorf("write %s: %w", tmp, err)
	}

	if err := f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("sync %s: %w", tmp, err)
	}

	if err := f.Close(); err != nil {
		return fmt.Errorf("close %s: %w", tmp, err)
	}

	if err := os.Rename(tmp, c.path); err != nil {
		return fmt.Errorf("rename: %w", err)
	}

	return nil
}
