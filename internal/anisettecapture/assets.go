package anisettecapture

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

const assetDirectory = "agent"

var (
	//go:embed agent/adi_dump.compiled.js agent/adi_anisette_call.compiled.js agent/jetsam_limit agent/mescal_device.js agent/native_purchase.js
	source embed.FS

	assetsOnce sync.Once
	assetsPath captureAssets
	assetsErr  error
)

type captureAssets struct {
	dumpAgent     string
	triggerAgent  string
	jetsamHelper  string
	mescalAgent   string
	purchaseAgent string
}

func embeddedAssets() (captureAssets, error) {
	assetsOnce.Do(func() {
		cache, err := os.UserCacheDir()
		if err != nil {
			assetsErr = fmt.Errorf("locate anisette capture cache: %w", err)
			return
		}

		assetsPath, assetsErr = extractAssets(cache)
	})

	return assetsPath, assetsErr
}

func extractAssets(cache string) (captureAssets, error) {
	files := []string{"adi_dump.compiled.js", "adi_anisette_call.compiled.js", "jetsam_limit", "mescal_device.js", "native_purchase.js"}
	hash := sha256.New()

	contents := make(map[string][]byte, len(files))
	for _, name := range files {
		sourceName := assetDirectory + "/" + name

		data, err := source.ReadFile(sourceName)
		if err != nil {
			return captureAssets{}, fmt.Errorf("read embedded anisette capture asset: %w", err)
		}

		hash.Write([]byte(name))
		hash.Write([]byte{0})
		hash.Write(data)
		hash.Write([]byte{0})

		contents[name] = data
	}

	directory := filepath.Join(cache, "ipadecrypt", "anisette-capture-"+hex.EncodeToString(hash.Sum(nil))[:16])
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return captureAssets{}, fmt.Errorf("create anisette capture cache: %w", err)
	}

	if err := os.Chmod(directory, 0o700); err != nil {
		return captureAssets{}, fmt.Errorf("secure anisette capture cache: %w", err)
	}

	for _, name := range files {
		path := filepath.Join(directory, name)
		if current, err := os.ReadFile(path); err == nil && string(current) == string(contents[name]) {
			continue
		}

		file, err := os.CreateTemp(directory, ".capture-asset-*")
		if err != nil {
			return captureAssets{}, fmt.Errorf("create cached anisette capture asset: %w", err)
		}

		temporary := file.Name()
		if err = file.Chmod(0o600); err == nil {
			_, err = file.Write(contents[name])
		}

		if closeErr := file.Close(); err == nil {
			err = closeErr
		}

		if err == nil {
			err = os.Rename(temporary, path)
		}

		if err != nil {
			_ = os.Remove(temporary)
			return captureAssets{}, fmt.Errorf("cache anisette capture asset: %w", err)
		}
	}

	return captureAssets{
		dumpAgent:     filepath.Join(directory, "adi_dump.compiled.js"),
		triggerAgent:  filepath.Join(directory, "adi_anisette_call.compiled.js"),
		jetsamHelper:  filepath.Join(directory, "jetsam_limit"),
		mescalAgent:   filepath.Join(directory, "mescal_device.js"),
		purchaseAgent: filepath.Join(directory, "native_purchase.js"),
	}, nil
}

// MescalAgent returns the embedded iPhone Mescal signing helper.
func MescalAgent() (string, error) {
	assets, err := embeddedAssets()
	if err != nil {
		return "", err
	}

	return assets.mescalAgent, nil
}
