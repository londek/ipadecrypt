package fairplay

import (
	"errors"
	"fmt"
	"os"
)

// CredentialSize is the fixed length of a FairPlay account credential.
const CredentialSize = 16

// LoadCredential reads and validates a 16-byte credential from path.
func LoadCredential(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read credential %s: %w", path, err)
	}

	if len(data) != CredentialSize {
		return nil, fmt.Errorf("credential must contain exactly %d bytes, got %d", CredentialSize, len(data))
	}

	return data, nil
}

// ValidateCredential checks that a credential has the expected length.
func ValidateCredential(credential []byte) error {
	if len(credential) != CredentialSize {
		return errors.New("credential must contain exactly 16 bytes")
	}

	return nil
}
