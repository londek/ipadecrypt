package main

import (
	"fmt"
	"os"

	"github.com/londek/ipadecrypt/internal/config"
	"github.com/londek/ipadecrypt/internal/fairplay"
)

// loadCachedCredential reads the 16-byte FairPlay credential cached for the
// given account DSID.
func loadCachedCredential(paths *config.Paths, dsid string) ([]byte, error) {
	path, err := paths.CredentialPath(dsid)
	if err != nil {
		return nil, err
	}

	return fairplay.LoadCredential(path)
}

// credentialCached reports whether a credential is already cached for dsid.
func credentialCached(paths *config.Paths, dsid string) bool {
	path, err := paths.CredentialPath(dsid)
	if err != nil {
		return false
	}

	_, err = os.Stat(path)

	return err == nil
}

// saveCredential writes the credential for dsid atomically with 0600 perms.
func saveCredential(paths *config.Paths, dsid string, credential []byte) error {
	if err := fairplay.ValidateCredential(credential); err != nil {
		return err
	}

	path, err := paths.CredentialPath(dsid)
	if err != nil {
		return err
	}

	tmp := path + ".tmp"

	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("open %s: %w", tmp, err)
	}

	if _, err := f.Write(credential); err != nil {
		f.Close()
		os.Remove(tmp)

		return fmt.Errorf("write %s: %w", tmp, err)
	}

	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)

		return fmt.Errorf("sync %s: %w", tmp, err)
	}

	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("close %s: %w", tmp, err)
	}

	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("rename: %w", err)
	}

	return nil
}
