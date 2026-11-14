// Package macstore integrates the pinned ipatool Store client with isolated state.
package macstore

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	cookiejar "github.com/juju/persistent-cookiejar"
	backend "github.com/londek/ipadecrypt/internal/store"
	store "github.com/majd/ipatool/v2/pkg/appstore"
	"github.com/majd/ipatool/v2/pkg/util/machine"
	"github.com/majd/ipatool/v2/pkg/util/operatingsystem"
)

type Session struct {
	API     store.AppStore
	jar     *cookiejar.Jar
	lock    *os.File
	Root    string
	machine machine.Machine
	backend *backend.Backend
	keys    diskKeys
}
type diskKeys string

func (d diskKeys) path(k string) string {
	return filepath.Join(string(d), fmt.Sprintf("%x", sha256.Sum256([]byte(k))))
}
func (d diskKeys) Get(k string) ([]byte, error) { return os.ReadFile(d.path(k)) }
func (d diskKeys) Set(k string, b []byte) error { return WritePrivate(d.path(k), b) }
func (d diskKeys) Remove(k string) error {
	err := os.Remove(d.path(k))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}

	return err
}

func WritePrivate(path string, b []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".write-*")
	if err != nil {
		return err
	}

	tmp := f.Name()
	defer os.Remove(tmp)

	if _, err = f.Write(b); err != nil {
		f.Close()
		return err
	}

	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}

	if err = f.Close(); err != nil {
		return err
	}

	return os.Rename(tmp, path)
}
func WriteJSON(path string, value any) error {
	b, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}

	return WritePrivate(path, append(b, '\n'))
}
func AccountHash(a store.Account) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(a.DirectoryServicesID)))
}

func Open(root string) (*Session, error) {
	if err := os.MkdirAll(root, 0700); err != nil {
		return nil, err
	}

	if err := os.Chmod(root, 0700); err != nil {
		return nil, err
	}

	lock, err := os.OpenFile(filepath.Join(root, ".lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}

	if err = lockFile(lock); err != nil {
		lock.Close()
		return nil, errors.New("the Mac Store state is in use by another process")
	}

	fail := func(err error) (*Session, error) { lock.Close(); return nil, err }

	keys := filepath.Join(root, "keys")
	if err = os.MkdirAll(keys, 0700); err != nil {
		return fail(err)
	}

	jar, err := cookiejar.New(&cookiejar.Options{Filename: filepath.Join(root, "cookies")})
	if err != nil {
		return fail(err)
	}

	operating := operatingsystem.New()
	m := machine.New(machine.Args{OS: operating})
	s := &Session{jar: jar, lock: lock, Root: root, machine: m, keys: diskKeys(keys), backend: backend.New(jar, m.MacAddress, nil)}
	s.reloadAPI()

	return s, nil
}

// Reload after the enrollment adapter advances the persisted anisette state.
func (s *Session) reloadAPI() {
	s.API = store.NewAppStore(store.Args{Keychain: s.keys, CookieJar: s.jar, OperatingSystem: operatingsystem.New(), Machine: s.machine})
}
func (s *Session) Close() error {
	s.backend.CloseIdleConnections()

	err := s.jar.Save()
	if e := os.Chmod(filepath.Join(s.Root, "cookies"), 0600); e != nil && !errors.Is(e, os.ErrNotExist) {
		err = errors.Join(err, e)
	}

	return errors.Join(err, s.lock.Close())
}

// Store errors may embed signed URLs or request metadata; expose known outcomes only.
func SafeError(err error) error {
	if err == nil {
		return nil
	}

	if errors.Is(err, context.Canceled) {
		return context.Canceled
	}

	if errors.Is(err, context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}

	if errors.Is(err, store.ErrPasswordTokenExpired) {
		return fmt.Errorf("%w; sign in again with bootstrap --flow mac --reset, then retry", store.ErrPasswordTokenExpired)
	}

	var interaction *InteractionError
	if errors.As(err, &interaction) {
		return interaction
	}

	for _, known := range []error{store.ErrAuthCodeRequired, store.ErrLicenseAlreadyExists, store.ErrLicenseRequired, store.ErrSubscriptionRequired, store.ErrTemporarilyUnavailable} {
		if errors.Is(err, known) {
			return known
		}
	}

	return errors.New("request to the Apple Store failed; account state was preserved (sensitive upstream details suppressed)")
}

func AccountCredentialPath(root string, a store.Account) string {
	return filepath.Join(root, "credentials", AccountHash(a)+".bin")
}
