package main

import (
	"errors"
	"fmt"

	"github.com/londek/ipadecrypt/internal/appstore"
	"github.com/londek/ipadecrypt/internal/config"
)

// authEvent names recovery steps that withAuth takes so callers can
// drive their UI. The store helpers themselves stay UI-ignorant.
type authEvent int

const (
	authReauth           authEvent = iota + 1 // re-authenticating because the token expired
	authLicense                               // acquiring a license before retrying
	authRetryingDownload                      // kicking the call off again
)

// reauth refreshes the App Store password token by logging in again with
// stored credentials. Updates cfg.Apple.Account in place and persists it.
func reauth(cfg *config.Config, as *appstore.Client) error {
	acc, err := as.Login(cfg.Apple.Email, cfg.Apple.Password, "")
	if err != nil {
		return fmt.Errorf("re-auth: %w", err)
	}

	cfg.Apple.Account = acc

	if err := cfg.Save(); err != nil {
		return fmt.Errorf("save config: %w", err)
	}
	return nil
}

// acquireLicense purchases the app (free apps still need a VPP-style license
// entry). Handles mid-purchase token expiry by re-authenticating once and
// retrying. ErrLicenseAlreadyExists is treated as success.
func acquireLicense(cfg *config.Config, as *appstore.Client, app appstore.App) error {
	perr := as.Purchase(cfg.Apple.Account, app)
	if errors.Is(perr, appstore.ErrPasswordTokenExpired) {
		if rerr := reauth(cfg, as); rerr != nil {
			return rerr
		}

		perr = as.Purchase(cfg.Apple.Account, app)
	}

	if perr != nil && !errors.Is(perr, appstore.ErrLicenseAlreadyExists) {
		return fmt.Errorf("purchase: %w", perr)
	}

	return nil
}

// withAuth runs fn with up to `retries` attempts, recovering from the two
// well-known recoverable errors from the private App Store endpoint:
// ErrPasswordTokenExpired via reauth and ErrLicenseRequired via
// acquireLicense. Any other error returns immediately.
func withAuth[T any](cfg *config.Config, as *appstore.Client, app appstore.App, retries int, onEvent func(authEvent), fn func() (T, error)) (T, error) {
	var zero T
	notify := func(e authEvent) {
		if onEvent != nil {
			onEvent(e)
		}
	}

	for range retries {
		out, err := fn()
		if err == nil {
			return out, nil
		}

		switch {
		case errors.Is(err, appstore.ErrPasswordTokenExpired):
			notify(authReauth)

			if rerr := reauth(cfg, as); rerr != nil {
				return zero, rerr
			}

			notify(authRetryingDownload)

		case errors.Is(err, appstore.ErrLicenseRequired):
			notify(authLicense)

			if lerr := acquireLicense(cfg, as, app); lerr != nil {
				return zero, lerr
			}

			notify(authRetryingDownload)

		default:
			return zero, err
		}
	}

	return zero, errors.New("exhausted retries")
}
