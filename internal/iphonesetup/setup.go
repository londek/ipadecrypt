// Package iphonesetup prepares the snapshot and native-signing portions of the
// iPhone Store flow. Device prompting is supplied by the CLI; protocol work
// remains in anisettecapture and appstore.
package iphonesetup

import (
	"errors"

	"github.com/londek/ipadecrypt/internal/config"
)

type Setup struct {
	PromptDevice func(*config.Config, bool) error
}

func (setup Setup) promptDevice(cfg *config.Config, confirmUser bool) error {
	if setup.PromptDevice == nil {
		return errors.New("device setup requires a prompt callback")
	}

	return setup.PromptDevice(cfg, confirmUser)
}
