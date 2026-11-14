package iphonesetup

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/londek/ipadecrypt/internal/anisettecapture"
	"github.com/londek/ipadecrypt/internal/appstore"
	"github.com/londek/ipadecrypt/internal/config"
	"github.com/londek/ipadecrypt/internal/tui"
)

func (setup Setup) PurchaseTicket(cfg *config.Config, app appstore.App) (appstore.DownloadTicket, error) {
	signing, err := setup.PrepareSigning(cfg)
	if err != nil {
		return appstore.DownloadTicket{}, fmt.Errorf("prepare native purchase: %w", err)
	}
	defer signing.Close()

	if signing == nil {
		return appstore.DownloadTicket{}, errors.New("native purchase requires the offline anisette flow")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Second)
	defer cancel()

	data, err := anisettecapture.Purchase(ctx, signing.remote, app.ID, func(event string) {
		switch event {
		case "authenticate":
			tui.Info("purchase authenticate requested")
		case "confirmed":
			tui.OK("App Store purchase confirmation completed automatically")
		}
	})
	if err != nil {
		return appstore.DownloadTicket{}, err
	}

	return appstore.DecodeNativeDownloadTicket(data)
}
