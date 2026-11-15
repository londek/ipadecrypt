package macstore

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	store "github.com/majd/ipatool/v2/pkg/appstore"
)

type sessionCommerce struct {
	session *Session
	ctx     context.Context
}

func (s *Session) Commerce(ctx context.Context) Commerce { return sessionCommerce{s, ctx} }

func (c sessionCommerce) OwnedApps(input store.OwnedAppsInput) (store.OwnedAppsOutput, error) {
	if err := c.ctx.Err(); err != nil {
		return store.OwnedAppsOutput{}, err
	}

	return c.session.API.OwnedApps(input)
}

func (c sessionCommerce) Purchase(input store.PurchaseInput) error {
	if input.Platform != store.PlatformIPhone || input.App.ID <= 0 || input.App.Price != 0 {
		return errors.New("only free iPhone apps can be acquired")
	}

	account := input.Account
	host := "buy.itunes.apple.com"

	if account.Pod != "" {
		if !digits.MatchString(account.Pod) {
			return errors.New("invalid Store pod")
		}

		host = "p" + account.Pod + "-" + host
	}

	hardware, err := c.session.hardwareID()
	if err != nil {
		return err
	}

	response, err := c.session.sendPlist(c.ctx, "purchase", "https://"+host+"/WebObjects/MZFinance.woa/wa/buyProduct", accountHeaders(account), map[string]any{
		"appExtVrsId":               "0",
		"hasAskedToFulfillPreorder": "true",
		"buyWithoutAuthorization":   "true",
		"hasDoneAgeCheck":           "true",
		"guid":                      strings.ToUpper(hex.EncodeToString(hardware)),
		"needDiv":                   "0",
		"origPage":                  fmt.Sprintf("Software-%d", input.App.ID),
		"origPageLocation":          "Buy",
		"price":                     "0",
		"pricingParameters":         store.PricingParameterAppStore,
		"productType":               "C",
		"salableAdamId":             input.App.ID,
	})
	if err != nil {
		return err
	}

	if response["jingleDocType"] != "purchaseSuccess" || fmt.Sprint(response["status"]) != "0" {
		return errors.New("purchase was not confirmed by Apple")
	}

	return nil
}
