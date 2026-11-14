package macstore

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	store "github.com/majd/ipatool/v2/pkg/appstore"
)

type Commerce interface {
	OwnedApps(store.OwnedAppsInput) (store.OwnedAppsOutput, error)
	Purchase(store.PurchaseInput) error
}

func Owned(ctx context.Context, api Commerce, account store.Account) ([]store.App, error) {
	var result []store.App

	seen := map[int64]bool{}
	total := -1

	for page := 1; page <= 10000; page++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		out, err := api.OwnedApps(store.OwnedAppsInput{Account: account, Page: page, Limit: 100})
		if err != nil {
			return nil, SafeError(err)
		}

		if total < 0 {
			total = out.TotalCount
		}

		if out.TotalCount != total || out.Count != len(out.Results) || out.Page != page || total < 0 {
			return nil, errors.New("library changed during pagination; no purchase attempted")
		}

		for _, app := range out.Results {
			if app.ID <= 0 || seen[app.ID] {
				return nil, errors.New("inconsistent library pagination")
			}

			seen[app.ID] = true
			result = append(result, app)
		}

		if len(result) == total {
			return result, nil
		}

		if len(result) > total || len(out.Results) == 0 {
			return nil, errors.New("incomplete library")
		}
	}

	return nil, errors.New("library pagination limit exceeded")
}
func HasApp(apps []store.App, id int64) bool {
	for _, app := range apps {
		if app.ID == id {
			return true
		}
	}

	return false
}

type PurchaseEvidence struct {
	AccountHash string     `json:"accountHash"`
	Catalog     CatalogApp `json:"catalog"`
	CheckedAt   time.Time  `json:"checkedAt"`
	BeforeCount int        `json:"beforeCount"`
	AfterCount  int        `json:"afterCount"`
	OwnedBefore bool       `json:"ownedBefore"`
	OwnedAfter  bool       `json:"ownedAfter"`
	Attempted   bool       `json:"attempted"`
	Outcome     string     `json:"outcome"`
}

func Purchase(ctx context.Context, api Commerce, account store.Account, catalog CatalogApp, root string) (PurchaseEvidence, error) {
	ev := PurchaseEvidence{AccountHash: AccountHash(account), Catalog: catalog, CheckedAt: time.Now().UTC(), Outcome: "not-attempted"}
	if catalog.App.Price != 0 || catalog.OfferPrice != 0 || catalog.Currency == "" {
		return ev, errors.New("only explicitly free apps can be purchased")
	}

	if age := time.Since(catalog.CheckedAt); age < 0 || age > time.Hour {
		return ev, errors.New("catalog is stale; resolve the offer again")
	}

	before, err := Owned(ctx, api, account)
	if err != nil {
		return ev, err
	}

	ev.BeforeCount = len(before)

	ev.OwnedBefore = HasApp(before, catalog.App.ID)
	if ev.OwnedBefore {
		ev.OwnedAfter = true
		ev.AfterCount = len(before)
		ev.Outcome = "already-owned"

		return ev, nil
	}

	dir := filepath.Join(root, "purchases")
	if err = os.MkdirAll(dir, 0700); err != nil {
		return ev, err
	}

	dir, err = os.MkdirTemp(dir, fmt.Sprintf("%d-", catalog.App.ID))
	if err != nil {
		return ev, err
	}

	if err = WriteJSON(filepath.Join(dir, "before.json"), ev); err != nil {
		return ev, err
	}

	if err = WriteJSON(filepath.Join(dir, "before-library.json"), before); err != nil {
		return ev, err
	}

	ev.Attempted = true

	ev.Outcome = "pending-or-unknown"
	if err = WriteJSON(filepath.Join(dir, "result.json"), ev); err != nil {
		return ev, err
	}
	// Never automatically retry a purchase after an unknown outcome.
	if err = ctx.Err(); err != nil {
		return ev, err
	}

	purchaseErr := api.Purchase(store.PurchaseInput{Account: account, App: catalog.App, Platform: store.PlatformIPhone})

	after, afterErr := Owned(ctx, api, account)
	if afterErr == nil {
		if err = WriteJSON(filepath.Join(dir, "after-library.json"), after); err != nil {
			return ev, err
		}

		ev.AfterCount = len(after)
		ev.OwnedAfter = HasApp(after, catalog.App.ID)
	}

	if purchaseErr == nil && afterErr == nil && ev.OwnedAfter {
		ev.Outcome = "purchase-verified"
	} else if errors.Is(purchaseErr, store.ErrLicenseAlreadyExists) && ev.OwnedAfter {
		ev.Outcome = "owned-after-race"
	}

	saveErr := WriteJSON(filepath.Join(dir, "result.json"), ev)
	if saveErr != nil {
		return ev, saveErr
	}

	if ev.Outcome == "purchase-verified" || ev.Outcome == "owned-after-race" {
		return ev, nil
	}

	var interaction *InteractionError
	if errors.As(purchaseErr, &interaction) {
		return ev, interaction
	}

	if errors.Is(purchaseErr, store.ErrPasswordTokenExpired) {
		return ev, SafeError(purchaseErr)
	}

	return ev, errors.New("purchase outcome could not be verified; check the account library before another purchase (evidence saved)")
}
