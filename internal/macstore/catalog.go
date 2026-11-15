package macstore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	legacy "github.com/londek/ipadecrypt/internal/appstore"
	store "github.com/majd/ipatool/v2/pkg/appstore"
	"golang.org/x/net/html"
)

type CatalogApp struct {
	App               store.App `json:"app"`
	Country           string    `json:"country"`
	Currency          string    `json:"currency"`
	ExternalVersionID string    `json:"externalVersionId"`
	OfferPrice        float64   `json:"offerPrice"`
	CheckedAt         time.Time `json:"checkedAt"`
}

var digits = regexp.MustCompile(`^[1-9][0-9]*$`)
var bundlePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
var appURLID = regexp.MustCompile(`(?:^|/)id([1-9][0-9]*)(?:/|$)`)

func Target(value string) (id, bundle string, err error) {
	if digits.MatchString(value) {
		return value, "", nil
	}

	if strings.Contains(value, "://") {
		u, e := url.Parse(value)
		if e != nil || u.Scheme != "https" || u.Host != "apps.apple.com" {
			return "", "", errors.New("expected an apps.apple.com HTTPS URL")
		}

		m := appURLID.FindStringSubmatch(u.Path)
		if m == nil {
			return "", "", errors.New("invalid App Store URL: missing numeric ID")
		}

		return m[1], "", nil
	}

	if bundlePattern.MatchString(value) && strings.Contains(value, ".") {
		return "", value, nil
	}

	return "", "", errors.New("expected an app ID, bundle ID or App Store URL")
}
func Country(storefront string) (string, error) {
	sf, _, _ := strings.Cut(storefront, ",")
	country, err := legacy.CountryCodeFromStoreFront(sf)

	return strings.ToLower(country), err
}
func publicClient() *http.Client {
	return &http.Client{Timeout: 45 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 || req.URL.Scheme != "https" || (req.URL.Host != "apps.apple.com" && req.URL.Host != "itunes.apple.com") {
			return errors.New("unexpected Apple catalog redirect")
		}

		return nil
	}}
}
func getPublic(ctx context.Context, raw string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", "Mozilla/5.0")

	res, err := publicClient().Do(req)
	if err != nil {
		return nil, errors.New("request to the Apple public catalog failed")
	}
	defer res.Body.Close()

	if res.StatusCode != 200 {
		return nil, fmt.Errorf("unexpected Apple public catalog HTTP status %d", res.StatusCode)
	}

	b, err := io.ReadAll(io.LimitReader(res.Body, 20<<20+1))
	if err != nil {
		return nil, err
	}

	if len(b) > 20<<20 {
		return nil, errors.New("catalog exceeds size limit")
	}

	return b, nil
}
func Resolve(ctx context.Context, target, storefront string) (CatalogApp, error) {
	country, err := Country(storefront)
	if err != nil {
		return CatalogApp{}, err
	}

	id, bundle, err := Target(target)
	if err != nil {
		return CatalogApp{}, err
	}

	q := url.Values{"country": {country}, "entity": {"software"}}
	if id != "" {
		q.Set("id", id)
	} else {
		q.Set("bundleId", bundle)
	}

	b, err := getPublic(ctx, "https://itunes.apple.com/lookup?"+q.Encode())
	if err != nil {
		return CatalogApp{}, err
	}

	app, currency, err := parseLookup(b, id, bundle)
	if err != nil {
		return CatalogApp{}, err
	}

	page, err := getPublic(ctx, "https://apps.apple.com/"+country+"/app/id"+strconv.FormatInt(app.ID, 10))
	if err != nil {
		return CatalogApp{}, err
	}

	version, price, err := parseOffer(page, app)
	if err != nil {
		return CatalogApp{}, err
	}

	if price != app.Price {
		return CatalogApp{}, errors.New("catalog and purchase offer disagree on price")
	}

	return CatalogApp{App: app, Country: country, Currency: currency, ExternalVersionID: version, OfferPrice: price, CheckedAt: time.Now().UTC()}, nil
}
func parseLookup(b []byte, id, bundle string) (store.App, string, error) {
	var doc struct {
		ResultCount int `json:"resultCount"`
		Results     []struct {
			ID       int64    `json:"trackId"`
			Bundle   string   `json:"bundleId"`
			Name     string   `json:"trackName"`
			Version  string   `json:"version"`
			Price    *float64 `json:"price"`
			Currency string   `json:"currency"`
			Kind     string   `json:"kind"`
		} `json:"results"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return store.App{}, "", err
	}

	for _, r := range doc.Results {
		if (id != "" && strconv.FormatInt(r.ID, 10) != id) || (bundle != "" && r.Bundle != bundle) {
			continue
		}

		if r.ID <= 0 || !bundlePattern.MatchString(r.Bundle) || r.Kind != "software" || r.Price == nil || *r.Price < 0 || r.Currency == "" || r.Version == "" {
			return store.App{}, "", errors.New("incomplete software catalog metadata (explicit price required)")
		}

		return store.App{ID: r.ID, BundleID: r.Bundle, Name: r.Name, Version: r.Version, Price: *r.Price}, r.Currency, nil
	}

	return store.App{}, "", errors.New("app not found in account storefront")
}
func parseOffer(page []byte, app store.App) (string, float64, error) {
	z := html.NewTokenizer(bytes.NewReader(page))

	var data []byte

	for {
		kind := z.Next()
		if kind == html.ErrorToken {
			break
		}

		if kind != html.StartTagToken {
			continue
		}

		t := z.Token()
		if t.Data != "script" {
			continue
		}

		found := false

		for _, a := range t.Attr {
			if a.Key == "id" && a.Val == "serialized-server-data" {
				found = true
			}
		}

		if found && z.Next() == html.TextToken {
			data = append([]byte(nil), z.Text()...)
			break
		}
	}

	var doc any

	if len(data) == 0 {
		return "", 0, errors.New("no structured offer on the Apple page")
	}

	if err := json.Unmarshal(data, &doc); err != nil {
		return "", 0, err
	}

	versions := map[string]float64{}
	ambiguous := false

	var walk func(any)

	walk = func(v any) {
		switch x := v.(type) {
		case []any:
			for _, a := range x {
				walk(a)
			}
		case map[string]any:
			if version, price, ok := mobileOffer(x, app); ok {
				if previous, exists := versions[version]; exists && previous != price {
					ambiguous = true
				}

				versions[version] = price
			}

			for _, a := range x {
				walk(a)
			}
		}
	}
	walk(doc)

	if ambiguous || len(versions) != 1 {
		return "", 0, errors.New("no unambiguous current iOS purchase offer for this app")
	}

	var (
		version string
		price   float64
	)
	for version, price = range versions {
	}

	return version, price, nil
}

// mobileOffer accepts only an explicit current iPhone/iPad offer for this app.
// Duplicate buy parameters are ambiguous even when their first values agree.
func mobileOffer(value map[string]any, app store.App) (string, float64, bool) {
	if value["$kind"] != "PurchaseConfiguration" || value["bundleId"] != app.BundleID ||
		value["isPreorder"] == true || value["isArcadeApp"] == true {
		return "", 0, false
	}

	platforms, _ := value["appPlatforms"].([]any)
	mobile := false

	for _, platform := range platforms {
		if platform == "phone" || platform == "pad" {
			mobile = true
			break
		}
	}

	if !mobile {
		return "", 0, false
	}

	raw, _ := value["buyParams"].(string)

	params, err := url.ParseQuery(raw)
	if err != nil {
		return "", 0, false
	}

	for _, key := range []string{"price", "appExtVrsId", "salableAdamId"} {
		if len(params[key]) != 1 {
			return "", 0, false
		}
	}

	version := params.Get("appExtVrsId")
	if params.Get("salableAdamId") != strconv.FormatInt(app.ID, 10) || !digits.MatchString(version) {
		return "", 0, false
	}

	price, err := strconv.ParseFloat(params.Get("price"), 64)
	if err != nil || !(price >= 0) {
		return "", 0, false
	}

	return version, price, true
}
