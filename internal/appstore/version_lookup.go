package appstore

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
)

// lookupLatestExternalVersionID resolves the current iOS external version id
// for an app, needed to pin a redownload/update request. It queries the MDM
// storefront catalogs (enterprise, then the consumer iphone/ipad listings) and
// falls back to the public catalog API, which still exposes Apple Arcade apps
// that are absent from the MDM catalogs.
func (c *Client) lookupLatestExternalVersionID(acc *Account, app App) (string, error) {
	if app.ID == 0 {
		return "", errors.New("version lookup: app ID is required")
	}

	countryCode, err := CountryCodeFromStoreFront(acc.StoreFront)
	if err != nil {
		return "", fmt.Errorf("version lookup: resolve country code: %w", err)
	}

	var lastErr error

	for _, catalog := range []string{"enterprisestore", "iphone", "ipad"} {
		id, err := c.mdmExternalVersionID(app, countryCode, catalog)
		if err != nil {
			lastErr = err

			continue
		}

		return id, nil
	}

	for _, platform := range []string{"iphone", "ipad"} {
		if id, err := c.catalogExternalVersionID(app, countryCode, platform); err == nil {
			return id, nil
		}
	}

	if lastErr == nil {
		lastErr = errors.New("no external version id found")
	}

	return "", fmt.Errorf("version lookup: app %d in storefront %s: %w", app.ID, countryCode, lastErr)
}

type platformVersionLookupResult struct {
	Results map[string]platformVersionLookupItem `json:"results,omitempty"`
}

type platformVersionLookupItem struct {
	Offers []platformVersionLookupOffer `json:"offers,omitempty"`
}

type platformVersionLookupOffer struct {
	BuyParams string                       `json:"buyParams,omitempty"`
	Version   platformVersionLookupVersion `json:"version,omitempty"`
}

type platformVersionLookupVersion struct {
	ExternalID externalVersionID `json:"externalId,omitempty"`
}

// externalVersionID decodes an external version id that Apple returns as
// either a JSON string or a JSON number.
type externalVersionID string

func (id *externalVersionID) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		return nil
	}

	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		*id = externalVersionID(s)

		return nil
	}

	var n json.Number
	if err := json.Unmarshal(data, &n); err == nil {
		*id = externalVersionID(n.String())

		return nil
	}

	return fmt.Errorf("invalid external version id %s", string(data))
}

func (c *Client) mdmExternalVersionID(app App, countryCode, catalog string) (string, error) {
	params := url.Values{}
	params.Add("version", "2")
	params.Add("id", strconv.FormatInt(app.ID, 10))
	params.Add("p", "mdm-lockup")
	params.Add("caller", "MDM")
	params.Add("platform", catalog)
	params.Add("cc", strings.ToLower(countryCode))
	params.Add("l", "en")

	lookupURL := "https://uclient-api.itunes.apple.com/WebObjects/MZStorePlatform.woa/wa/lookup?" + params.Encode()

	var out platformVersionLookupResult

	res, err := c.send("request", http.MethodGet, lookupURL, nil, nil, nil, formatJSON, &out)
	if err != nil {
		return "", fmt.Errorf("mdm lookup (%s): %w", catalog, err)
	}

	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("mdm lookup (%s): status %d", catalog, res.StatusCode)
	}

	item, ok := out.Results[strconv.FormatInt(app.ID, 10)]
	if !ok || len(item.Offers) == 0 {
		return "", fmt.Errorf("mdm lookup (%s): no offers", catalog)
	}

	offer := item.Offers[0]

	id := string(offer.Version.ExternalID)
	if id == "" {
		id, err = externalVersionIDFromBuyParams(offer.BuyParams)
		if err != nil {
			return "", err
		}
	}

	if id == "" {
		return "", fmt.Errorf("mdm lookup (%s): no external version id", catalog)
	}

	return id, nil
}

type catalogVersionLookupResult struct {
	Data []catalogVersionLookupItem `json:"data,omitempty"`
}

type catalogVersionLookupItem struct {
	ID         string `json:"id,omitempty"`
	Type       string `json:"type,omitempty"`
	Attributes struct {
		DeviceFamilies     []string                                    `json:"deviceFamilies,omitempty"`
		PlatformAttributes map[string]catalogVersionPlatformAttributes `json:"platformAttributes,omitempty"`
	} `json:"attributes,omitempty"`
}

type catalogVersionPlatformAttributes struct {
	BundleID          string            `json:"bundleId,omitempty"`
	ExternalVersionID externalVersionID `json:"externalVersionId,omitempty"`
}

func (c *Client) catalogExternalVersionID(app App, countryCode, platform string) (string, error) {
	lookupURL := fmt.Sprintf("https://apps.apple.com/api/apps/v1/catalog/%s/apps/%d?platform=%s", strings.ToLower(countryCode), app.ID, platform)

	var out catalogVersionLookupResult

	res, err := c.send("request", http.MethodGet, lookupURL, nil, nil, nil, formatJSON, &out)
	if err != nil {
		return "", fmt.Errorf("catalog lookup (%s): %w", platform, err)
	}

	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("catalog lookup (%s): status %d", platform, res.StatusCode)
	}

	if len(out.Data) != 1 {
		return "", fmt.Errorf("catalog lookup (%s): expected one app", platform)
	}

	item := out.Data[0]
	if item.ID != strconv.FormatInt(app.ID, 10) || item.Type != "apps" {
		return "", fmt.Errorf("catalog lookup (%s): different app", platform)
	}

	attrs, ok := item.Attributes.PlatformAttributes["ios"]
	if !ok || !slices.Contains(item.Attributes.DeviceFamilies, platform) {
		return "", fmt.Errorf("catalog lookup (%s): no metadata for platform", platform)
	}

	if app.BundleID != "" && attrs.BundleID != app.BundleID {
		return "", fmt.Errorf("catalog lookup (%s): different bundle id", platform)
	}

	id := string(attrs.ExternalVersionID)
	if n, err := strconv.ParseUint(id, 10, 64); err != nil || n == 0 {
		return "", fmt.Errorf("catalog lookup (%s): no valid external version id", platform)
	}

	return id, nil
}

func externalVersionIDFromBuyParams(buyParams string) (string, error) {
	if buyParams == "" {
		return "", nil
	}

	values, err := url.ParseQuery(buyParams)
	if err != nil {
		return "", fmt.Errorf("parse buy params: %w", err)
	}

	return values.Get("appExtVrsId"), nil
}
