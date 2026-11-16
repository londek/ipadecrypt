package appstore

import (
	"fmt"
	"net/http"
	"net/url"
)

type lookupResult struct {
	Results []App `json:"results,omitempty"`
}

func (c *Client) LookupByBundleID(acc *Account, bundleID string) (App, error) {
	cc, err := c.CountryCodeFromStoreFront(acc.StoreFront)
	if err != nil {
		return App{}, err
	}

	q := url.Values{}
	q.Add("entity", "software,iPadSoftware")
	q.Add("limit", "1")
	q.Add("media", "software")
	q.Add("country", cc)
	q.Add("bundleId", bundleID)

	return c.lookup(fmt.Sprintf("https://%s%s?%s", iTunesDomain, lookupPath, q.Encode()), bundleID)
}

func (c *Client) LookupByAppID(acc *Account, appID string) (App, error) {
	cc, err := c.CountryCodeFromStoreFront(acc.StoreFront)
	if err != nil {
		return App{}, err
	}

	q := url.Values{}
	q.Add("entity", "software,iPadSoftware")
	q.Add("country", cc)
	q.Add("id", appID)

	return c.lookup(fmt.Sprintf("https://%s%s?%s", iTunesDomain, lookupPath, q.Encode()), appID)
}

func (c *Client) lookup(u, id string) (App, error) {
	var out lookupResult

	res, err := c.send("request", http.MethodGet, u, nil, nil, formatJSON, &out)
	if err != nil {
		return App{}, fmt.Errorf("lookup: %w", err)
	}

	if res.StatusCode != http.StatusOK {
		return App{}, fmt.Errorf("lookup: status %d", res.StatusCode)
	}

	if len(out.Results) == 0 {
		return App{}, fmt.Errorf("lookup: %s: %w", id, ErrAppNotFound)
	}

	return out.Results[0], nil
}
