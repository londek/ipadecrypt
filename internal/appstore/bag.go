package appstore

import (
	"fmt"
	"net/http"
)

type bagResult struct {
	URLBag struct {
		AuthEndpoint string `plist:"authenticateAccount,omitempty"`
	} `plist:"urlBag,omitempty"`
	AuthEndpoint string `plist:"authenticateAccount,omitempty"`
}

// bag fetches the App Store bag.xml and returns the authenticate endpoint URL.
// The bag holds many other URLs; we only need this one.
func (c *Client) bag() (string, error) {
	g, err := guid()
	if err != nil {
		return "", err
	}

	url := fmt.Sprintf("https://%s%s?guid=%s", initDomain, initPath, g)

	var out bagResult

	res, err := c.send(http.MethodGet, url, map[string]string{"Accept": "application/xml"}, nil, formatXML, &out)
	if err != nil {
		return "", fmt.Errorf("bag: %w", err)
	}

	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("bag: status %d", res.StatusCode)
	}

	return normalizeAuthEndpoint(out.AuthEndpoint, out.URLBag.AuthEndpoint), nil
}
