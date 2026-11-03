package appstore

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

type bagResult struct {
	URLBag urlBag `plist:"urlBag,omitempty"`
}

type urlBag struct {
	AuthEndpoint         string `plist:"authenticateAccount,omitempty"`
	EntDownloadEndpoint  string `plist:"volumeStoreDownloadProduct,omitempty"`
	RedownloadEndpoint   string `plist:"redownloadProduct,omitempty"`
	UpdateEndpoint       string `plist:"updateProduct,omitempty"`
	SAPSetupEndpoint     string `plist:"sign-sap-setup,omitempty"`
	SAPSetupCertEndpoint string `plist:"sign-sap-setup-cert,omitempty"`
	SAPVersion           string `plist:"sign-sap-version,omitempty"`
}

// fetchURLBag fetches the raw App Store bag.xml. The download fallback
// endpoints it carries do not need the authenticate-specific SAP validation,
// so this is kept separate from bag() and reused by the download chain.
func (c *Client) fetchURLBag() (urlBag, error) {
	g, err := guid()
	if err != nil {
		return urlBag{}, err
	}

	bagURL := fmt.Sprintf("https://%s%s?guid=%s", initDomain, initPath, g)

	var out bagResult

	res, err := c.send("bag", http.MethodGet, bagURL, map[string]string{"Accept": "application/xml"}, nil, nil, formatXML, &out)
	if err != nil {
		return urlBag{}, fmt.Errorf("bag: %w", err)
	}

	if res.StatusCode != http.StatusOK {
		return urlBag{}, fmt.Errorf("bag: status %d", res.StatusCode)
	}

	return out.URLBag, nil
}

// bag fetches the App Store bag.xml and returns the current SAP signing config:
// the authenticate endpoint to sign against plus the setup/certificate endpoints
// and version used to establish the machine-signing session during Login.
func (c *Client) bag() (SAPConfig, error) {
	out, err := c.fetchURLBag()
	if err != nil {
		return SAPConfig{}, err
	}

	config := SAPConfig{
		AuthEndpoint:   out.AuthEndpoint,
		SetupURL:       out.SAPSetupEndpoint,
		CertificateURL: out.SAPSetupCertEndpoint,
	}

	version, err := strconv.ParseUint(out.SAPVersion, 10, 32)
	if err != nil {
		return SAPConfig{}, fmt.Errorf("bag: invalid SAP version %q: %w", out.SAPVersion, err)
	}

	config.Version = uint32(version)

	if err := validateSAPConfig(config); err != nil {
		return SAPConfig{}, fmt.Errorf("bag: %w", err)
	}

	authEndpoint, err := url.Parse(config.AuthEndpoint)
	if err != nil {
		return SAPConfig{}, fmt.Errorf("bag: parse authentication endpoint: %w", err)
	}

	// The bare path returns unusable responses (204/301/HTML); Apple only
	// answers the signed authenticate request on the slashed path.
	authEndpoint.Path = PrivateAppStoreAPIPathAuth + "/"
	config.AuthEndpoint = authEndpoint.String()

	return config, nil
}

// validateSAPConfig checks that the SAP endpoints are well-formed HTTPS URLs,
// that the authenticate endpoint targets the signed MZFinance authenticate path,
// and that the SAP version is one this build supports.
func validateSAPConfig(config SAPConfig) error {
	if err := validateAuthenticationEndpoint(config.AuthEndpoint); err != nil {
		return err
	}

	for name, endpoint := range map[string]string{
		"SAP setup":      config.SetupURL,
		"SAP setup cert": config.CertificateURL,
	} {
		parsed, err := url.ParseRequestURI(endpoint)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
			return fmt.Errorf("invalid %s endpoint %q", name, endpoint)
		}
	}

	if config.Version != supportedSAPVersion {
		return fmt.Errorf("unsupported SAP version %d", config.Version)
	}

	return nil
}

// validateAuthenticationEndpoint ensures the authenticate endpoint is the signed
// MZFinance authenticate path, optionally on a per-pod buy subdomain.
func validateAuthenticationEndpoint(endpoint string) error {
	parsed, err := url.ParseRequestURI(endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return fmt.Errorf("invalid authentication endpoint %q", endpoint)
	}

	host := strings.ToLower(parsed.Hostname())
	if host != "buy."+iTunesDomain && !strings.HasSuffix(host, "-buy."+iTunesDomain) {
		return fmt.Errorf("unsupported authentication endpoint %q", endpoint)
	}

	if parsed.Path != PrivateAppStoreAPIPathAuth && parsed.Path != PrivateAppStoreAPIPathAuth+"/" {
		return fmt.Errorf("unsupported authentication endpoint %q", endpoint)
	}

	return nil
}
