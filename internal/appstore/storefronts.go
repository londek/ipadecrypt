package appstore

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	apphttp "github.com/londek/ipadecrypt/internal/apphttp"
	"howett.net/plist"
)

// Storefronts missing from the storeFronts table are discovered from Apple and
// cached on the client: first from the available-storefronts list, then by
// asking the App Store which country a storefront ID belongs to (the list
// omits some live storefronts, such as China).
const (
	availableStorefrontsURL = "https://itunes.apple.com/WebObjects/MZStore.woa/wa/availableStoreFronts"
	storefrontGenreURL      = "https://apps.apple.com/genre/id36"
	maxStorefrontIDRange    = 1000
)

type availableStorefrontsResult struct {
	Storefronts []availableStorefront `plist:"storefronts"`
}

type availableStorefront struct {
	CountryCode string `plist:"country-code"`
	ID          int64  `plist:"id"`
}

type storefrontGenrePage struct {
	StorePlatformData map[string]struct {
		Meta struct {
			Storefront struct {
				CountryCode string `json:"cc"`
				ID          string `json:"id"`
			} `json:"storefront"`
		} `json:"meta"`
	} `json:"storePlatformData"`
}

func (c *Client) CountryCodeFromStoreFront(storeFront string) (string, error) {
	identifier := storefrontIdentifier(storeFront)

	// The built-in table answers known storefronts without a network call;
	// Apple's list is only fetched for the ones it lacks.
	for key, val := range storeFronts {
		if identifier == val {
			return key, nil
		}
	}

	if err := c.discoverAvailableStorefronts(); err != nil {
		return "", err
	}

	if countryCode := c.cachedStorefrontCountryCode(identifier); countryCode != "" {
		return countryCode, nil
	}

	countryCode, found, err := c.discoverStorefrontCountryCode(identifier)
	if err != nil {
		return "", err
	}

	if found {
		return countryCode, nil
	}

	return "", fmt.Errorf("country code mapping for store front (%s) was not found", storeFront)
}

func (c *Client) storefrontID(countryCode string) string {
	if id, ok := storeFronts[countryCode]; ok {
		return id
	}

	c.storefrontsMu.Lock()
	defer c.storefrontsMu.Unlock()

	for identifier, code := range c.storefrontCountryCodes {
		if code == countryCode {
			return identifier
		}
	}

	return ""
}

func (c *Client) discoverStorefrontID(countryCode string) (string, error) {
	countryCode = strings.ToUpper(strings.TrimSpace(countryCode))
	if id, ok := storeFronts[countryCode]; ok {
		return id, nil
	}

	if err := c.discoverAvailableStorefronts(); err != nil {
		return "", err
	}

	if identifier := c.storefrontID(countryCode); identifier != "" {
		return identifier, nil
	}

	identifiers, err := c.missingStorefrontIdentifiers()
	if err != nil {
		return "", err
	}

	for _, identifier := range identifiers {
		resolvedCountryCode, found, resolveErr := c.discoverStorefrontCountryCode(identifier)
		if resolveErr != nil {
			return "", resolveErr
		}

		if found && resolvedCountryCode == countryCode {
			return identifier, nil
		}
	}

	return "", fmt.Errorf("store front mapping for country code (%s) was not found", countryCode)
}

func (c *Client) cachedStorefrontCountryCode(identifier string) string {
	c.storefrontsMu.Lock()
	defer c.storefrontsMu.Unlock()

	return c.storefrontCountryCodes[identifier]
}

// missingStorefrontIdentifiers lists the unknown IDs between the lowest and
// highest known storefront IDs.
func (c *Client) missingStorefrontIdentifiers() ([]string, error) {
	c.storefrontsMu.Lock()
	defer c.storefrontsMu.Unlock()

	minimum, maximum := int64(0), int64(0)
	known := make(map[int64]struct{}, len(c.storefrontCountryCodes))

	for identifier := range c.storefrontCountryCodes {
		value, err := strconv.ParseInt(identifier, 10, 64)
		if err != nil || value <= 0 {
			continue
		}

		known[value] = struct{}{}

		if minimum == 0 || value < minimum {
			minimum = value
		}

		if value > maximum {
			maximum = value
		}
	}

	if minimum == 0 || maximum-minimum > maxStorefrontIDRange {
		return nil, errors.New("available storefront identifier range is invalid")
	}

	identifiers := make([]string, 0, maximum-minimum+1-int64(len(known)))

	for identifier := minimum; identifier <= maximum; identifier++ {
		if _, ok := known[identifier]; !ok {
			identifiers = append(identifiers, strconv.FormatInt(identifier, 10))
		}
	}

	return identifiers, nil
}

// discoverStorefrontCountryCode asks the App Store which country a storefront
// ID belongs to and caches it. Retired IDs redirect or return 404.
func (c *Client) discoverStorefrontCountryCode(identifier string) (string, bool, error) {
	if _, err := strconv.ParseInt(identifier, 10, 64); err != nil {
		return "", false, nil
	}

	var body []byte

	res, err := c.sendRequest("request", apphttp.Request{
		URL:         storefrontGenreURL,
		Method:      http.MethodGet,
		NoRedirects: true,
		Headers: map[string]string{
			"X-Apple-Store-Front": identifier + "-2,29",
		},
	}, formatRaw, &body)
	if err != nil {
		return "", false, fmt.Errorf("storefront country code: %w", err)
	}

	if (res.StatusCode >= http.StatusMultipleChoices && res.StatusCode < http.StatusBadRequest) || res.StatusCode == http.StatusNotFound {
		return "", false, nil
	}

	if res.StatusCode != http.StatusOK {
		return "", false, fmt.Errorf("storefront country code: status %d", res.StatusCode)
	}

	var page storefrontGenrePage

	if err = json.Unmarshal(body, &page); err != nil {
		return "", false, fmt.Errorf("storefront country code: decode json: %w", err)
	}

	var (
		countryCode     string
		foundIdentifier bool
	)

	for _, data := range page.StorePlatformData {
		storefront := data.Meta.Storefront
		if storefront.ID == identifier {
			foundIdentifier = true
			countryCode = strings.ToUpper(strings.TrimSpace(storefront.CountryCode))

			break
		}
	}

	if !foundIdentifier {
		return "", false, nil
	}

	if len(countryCode) != 2 {
		return "", false, errors.New("storefront country code response contains no country code")
	}

	for _, character := range countryCode {
		if character < 'A' || character > 'Z' {
			return "", false, errors.New("storefront country code response contains an invalid country code")
		}
	}

	c.storefrontsMu.Lock()
	defer c.storefrontsMu.Unlock()

	for knownIdentifier, knownCountryCode := range c.storefrontCountryCodes {
		if knownCountryCode == countryCode && knownIdentifier != identifier {
			return "", false, nil
		}
	}

	c.storefrontCountryCodes[identifier] = countryCode

	return countryCode, true, nil
}

// discoverAvailableStorefronts loads Apple's available-storefronts list once
// per client.
func (c *Client) discoverAvailableStorefronts() error {
	c.storefrontsMu.Lock()
	defer c.storefrontsMu.Unlock()

	if c.storefrontCountryCodes != nil {
		return nil
	}

	var data []byte

	res, err := c.sendRequest("request", apphttp.Request{
		URL:    availableStorefrontsURL,
		Method: http.MethodGet,
	}, formatRaw, &data)
	if err != nil {
		return fmt.Errorf("available storefronts: %w", err)
	}

	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("available storefronts: status %d", res.StatusCode)
	}

	var result availableStorefrontsResult

	if _, err = plist.Unmarshal(data, &result); err != nil {
		return fmt.Errorf("available storefronts: decode plist: %w", err)
	}

	countryCodes := make(map[string]string, len(result.Storefronts))

	for _, storefront := range result.Storefronts {
		countryCode := strings.ToUpper(strings.TrimSpace(storefront.CountryCode))
		if storefront.ID <= 0 || countryCode == "" {
			continue
		}

		countryCodes[strconv.FormatInt(storefront.ID, 10)] = countryCode
	}

	if len(countryCodes) == 0 {
		return errors.New("available storefronts response contains no storefronts")
	}

	c.storefrontCountryCodes = countryCodes

	return nil
}

func storefrontIdentifier(storeFront string) string {
	identifier, _, _ := strings.Cut(strings.TrimSpace(storeFront), ",")
	identifier, _, _ = strings.Cut(identifier, "-")

	return identifier
}

// phoneNumberStorefrontCountryCode identifies the storefront routing hint for
// phone-based Apple Accounts in mainland China and India. It does not change
// the Apple ID sent to Apple.
func phoneNumberStorefrontCountryCode(appleID string) string {
	number := strings.ReplaceAll(strings.TrimSpace(appleID), " ", "")
	number = strings.ReplaceAll(number, "-", "")

	international := false

	switch {
	case strings.HasPrefix(number, "+"):
		international = true
		number = number[1:]
	case strings.HasPrefix(number, "00"):
		international = true
		number = number[2:]
	}

	for _, digit := range number {
		if digit < '0' || digit > '9' {
			return ""
		}
	}

	// Check the full length before removing a country code: a local Indian
	// number can itself start with 91. Explicit international numbers must
	// match a supported country code and cannot fall back to a local format.
	switch {
	case len(number) == 13 && strings.HasPrefix(number, "861"):
		return "CN"
	case len(number) == 12 && strings.HasPrefix(number, "91"):
		number = number[2:]
	case international:
		return ""
	}

	if len(number) == 11 && number[0] == '1' {
		return "CN"
	}

	// India also permits a trunk prefix when writing a national number.
	if !international && len(number) == 11 && number[0] == '0' {
		number = number[1:]
	}

	if len(number) == 10 && number[0] >= '6' && number[0] <= '9' {
		return "IN"
	}

	return ""
}

// ResolveStorefront turns a user-provided storefront value into a numeric
// Apple Store Front ID.  It accepts both the canonical ID (e.g. "143441")
// and two-letter country codes (e.g. "US", "pl").
func (c *Client) ResolveStorefront(input string) (string, error) {
	if input == "" {
		return "", nil
	}

	// Already a numeric storefront ID.
	allDigits := true

	for _, r := range input {
		if r < '0' || r > '9' {
			allDigits = false
			break
		}
	}

	if allDigits {
		return input, nil
	}

	// Country code lookup (case-insensitive).
	cc := strings.ToUpper(input)
	if len(cc) != 2 {
		return "", fmt.Errorf("unknown storefront %q (expected numeric ID or two-letter country code)", input)
	}

	id, err := c.discoverStorefrontID(cc)
	if err != nil {
		return "", fmt.Errorf("unknown storefront %q (expected numeric ID or two-letter country code): %w", input, err)
	}

	return id, nil
}

var storeFronts = map[string]string{
	"AE": "143481",
	"AG": "143540",
	"AI": "143538",
	"AL": "143575",
	"AM": "143524",
	"AO": "143564",
	"AR": "143505",
	"AT": "143445",
	"AU": "143460",
	"AZ": "143568",
	"BB": "143541",
	"BD": "143490",
	"BE": "143446",
	"BG": "143526",
	"BH": "143559",
	"BM": "143542",
	"BN": "143560",
	"BO": "143556",
	"BR": "143503",
	"BS": "143539",
	"BW": "143525",
	"BY": "143565",
	"BZ": "143555",
	"CA": "143455",
	"CH": "143459",
	"CI": "143527",
	"CL": "143483",
	"CN": "143465",
	"CO": "143501",
	"CR": "143495",
	"CY": "143557",
	"CZ": "143489",
	"DE": "143443",
	"DK": "143458",
	"DM": "143545",
	"DO": "143508",
	"DZ": "143563",
	"EC": "143509",
	"EE": "143518",
	"EG": "143516",
	"ES": "143454",
	"FI": "143447",
	"FR": "143442",
	"GB": "143444",
	"GD": "143546",
	"GE": "143615",
	"GH": "143573",
	"GR": "143448",
	"GT": "143504",
	"GY": "143553",
	"HK": "143463",
	"HN": "143510",
	"HR": "143494",
	"HU": "143482",
	"ID": "143476",
	"IE": "143449",
	"IL": "143491",
	"IN": "143467",
	"IS": "143558",
	"IT": "143450",
	"IQ": "143617",
	"JM": "143511",
	"JO": "143528",
	"JP": "143462",
	"KE": "143529",
	"KN": "143548",
	"KR": "143466",
	"KW": "143493",
	"KY": "143544",
	"KZ": "143517",
	"LB": "143497",
	"LC": "143549",
	"LI": "143522",
	"LK": "143486",
	"LT": "143520",
	"LU": "143451",
	"LV": "143519",
	"MD": "143523",
	"MG": "143531",
	"MK": "143530",
	"ML": "143532",
	"MN": "143592",
	"MO": "143515",
	"MS": "143547",
	"MT": "143521",
	"MU": "143533",
	"MV": "143488",
	"MX": "143468",
	"MY": "143473",
	"NE": "143534",
	"NG": "143561",
	"NI": "143512",
	"NL": "143452",
	"NO": "143457",
	"NP": "143484",
	"NZ": "143461",
	"OM": "143562",
	"PA": "143485",
	"PE": "143507",
	"PH": "143474",
	"PK": "143477",
	"PL": "143478",
	"PT": "143453",
	"PY": "143513",
	"QA": "143498",
	"RO": "143487",
	"RS": "143500",
	"RU": "143469",
	"SA": "143479",
	"SE": "143456",
	"SG": "143464",
	"SI": "143499",
	"SK": "143496",
	"SN": "143535",
	"SR": "143554",
	"SV": "143506",
	"TC": "143552",
	"TH": "143475",
	"TN": "143536",
	"TR": "143480",
	"TT": "143551",
	"TW": "143470",
	"TZ": "143572",
	"UA": "143492",
	"UG": "143537",
	"US": "143441",
	"UY": "143514",
	"UZ": "143566",
	"VC": "143550",
	"VE": "143502",
	"VG": "143543",
	"VN": "143471",
	"YE": "143571",
	"ZA": "143472",
}
