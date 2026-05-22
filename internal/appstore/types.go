package appstore

import "errors"

type Account struct {
	Email               string `json:"email"`
	PasswordToken       string `json:"passwordToken"`
	DirectoryServicesID string `json:"directoryServicesIdentifier"`
	StoreFront          string `json:"storeFront"`
	Password            string `json:"password"`
	Pod                 string `json:"pod"`
	Name                string `json:"name"`
}

type App struct {
	ID       int64   `json:"trackId,omitempty"`
	BundleID string  `json:"bundleId,omitempty"`
	Name     string  `json:"trackName,omitempty"`
	Version  string  `json:"version,omitempty"`
	Price    float64 `json:"price,omitempty"`
}

type Sinf struct {
	ID   int64  `plist:"id,omitempty"`
	Data []byte `plist:"sinf,omitempty"`
}

const (
	failureInvalidCredentials       = "-5000"
	failurePasswordTokenExpired     = "2034"
	failureSignInRequired           = "2042"
	failureLicenseNotFound          = "9610"
	failureTemporarilyUnavailable   = "2059"
	failureLicenseAlreadyExists     = "5002"
	failureDeviceVerificationFailed = "1008"

	custMsgBadLogin             = "MZFinance.BadLogin.Configurator_message"
	custMsgAccountDisabled      = "Your account is disabled."
	custMsgSubscriptionRequired = "Subscription Required"
	custMsgPasswordChanged      = "Your password has changed."
)

const (
	iTunesDomain = "itunes.apple.com"
	lookupPath   = "/lookup"

	initDomain = "init." + iTunesDomain
	initPath   = "/bag.xml"

	storeDomain  = "buy." + iTunesDomain
	purchasePath = "/WebObjects/MZFinance.woa/wa/buyProduct"
	downloadPath = "/WebObjects/MZFinance.woa/wa/volumeStoreDownloadProduct"
	authURL      = "https://buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/authenticate"

	hdrStoreFront = "X-Set-Apple-Store-Front"
	hdrPod        = "pod"

	pricingAppStore    = "STDQ"
	pricingAppleArcade = "GAME"

	defaultUserAgent = "Configurator/2.17 (Macintosh; OS X 15.2; 24C5089c) AppleWebKit/0620.1.16.11.6"
)

var (
	ErrAuthCodeRequired       = errors.New("auth code required")
	ErrPasswordTokenExpired   = errors.New("password token expired")
	ErrLicenseRequired        = errors.New("license required")
	ErrLicenseAlreadyExists   = errors.New("license already exists")
	ErrSubscriptionRequired   = errors.New("subscription required")
	ErrTemporarilyUnavailable = errors.New("temporarily unavailable")
)
