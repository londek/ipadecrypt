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

	// Download fallback endpoints (bag-provided). Apple moved builds published
	// on/after 2026-09 off the per-pod volumeStore endpoint; those return an
	// empty songList and must be fetched via the bag's redownload/update paths.
	downloadDispatchDomain = "downloaddispatch." + iTunesDomain
	redownloadProductPath  = "/r/redownload"
	updateProductPath      = "/up/updateProduct"

	downloadVersionKeyVolumeStore = "externalVersionId"
	downloadVersionKeyRedownload  = "appExtVrsId"

	// PrivateAppStoreAPIPathAuth is the exact path Apple accepts for the signed
	// authenticate endpoint (optionally on a <pod>-buy.itunes.apple.com host).
	PrivateAppStoreAPIPathAuth = "/WebObjects/MZFinance.woa/wa/authenticate"

	PrivateAuthDomain     = "auth." + iTunesDomain
	PrivateAuthPathNative = "/auth/v1/native/fast/"

	hdrStoreFront = "X-Set-Apple-Store-Front"
	hdrPod        = "pod"

	supportedSAPVersion = 200

	pricingAppStore    = "STDQ"
	pricingAppleArcade = "GAME"
)

var (
	ErrAuthCodeRequired       = errors.New("auth code required")
	ErrPasswordTokenExpired   = errors.New("password token expired")
	ErrLicenseRequired        = errors.New("license required")
	ErrLicenseAlreadyExists   = errors.New("license already exists")
	ErrPaidAppNotOwned        = errors.New("account does not own this paid app")
	ErrSubscriptionRequired   = errors.New("subscription required")
	ErrTemporarilyUnavailable = errors.New("temporarily unavailable")

	// ErrModernDownloadUnsupported reports that Apple will only serve this app's
	// current build through the attested download-dispatch endpoints (they answer
	// HTTP 403 without device attestation), which ipadecrypt does not implement
	// yet. Older builds served by the legacy store endpoint, and local .ipa
	// files, are unaffected.
	ErrModernDownloadUnsupported = errors.New("this build needs App Store device attestation ipadecrypt does not implement yet")
)
