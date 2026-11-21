package appstore

import (
	"archive/zip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	apphttp "github.com/londek/ipadecrypt/internal/apphttp"
	"howett.net/plist"
)

type DownloadOutput struct {
	DestinationPath string
	Sinfs           []Sinf
}

// DownloadTicket is an App-Store-authorized download: the signed CDN URL to
// fetch, the per-file sinf licensing blobs, and the response metadata.
// PrepareDownload returns one; hand it to CompleteDownload to pull the bytes.
// No bytes move until CompleteDownload runs, so the caller can look at the
// ticket and decide whether it's worth fetching.
type DownloadTicket struct {
	URL       string
	Sinfs     []Sinf
	Metadata  map[string]any
	AssetInfo map[string]any

	// validatePlatform is set when the response came from a path that resolves
	// the iPhone platform, so the package's Info.plist is checked.
	validatePlatform bool
}

// Version returns CFBundleShortVersionString ("1.54.0") - the human-readable
// version of the specific release this ticket describes. Empty if absent.
func (t DownloadTicket) Version() string {
	return metaString(t.Metadata, "bundleShortVersionString")
}

// FileSize returns the IPA download size in bytes as reported by the
// response (asset-info.file-size). 0 if unknown.
func (t DownloadTicket) FileSize() int64 {
	if v, ok := t.AssetInfo["file-size"]; ok {
		switch n := v.(type) {
		case int64:
			return n
		case uint64:
			return int64(n)
		case int:
			return int64(n)
		}
	}

	return 0
}

func metaString(m map[string]any, key string) string {
	if v, ok := m[key]; ok {
		return fmt.Sprintf("%v", v)
	}

	return ""
}

// metaIntSlice reads a []any of numeric values from the metadata map and
// returns them as []int. plist decoding yields int64/uint64/float64, hence
// the type switch.
func metaIntSlice(m map[string]any, key string) []int {
	v, ok := m[key]
	if !ok {
		return nil
	}

	arr, ok := v.([]any)
	if !ok {
		return nil
	}

	out := make([]int, 0, len(arr))
	for _, e := range arr {
		switch n := e.(type) {
		case int:
			out = append(out, n)
		case int64:
			out = append(out, int(n))
		case uint64:
			out = append(out, int(n))
		case float64:
			out = append(out, int(n))
		}
	}

	return out
}

type downloadItem struct {
	URL       string         `plist:"URL,omitempty"`
	Sinfs     []Sinf         `plist:"sinfs,omitempty"`
	Metadata  map[string]any `plist:"metadata,omitempty"`
	AssetInfo map[string]any `plist:"asset-info,omitempty"`

	validatePlatform bool
}

type downloadResult struct {
	FailureType     string         `plist:"failureType,omitempty"`
	CustomerMessage string         `plist:"customerMessage,omitempty"`
	Dialog          map[string]any `plist:"dialog,omitempty"`
	Metrics         map[string]any `plist:"metrics,omitempty"`
	Items           []downloadItem `plist:"songList,omitempty"`
}

// PrepareDownload authorizes a download with Apple and returns a ticket
// describing the specific release that will be fetched (URL, sinfs, metadata,
// asset info). No bytes are transferred. Callers can inspect
// ticket.Version(), ticket.FileSize() etc. and then hand the ticket to
// CompleteDownload - or drop it if the version turns out to already be cached.
//
// On ErrPasswordTokenExpired the caller must re-Login and retry.
// On ErrLicenseRequired the caller must Purchase and retry.
func (c *Client) PrepareDownload(acc *Account, app App, externalVersionID string) (DownloadTicket, error) {
	res, validatePlatform, err := c.volumeDownload(acc, app, externalVersionID)
	if err != nil {
		return DownloadTicket{}, err
	}

	item, err := classifyDownload(res.Data, failurePasswordTokenExpired, failureSignInRequired, failureDeviceVerificationFailed, failureLicenseAlreadyExists)
	if err != nil {
		return DownloadTicket{}, err
	}

	item.validatePlatform = validatePlatform

	return DownloadTicket(item), nil
}

// classifyDownload interprets a download-product response: its first item or
// an error. expiredFailures are the failure types that mean re-Login.
func classifyDownload(res downloadResult, expiredFailures ...string) (downloadItem, error) {
	switch {
	case slices.Contains(expiredFailures, res.FailureType):
		return downloadItem{}, ErrPasswordTokenExpired
	case res.FailureType == failureLicenseNotFound:
		return downloadItem{}, ErrLicenseRequired
	case res.CustomerMessage != "" && (res.FailureType != "" || len(res.Items) == 0):
		return downloadItem{}, errors.New(res.CustomerMessage)
	case res.FailureType != "":
		return downloadItem{}, fmt.Errorf("download: %s", res.FailureType)
	case len(res.Items) == 0:
		return downloadItem{}, errors.New("download: empty songList")
	}

	return res.Items[0], nil
}

// volumeDownload authorizes a download (or a metadata-only lookup). It
// prefers ent/download, then the per-pod volumeStore endpoint, and when that
// returns an empty or "no longer available" response falls back to the bag's
// redownload and update endpoints. validatePlatform reports whether the
// response came from a path that resolves the iPhone platform. Used by
// PrepareDownload, ListVersions and GetVersionMetadata - the request shape is
// identical, externalVersionID decides what comes back.
func (c *Client) volumeDownload(acc *Account, app App, externalVersionID string) (apphttp.Result[downloadResult], bool, error) {
	g, err := guid()
	if err != nil {
		return apphttp.Result[downloadResult]{}, false, err
	}

	// Keep the fetched bag for the legacy chain if ent/download cannot serve the
	// requested app; asset, network, and response failures can fall back.
	var bag *urlBag

	if fetched, err := c.fetchURLBag(); err == nil {
		bag = &fetched
		if bag.EntDownloadEndpoint != "" {
			res, err := c.entDownload(bag.EntDownloadEndpoint, acc, app, g, externalVersionID)
			if err == nil {
				return res, true, nil
			}

			debugf("ent/download unavailable, falling back to volumeStore: %v", err)
		}
	}

	res, err := c.postDownloadProduct(context.Background(), podVolumeStoreURL(acc), downloadVersionKeyVolumeStore, acc, app, g, externalVersionID)
	if err != nil {
		return res, false, fmt.Errorf("download: %w", err)
	}

	if !isEmptyDownload(res) && !isUnavailableDownload(res) {
		return res, false, nil
	}

	// Try redownload when volumeStore returns no items, either silently or
	// with the message-only "No Longer Available" response.
	if bag == nil {
		fetched, err := c.fetchURLBag()
		if err != nil {
			return res, false, fmt.Errorf("download: bag for fallback: %w", err)
		}

		bag = &fetched
	}

	if bag.RedownloadEndpoint == "" {
		return res, false, nil
	}

	redownloadURL, err := downloadDispatchURL(bag.RedownloadEndpoint, redownloadProductPath)
	if err != nil {
		return res, false, err
	}

	validatePlatform := false

	if externalVersionID == "" {
		// Unpinned redownloads can fail or return another platform's package.
		// Select the current iOS build when the catalog has an offer.
		validatePlatform = true

		externalVersionID, err = c.lookupLatestExternalVersionID(acc, app)
		if errors.Is(err, errCatalogAppNotFound) {
			// A delisted app can still be available to this account. Neither
			// recovery endpoint needs a catalog version to select its entitled build.
			res, err := c.sendDelistedDownload(redownloadURL, bag.EntDownloadEndpoint, acc, app, g)

			return res, true, err
		}

		if err != nil {
			return res, true, fmt.Errorf("download: resolve latest version for redownload: %w", err)
		}

		debugf("fallback resolved externalVersionID=%q for app %d (%s)", externalVersionID, app.ID, app.BundleID)
	}

	redownloadRes, err := c.postDownloadProduct(context.Background(), redownloadURL, downloadVersionKeyRedownload, acc, app, g, externalVersionID)
	// ipatool parity: the update endpoint only helps when redownload came back as
	// an empty HTTP 500 or a message-only "no longer available" response.
	if bag.UpdateEndpoint != "" && externalVersionID != "" &&
		(isEmptyRedownloadError(err) || (err == nil && isUnavailableDownload(redownloadRes))) {
		updateRes, updateErr := c.sendUpdateProduct(bag.UpdateEndpoint, acc, app, g, externalVersionID)

		return updateRes, validatePlatform || updateErr == nil, updateErr
	}

	if isForbidden(redownloadRes, err) {
		return redownloadRes, validatePlatform, ErrModernDownloadUnsupported
	}

	if err != nil {
		return redownloadRes, validatePlatform, fmt.Errorf("download: redownload request: %w", err)
	}

	return redownloadRes, validatePlatform, nil
}

// sendDelistedDownload recovers an app the catalog no longer lists but the
// account may still own: an unpinned redownload goes first, then an unpinned
// ent/download.
func (c *Client) sendDelistedDownload(redownloadURL, entEndpoint string, acc *Account, app App, g string) (apphttp.Result[downloadResult], error) {
	res, err := c.sendUnpinnedRedownload(redownloadURL, acc, app, g)
	if err == nil && res.Data.FailureType != failureLicenseNotFound {
		return res, nil
	}

	if entEndpoint == "" {
		return res, err
	}

	endpoint, endpointErr := downloadDispatchURL(entEndpoint, entDownloadPath)
	if endpointErr != nil {
		return res, errors.Join(err, endpointErr)
	}

	// Bypass catalog discovery: it already confirmed that there is no offer.
	// CompleteDownload still checks the returned package's platform.
	entRes, entErr := c.sendEntDownload(endpoint, acc, app, g, "")
	if entErr == nil || entRes.Data.FailureType == failurePasswordTokenExpired ||
		entRes.Data.FailureType == failureLicenseNotFound {
		return entRes, nil
	}

	if res.Data.FailureType == failureLicenseNotFound {
		return res, nil
	}

	return entRes, fmt.Errorf("download: app %d has no catalog offer and the ent/download fallback failed: %w", app.ID, errors.Join(err, entErr))
}

// sendUnpinnedRedownload lets the redownload endpoint pick the entitled build.
func (c *Client) sendUnpinnedRedownload(endpoint string, acc *Account, app App, g string) (apphttp.Result[downloadResult], error) {
	ctx, cancel := context.WithTimeout(context.Background(), apphttp.DefaultAuthenticationTimeout)
	defer cancel()

	res, err := c.postDownloadProduct(ctx, endpoint, downloadVersionKeyRedownload, acc, app, g, "")
	if err != nil {
		return res, fmt.Errorf("download: redownload request: %w", err)
	}

	res.Data = normalizeDownloadFailure(res.Data)

	if err := validateVersionedDownload(res, app, "", "redownload"); err != nil {
		return res, err
	}

	if res.Data.FailureType == "" && res.Data.Items[0].URL == "" {
		return res, errors.New("download: redownload response has no package URL")
	}

	return res, nil
}

// normalizeDownloadFailure maps the failure shapes the redownload and
// ent/download endpoints use to the standard failure codes.
func normalizeDownloadFailure(data downloadResult) downloadResult {
	if len(data.Items) == 0 && data.FailureType == "" && data.Metrics["messageCode"] != nil {
		data.FailureType = strings.TrimSpace(fmt.Sprint(data.Metrics["messageCode"]))
	}

	if data.FailureType == failureSignInRequired || data.FailureType == failureDeviceVerificationFailed {
		data.FailureType = failurePasswordTokenExpired
	}

	if len(data.Items) > 0 {
		return data
	}

	message := strings.Join(strings.Fields(data.CustomerMessage), " ")
	if strings.EqualFold(message, "sign in to the itunes store") || strings.EqualFold(message, "sign-in required") {
		data.FailureType = failurePasswordTokenExpired
	}

	if data.FailureType == failurePasswordTokenExpired {
		return data
	}

	const unavailable = "Redownload Unavailable with This Apple Account"

	dialogMessage, _ := data.Dialog["message"].(string)
	dialogExplanation, _ := data.Dialog["explanation"].(string)

	if message == unavailable ||
		(strings.Join(strings.Fields(dialogMessage), " ") == unavailable &&
			strings.Join(strings.Fields(dialogExplanation), " ") == "This redownload is not available for this Apple Account either because it was bought by a different user or the item was refunded or cancelled.") {
		data.FailureType = failureLicenseNotFound
	}

	return data
}

// isEmptyRedownloadError reports the empty non-plist HTTP 500 redownload
// answers with when a version must be fetched through updateProduct.
func isEmptyRedownloadError(err error) bool {
	var unexpected *apphttp.UnexpectedResponseError

	return errors.As(err, &unexpected) &&
		unexpected.StatusCode == http.StatusInternalServerError && unexpected.Snippet == ""
}

// sendUpdateProduct requests a pinned version from the bag's updateProduct
// endpoint.
func (c *Client) sendUpdateProduct(endpoint string, acc *Account, app App, g, externalVersionID string) (apphttp.Result[downloadResult], error) {
	update, err := downloadDispatchURL(endpoint, updateProductPath)
	if err != nil {
		return apphttp.Result[downloadResult]{}, err
	}

	res, err := c.postDownloadProduct(context.Background(), update, downloadVersionKeyRedownload, acc, app, g, externalVersionID)
	if isForbidden(res, err) {
		return res, ErrModernDownloadUnsupported
	}

	if err != nil {
		return res, fmt.Errorf("download: update request: %w", err)
	}

	return res, validateVersionedDownload(res, app, externalVersionID, "update")
}

// isForbidden reports a 403 from the download-dispatch endpoints, whether it
// came with a plist body or as an empty/non-plist UnexpectedResponseError.
func isForbidden(res apphttp.Result[downloadResult], err error) bool {
	var unexpected *apphttp.UnexpectedResponseError

	return res.StatusCode == http.StatusForbidden ||
		errors.As(err, &unexpected) && unexpected.StatusCode == http.StatusForbidden
}

// postDownloadProduct sends a single download-product POST to a fully-formed
// endpoint. ctx bounds the request and its Store AMD proof.
func (c *Client) postDownloadProduct(ctx context.Context, baseURL, versionKey string, acc *Account, app App, g, externalVersionID string) (apphttp.Result[downloadResult], error) {
	request := downloadProductRequest(baseURL, versionKey, acc, app, g, externalVersionID)
	request.Context = ctx

	res, err := c.sendCommerce(ctx, request, g)
	if err != nil {
		debugf("downloadProduct %s key=%s ver=%q: send error: %v", baseURL, versionKey, externalVersionID, err)
		return res, err
	}

	debugf("downloadProduct %s key=%s ver=%q: status=%d failureType=%q customerMessage=%q items=%d",
		baseURL, versionKey, externalVersionID, res.StatusCode, res.Data.FailureType, res.Data.CustomerMessage, len(res.Data.Items))

	return res, nil
}

// downloadProductRequest builds a download-product request that never follows
// redirects.
func downloadProductRequest(baseURL, versionKey string, acc *Account, app App, g, externalVersionID string) apphttp.Request {
	payload := map[string]any{
		"creditDisplay": "",
		"guid":          g,
		"salableAdamId": app.ID,
		"serialNumber":  "0",
	}
	if externalVersionID != "" {
		payload[versionKey] = externalVersionID
	}

	return apphttp.Request{
		URL:            fmt.Sprintf("%s?guid=%s", baseURL, g),
		Method:         http.MethodPost,
		ResponseFormat: apphttp.ResponseFormatXML,
		NoRedirects:    true,
		Headers: map[string]string{
			"Content-Type":        "application/x-apple-plist",
			"User-Agent":          storeUserAgent,
			"iCloud-DSID":         acc.DirectoryServicesID,
			"X-Apple-Store-Front": acc.StoreFront,
			"X-Dsid":              acc.DirectoryServicesID,
			"X-Token":             acc.PasswordToken,
		},
		Payload: &apphttp.XMLPayload{Content: payload},
	}
}

// validateVersionedDownload confirms a successful response matches the
// requested app and, when pinned, version, guarding against the endpoint
// returning a different build or platform. An empty externalVersionID lets the
// server select a version while retaining the app identity checks.
func validateVersionedDownload(res apphttp.Result[downloadResult], app App, externalVersionID, source string) error {
	if res.Data.FailureType != "" {
		return nil
	}

	if res.Data.CustomerMessage != "" {
		return fmt.Errorf("download: %s: %s", source, res.Data.CustomerMessage)
	}

	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("download: %s: status %d", source, res.StatusCode)
	}

	if len(res.Data.Items) != 1 {
		return fmt.Errorf("download: %s response must contain exactly one item", source)
	}

	meta := res.Data.Items[0].Metadata
	if metaString(meta, "itemId") != fmt.Sprint(app.ID) ||
		(externalVersionID != "" && metaString(meta, "softwareVersionExternalIdentifier") != externalVersionID) {
		return fmt.Errorf("download: %s response does not match the requested app or version", source)
	}

	bundleID, ok := meta["softwareVersionBundleId"].(string)
	if !ok || bundleID == "" || (app.BundleID != "" && bundleID != app.BundleID) {
		return fmt.Errorf("download: %s response does not match the requested bundle identifier", source)
	}

	return nil
}

// downloadDispatchURL validates a bag-provided download-dispatch endpoint: it
// must be an exact https://downloaddispatch.itunes.apple.com URL on the
// expected path with no query, fragment or userinfo.
func downloadDispatchURL(endpoint, path string) (string, error) {
	parsed, err := url.ParseRequestURI(endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.Host != downloadDispatchDomain ||
		parsed.Path != path || parsed.RawPath != "" || parsed.RawQuery != "" ||
		parsed.ForceQuery || parsed.Fragment != "" || parsed.User != nil {
		return "", fmt.Errorf("download: invalid %s endpoint in bag", path)
	}

	return endpoint, nil
}

// isUnavailableDownload reports the message-only "no longer available" response
// Apple returns on HTTP 200 with no failure and no items. Mirrors ipatool's
// isUnavailableDownloadProductResponse.
func isUnavailableDownload(res apphttp.Result[downloadResult]) bool {
	msg := strings.ToLower(strings.TrimSpace(res.Data.CustomerMessage))

	return res.StatusCode == http.StatusOK &&
		res.Data.FailureType == "" && len(res.Data.Items) == 0 &&
		(msg == "no longer available" || strings.HasSuffix(msg, " no longer available"))
}

func isEmptyDownload(res apphttp.Result[downloadResult]) bool {
	return res.StatusCode == http.StatusOK &&
		res.Data.FailureType == "" &&
		res.Data.CustomerMessage == "" &&
		len(res.Data.Items) == 0
}

func podVolumeStoreURL(acc *Account) string {
	podPrefix := ""
	if acc.Pod != "" {
		podPrefix = "p" + acc.Pod + "-"
	}

	return fmt.Sprintf("https://%s%s%s", podPrefix, storeDomain, downloadPath)
}

// CompleteDownload fetches the IPA described by `ticket` into outPath.
// If onProgress is non-nil it is called periodically (throttled to
// ~100ms) during the CDN fetch with the running byte count and
// the download's total size.
func (c *Client) CompleteDownload(acc *Account, ticket DownloadTicket, outPath string, onProgress func(cur, total int64)) (DownloadOutput, error) {
	if outPath == "" {
		return DownloadOutput{}, errors.New("download: outPath is required (must be a file path)")
	}

	info, err := os.Stat(outPath)
	if err != nil && !os.IsNotExist(err) {
		return DownloadOutput{}, fmt.Errorf("download: stat outPath: %w", err)
	}

	if err == nil && info.IsDir() {
		return DownloadOutput{}, fmt.Errorf("download: outPath %q is a directory; CompleteDownload expects a file path", outPath)
	}

	item := downloadItem(ticket)

	tmp := outPath + ".tmp"
	if err := c.fetchToFile(item.URL, tmp, onProgress); err != nil {
		return DownloadOutput{}, err
	}

	if onProgress != nil && ticket.FileSize() > 0 {
		onProgress(ticket.FileSize(), ticket.FileSize())
	}

	if item.validatePlatform {
		if err := validatePackagePlatform(tmp); err != nil {
			if removeErr := os.Remove(tmp); removeErr != nil {
				err = errors.Join(err, fmt.Errorf("remove tmp: %w", removeErr))
			}

			return DownloadOutput{}, fmt.Errorf("validate package platform: %w", err)
		}
	}

	if err := applyPatches(tmp, outPath, item, acc); err != nil {
		return DownloadOutput{}, err
	}

	if err := os.Remove(tmp); err != nil {
		return DownloadOutput{}, fmt.Errorf("remove tmp: %w", err)
	}

	return DownloadOutput{DestinationPath: outPath, Sinfs: item.Sinfs}, nil
}

// FetchPackage reuses the Store CDN transfer and resume logic for a package.
func (c *Client) FetchPackage(src, dst string, onProgress func(cur, total int64)) error {
	return c.fetchToFile(src, dst, onProgress)
}

// PatchPackage injects the account metadata and licensing from an authorized ticket.
func PatchPackage(src, dst string, ticket DownloadTicket, acc *Account) error {
	return applyPatches(src, dst, downloadItem(ticket), acc)
}

type platformPackageInfo struct {
	SupportedPlatforms []string `plist:"CFBundleSupportedPlatforms,omitempty"`
}

// validatePackagePlatform requires a top-level app Info.plist to declare
// iPhoneOS support.
func validatePackagePlatform(path string) error {
	const expectedPlatform = "iPhoneOS"

	zr, err := zip.OpenReader(path)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}

	defer zr.Close()

	registerAppleZIPDecompressor(&zr.Reader)

	for _, f := range zr.File {
		if !isTopLevelAppInfoPlist(f.Name) {
			continue
		}

		rc, err := f.Open()
		if err != nil {
			return fmt.Errorf("open Info.plist: %w", err)
		}

		data, readErr := io.ReadAll(rc)
		closeErr := rc.Close()

		if readErr != nil {
			return fmt.Errorf("read Info.plist: %w", readErr)
		}

		if closeErr != nil {
			return fmt.Errorf("close Info.plist: %w", closeErr)
		}

		var info platformPackageInfo
		if _, err := plist.Unmarshal(data, &info); err != nil {
			return fmt.Errorf("parse Info.plist: %w", err)
		}

		// Legacy iOS apps may predate CFBundleSupportedPlatforms. Only a
		// missing declaration qualifies; an empty or conflicting one does not.
		if info.SupportedPlatforms == nil || slices.Contains(info.SupportedPlatforms, expectedPlatform) {
			return nil
		}
	}

	return fmt.Errorf("downloaded package does not declare %s support", expectedPlatform)
}

func isTopLevelAppInfoPlist(path string) bool {
	parts := strings.Split(path, "/")

	return len(parts) == 3 && parts[0] == "Payload" && strings.HasSuffix(parts[1], ".app") && parts[2] == "Info.plist"
}

// transferClient fetches CDN bytes through the Store backend's transfer
// executor.
func (c *Client) transferClient() apphttp.Client[any] {
	return apphttp.NewClient[any](apphttp.Args{CookieJar: c.jar, Executor: c.backend.Client("transfer")})
}

// fetchToFile downloads src into dst, resuming a partial dst. Large files are
// fetched over several connections; if that fails it retries on one
// connection, resuming the contiguous prefix already written.
func (c *Client) fetchToFile(src, dst string, onProgress func(cur, total int64)) error {
	err := c.fetchToFileAttempt(src, dst, onProgress, true, "")

	var parallelErr *parallelDownloadError
	if !errors.As(err, &parallelErr) {
		return err
	}

	if fallbackErr := c.fetchToFileAttempt(src, dst, onProgress, false, parallelErr.validator); fallbackErr != nil {
		return errors.Join(err, fmt.Errorf("single-connection fallback: %w", fallbackErr))
	}

	return nil
}

func (c *Client) fetchToFileAttempt(src, dst string, onProgress func(cur, total int64), parallel bool, validator string) (err error) {
	client := c.transferClient()

	req, err := client.NewRequest(http.MethodGet, src, nil)
	if err != nil {
		return err
	}

	// Staged ranges are expendable; only the contiguous destination is resumed.
	if err := os.RemoveAll(downloadPartsPath(dst)); err != nil {
		return fmt.Errorf("remove %s: %w", downloadPartsPath(dst), err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	req = req.WithContext(ctx)
	req.Header.Set("Accept-Encoding", "identity")

	if validator != "" {
		req.Header.Set("If-Range", validator)
	}

	f, err := os.OpenFile(dst, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return fmt.Errorf("open %s: %w", dst, err)
	}

	defer func() {
		if closeErr := f.Close(); closeErr != nil {
			err = joinCleanupError(err, "close "+dst, closeErr)
		}
	}()

	stat, err := os.Stat(dst)
	if err != nil {
		return fmt.Errorf("stat %s: %w", dst, err)
	}

	req.Header.Set("Range", fmt.Sprintf("bytes=%d-", stat.Size()))

	res, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("fetch: %w", err)
	}

	defer res.Body.Close()

	offset, remaining, total, complete, err := downloadResponseRange(res, stat.Size())
	if err != nil {
		return err
	}

	if complete {
		return nil
	}

	if res.StatusCode == http.StatusOK {
		if err := f.Truncate(0); err != nil {
			return fmt.Errorf("truncate %s: %w", dst, err)
		}
	}

	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return fmt.Errorf("seek %s: %w", dst, err)
	}

	var (
		w        io.Writer = f
		progress io.Writer
	)

	if onProgress != nil {
		progress = &progressWriter{total: total, written: offset, onProgress: onProgress}
		w = io.MultiWriter(f, progress)
	}

	// Combining responses requires a strong validator to keep all ranges on
	// the same representation. Servers without one retain the single stream.
	if parallel && res.StatusCode == http.StatusPartialContent &&
		remaining == total-offset && remaining >= parallelDownloadThreshold && downloadValidator(res) != "" {
		if err := downloadFileParallel(ctx, cancel, client, src, dst, f, w, res, offset, total, progress); err != nil {
			return &parallelDownloadError{err: err, validator: downloadValidator(res)}
		}

		return nil
	}

	var body io.Reader = res.Body
	if remaining >= 0 {
		body = io.LimitReader(body, remaining)
	}

	written, err := io.Copy(w, body)
	if err != nil {
		return fmt.Errorf("write %s: %w", dst, err)
	}

	if remaining >= 0 && written != remaining || total >= 0 && offset+written != total {
		return fmt.Errorf("write %s: %w", dst, io.ErrUnexpectedEOF)
	}

	return nil
}

// downloadResponseRange validates the response before any partial bytes
// change. It returns the write offset, remaining bytes, total size, and
// completion state.
func downloadResponseRange(res *http.Response, localSize int64) (int64, int64, int64, bool, error) {
	switch res.StatusCode {
	case http.StatusOK:
		return 0, res.ContentLength, res.ContentLength, false, nil
	case http.StatusRequestedRangeNotSatisfiable:
		value, found := strings.CutPrefix(res.Header.Get("Content-Range"), "bytes */")
		size, parseErr := strconv.ParseInt(value, 10, 64)

		if found && parseErr == nil && size >= 0 && size == localSize {
			return localSize, 0, size, true, nil
		}

		return 0, 0, 0, false, fmt.Errorf("fetch: local size %d does not match server range %q", localSize, res.Header.Get("Content-Range"))
	case http.StatusPartialContent:
		header := res.Header.Get("Content-Range")
		value, found := strings.CutPrefix(header, "bytes ")
		bounds, totalText, hasTotal := strings.Cut(value, "/")
		startText, endText, hasEnd := strings.Cut(bounds, "-")
		start, startErr := strconv.ParseInt(startText, 10, 64)
		end, endErr := strconv.ParseInt(endText, 10, 64)
		size, sizeErr := strconv.ParseInt(totalText, 10, 64)

		if !found || !hasTotal || !hasEnd || startErr != nil || endErr != nil || sizeErr != nil || start != localSize || start < 0 || end < start || size <= end {
			return 0, 0, 0, false, fmt.Errorf("fetch: invalid content range %q for local size %d", header, localSize)
		}

		length := end - start + 1
		if res.ContentLength >= 0 && res.ContentLength != length {
			return 0, 0, 0, false, fmt.Errorf("fetch: content length %d does not match range length %d", res.ContentLength, length)
		}

		return start, length, size, false, nil
	default:
		return 0, 0, 0, false, fmt.Errorf("fetch: status %d", res.StatusCode)
	}
}

// progressWriter counts bytes written and invokes onProgress at most
// once every 100ms. It is shared by parallel range downloads, so it is
// safe for concurrent use. Callers are expected to emit the final count
// themselves after the download returns.
type progressWriter struct {
	mu         sync.Mutex
	total      int64
	written    int64
	last       time.Time
	onProgress func(cur, total int64)
}

func (p *progressWriter) Write(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.written += int64(len(b))

	now := time.Now()
	if now.Sub(p.last) >= 100*time.Millisecond {
		p.last = now
		p.onProgress(p.written, p.total)
	}

	return len(b), nil
}

// applyPatches rebuilds src into dst with iTunesMetadata.plist injected and
// sinfs replicated into either manifest-listed paths or the SC_Info fallback.
func applyPatches(src, dst string, item downloadItem, acc *Account) (err error) {
	zr, err := zip.OpenReader(src)
	if err != nil {
		return fmt.Errorf("open %s: %w", src, err)
	}

	defer zr.Close()

	registerAppleZIPDecompressor(&zr.Reader)

	df, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("open %s: %w", dst, err)
	}

	defer func() {
		if closeErr := df.Close(); closeErr != nil {
			err = joinCleanupError(err, "close "+dst, closeErr)
		}
	}()

	zw := zip.NewWriter(df)

	defer func() {
		if closeErr := zw.Close(); closeErr != nil {
			err = joinCleanupError(err, "close zip", closeErr)
		}
	}()

	if err := replicateZip(zr, zw, src); err != nil {
		return err
	}

	if err := writeMetadataEntry(zw, item.Metadata, acc); err != nil {
		return err
	}

	// Device-based downloads can omit sinfs even when the package has a
	// manifest. Preserve the archive rewrite, but only inject supplied data.
	if len(item.Sinfs) == 0 {
		return nil
	}

	bundleName, err := readBundleName(zr)
	if err != nil {
		return err
	}

	manifest, err := readManifest(zr)
	if err != nil {
		return err
	}

	info, err := readInfo(zr)
	if err != nil {
		return err
	}

	if manifest != nil {
		if len(item.Sinfs) != len(manifest.SinfPaths) {
			return fmt.Errorf("sinf count mismatch: have %d, manifest wants %d", len(item.Sinfs), len(manifest.SinfPaths))
		}

		for i, p := range manifest.SinfPaths {
			entry := fmt.Sprintf("Payload/%s.app/%s", bundleName, p)
			if err := writeEntry(zw, entry, item.Sinfs[i].Data); err != nil {
				return err
			}
		}
	} else {
		entry := fmt.Sprintf("Payload/%s.app/SC_Info/%s.sinf", bundleName, info.BundleExecutable)
		if err := writeEntry(zw, entry, item.Sinfs[0].Data); err != nil {
			return err
		}
	}

	return nil
}

func joinCleanupError(err error, message string, cleanupErr error) error {
	wrapped := fmt.Errorf("%s: %w", message, cleanupErr)
	if err == nil {
		return wrapped
	}

	return errors.Join(err, wrapped)
}

// replicateZip copies every entry's compressed bytes and local-header extra
// verbatim.
func replicateZip(src *zip.ReadCloser, dst *zip.Writer, sourcePath string) error {
	if slices.ContainsFunc(src.File, func(file *zip.File) bool {
		return file.Method == appleLZFSEMethod
	}) {
		return replicateAppleZIP(src, dst)
	}

	source, err := os.Open(sourcePath)
	if err != nil {
		return fmt.Errorf("open %s: %w", sourcePath, err)
	}

	defer source.Close()

	info, err := source.Stat()
	if err != nil {
		return fmt.Errorf("stat %s: %w", sourcePath, err)
	}

	headers, err := newZIPLocalHeaders(source, info.Size())
	if err != nil {
		return fmt.Errorf("read zip directory: %w", err)
	}

	for _, file := range src.File {
		srcFile, err := file.OpenRaw()
		if err != nil {
			return err
		}

		header := file.FileHeader

		localExtra, err := headers.extra(file)
		if err != nil {
			return fmt.Errorf("read local header of %s: %w", file.Name, err)
		}

		header.Extra = zipStoredExtra(&header, localExtra)
		// Frame deflated files with a trailing descriptor for streaming
		// installers, without changing their compressed data or timestamps.
		// Stored files need inline sizes because they have no stream terminator.
		if strings.HasSuffix(header.Name, "/") || header.Method == zip.Store {
			header.Flags &^= 0x8
		} else if header.Method == zip.Deflate {
			header.Flags |= 0x8
		}

		w, err := dst.CreateRaw(&header)
		if err != nil {
			return err
		}

		// CreateRaw writes the local header immediately and retains this pointer
		// for the central directory written by Close. Keep the two extras distinct.
		header.Extra = zipExtraWithoutZIP64(file.Extra)

		if _, err := io.Copy(w, srcFile); err != nil {
			return err
		}
	}

	return nil
}

// replicateAppleZIP rewrites Apple's method-99 archives instead of copying
// their private local-header layout. All members are CRC-checked by archive/zip
// and emitted using standard Store or Deflate compression.
func replicateAppleZIP(src *zip.ReadCloser, dst *zip.Writer) error {
	for _, file := range src.File {
		r, err := file.Open()
		if err != nil {
			return err
		}

		header := file.FileHeader

		header.Extra = zipExtraWithoutZIP64(header.Extra)
		if strings.HasSuffix(header.Name, "/") {
			header.Method = zip.Store
		} else {
			header.Method = zip.Deflate
		}

		w, err := dst.CreateHeader(&header)
		if err != nil {
			_ = r.Close()

			return err
		}

		_, copyErr := io.Copy(w, r)
		closeErr := r.Close()

		if copyErr != nil {
			return copyErr
		}

		if closeErr != nil {
			return closeErr
		}
	}

	return nil
}

func writeEntry(zw *zip.Writer, name string, data []byte) error {
	w, err := zw.Create(name)
	if err != nil {
		return err
	}

	_, err = w.Write(data)

	return err
}

func writeMetadataEntry(zw *zip.Writer, metadata map[string]any, acc *Account) error {
	out := make(map[string]any, len(metadata)+2)
	for k, v := range metadata {
		out[k] = v
	}

	out["apple-id"] = acc.Email
	out["userName"] = acc.Email

	data, err := plist.Marshal(out, plist.BinaryFormat)
	if err != nil {
		return fmt.Errorf("marshal iTunesMetadata: %w", err)
	}

	return writeEntry(zw, "iTunesMetadata.plist", data)
}

type pkgManifest struct {
	SinfPaths []string `plist:"SinfPaths,omitempty"`
}

type pkgInfo struct {
	BundleExecutable string `plist:"CFBundleExecutable,omitempty"`
}

func readManifest(zr *zip.ReadCloser) (*pkgManifest, error) {
	for _, f := range zr.File {
		if !strings.HasSuffix(f.Name, ".app/SC_Info/Manifest.plist") {
			continue
		}

		data, err := readZipFile(f)
		if err != nil {
			return nil, err
		}

		var m pkgManifest
		if _, err := plist.Unmarshal(data, &m); err != nil {
			return nil, fmt.Errorf("parse Manifest.plist: %w", err)
		}

		return &m, nil
	}

	return nil, nil
}

func readInfo(zr *zip.ReadCloser) (*pkgInfo, error) {
	for _, f := range zr.File {
		if !strings.Contains(f.Name, ".app/Info.plist") {
			continue
		}

		data, err := readZipFile(f)
		if err != nil {
			return nil, err
		}

		var i pkgInfo
		if _, err := plist.Unmarshal(data, &i); err != nil {
			return nil, fmt.Errorf("parse Info.plist: %w", err)
		}

		return &i, nil
	}

	return nil, nil
}

func readBundleName(zr *zip.ReadCloser) (string, error) {
	for _, f := range zr.File {
		if strings.Contains(f.Name, ".app/Info.plist") && !strings.Contains(f.Name, "/Watch/") {
			return filepath.Base(strings.TrimSuffix(f.Name, ".app/Info.plist")), nil
		}
	}

	return "", errors.New("no .app/Info.plist in package")
}

func readZipFile(f *zip.File) ([]byte, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}

	defer rc.Close()

	return io.ReadAll(rc)
}
