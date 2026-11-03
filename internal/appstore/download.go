package appstore

import (
	"archive/zip"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
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
}

type downloadResult struct {
	FailureType     string         `plist:"failureType,omitempty"`
	CustomerMessage string         `plist:"customerMessage,omitempty"`
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
	item, err := c.volumeDownload(acc, app, externalVersionID)
	if err != nil {
		return DownloadTicket{}, err
	}

	return DownloadTicket(item), nil
}

// volumeDownload authorizes a download (or a metadata-only lookup) and returns
// the chosen item. It tries the per-pod volumeStore endpoint first and, when
// that returns an empty songList or a "no longer available" response (Apple
// moved post-2026-09 builds off it), falls back to the bag's redownload and
// update endpoints. Used by PrepareDownload, ListVersions and
// GetVersionMetadata - the request shape is identical, externalVersionID
// decides what comes back.
func (c *Client) volumeDownload(acc *Account, app App, externalVersionID string) (downloadItem, error) {
	g, err := guid()
	if err != nil {
		return downloadItem{}, err
	}

	// Prefer the attested ent/download path (the one Apple's modern AMS framework
	// fully supports). Fall back to the legacy volumeStore chain when it is not
	// available for this account/app.
	if item, handled, entErr := c.entDownload(acc, app, g, externalVersionID); handled {
		return item, entErr
	}

	res, _, err := c.postDownloadProduct(podVolumeStoreURL(acc), downloadVersionKeyVolumeStore, acc, app, g, externalVersionID)
	if err != nil {
		return downloadItem{}, err
	}

	if item, decided, ferr := classifyDownload(res); decided {
		return item, ferr
	}

	return c.downloadProductFallback(acc, app, g, externalVersionID)
}

// downloadProductFallback runs after the legacy volumeStore endpoint returns an
// empty or unavailable response: it resolves the current external version id
// (when unpinned), retries against the bag's redownload endpoint, and finally
// the update endpoint.
func (c *Client) downloadProductFallback(acc *Account, app App, g, externalVersionID string) (downloadItem, error) {
	bag, err := c.fetchURLBag()
	if err != nil {
		return downloadItem{}, fmt.Errorf("download: bag for fallback: %w", err)
	}

	if bag.RedownloadEndpoint == "" {
		return downloadItem{}, errors.New("download: empty songList")
	}

	redownloadURL, err := downloadDispatchURL(bag.RedownloadEndpoint, redownloadProductPath)
	if err != nil {
		return downloadItem{}, err
	}

	if externalVersionID == "" {
		externalVersionID, err = c.lookupLatestExternalVersionID(acc, app)
		if err != nil {
			return downloadItem{}, fmt.Errorf("download: resolve latest version for redownload: %w", err)
		}

		debugf("fallback resolved externalVersionID=%q for app %d (%s)", externalVersionID, app.ID, app.BundleID)
	}

	redoRes, redoStatus, redoErr := c.postDownloadProduct(redownloadURL, downloadVersionKeyRedownload, acc, app, g, externalVersionID)
	if redoErr == nil {
		if redoStatus == http.StatusForbidden {
			return downloadItem{}, ErrModernDownloadUnsupported
		}

		if item, decided, ferr := classifyDownload(redoRes); decided {
			return item, ferr
		}
	}

	// ipatool parity: the update endpoint only helps when redownload came back as
	// an empty HTTP 500 or a message-only "no longer available" response.
	emptyServer := redoErr == nil && redoStatus == http.StatusInternalServerError
	unavailable := redoErr == nil && redoStatus == http.StatusOK && isUnavailableDownload(redoRes)

	if bag.UpdateEndpoint != "" && externalVersionID != "" && (emptyServer || unavailable) {
		updateURL, err := downloadDispatchURL(bag.UpdateEndpoint, updateProductPath)
		if err != nil {
			return downloadItem{}, err
		}

		updRes, updStatus, updErr := c.postDownloadProduct(updateURL, downloadVersionKeyRedownload, acc, app, g, externalVersionID)
		if updErr != nil {
			return downloadItem{}, fmt.Errorf("download: update request: %w", updErr)
		}

		if updStatus == http.StatusForbidden {
			return downloadItem{}, ErrModernDownloadUnsupported
		}

		if err := validateVersionedDownload(updRes, app, externalVersionID); err != nil {
			return downloadItem{}, err
		}

		if item, decided, ferr := classifyDownload(updRes); decided {
			return item, ferr
		}
	}

	if redoErr != nil {
		return downloadItem{}, fmt.Errorf("download: redownload request: %w", redoErr)
	}

	return downloadItem{}, errors.New("download: empty songList")
}

// isUnavailableDownload reports the message-only "no longer available" response
// Apple returns on HTTP 200 with no failure and no items. Mirrors ipatool's
// isUnavailableDownloadProductResponse.
func isUnavailableDownload(res downloadResult) bool {
	msg := strings.ToLower(strings.TrimSpace(res.CustomerMessage))

	return res.FailureType == "" && len(res.Items) == 0 &&
		(msg == "no longer available" || strings.HasSuffix(msg, " no longer available"))
}

// postDownloadProduct sends a single download-product POST to a fully-formed
// endpoint and returns the parsed response and its HTTP status. It errors only
// on transport or decode failures; emptiness, HTTP status and structured
// failures are left to the caller (the download-dispatch endpoints answer 403
// without device attestation and an empty 500 when a version must be updated).
func (c *Client) postDownloadProduct(baseURL, versionKey string, acc *Account, app App, g, externalVersionID string) (downloadResult, int, error) {
	payload := map[string]any{
		"creditDisplay": "",
		"guid":          g,
		"salableAdamId": app.ID,
		"serialNumber":  "0",
	}
	if externalVersionID != "" {
		payload[versionKey] = externalVersionID
	}

	headers := map[string]string{
		"Content-Type": "application/x-apple-plist",
		"iCloud-DSID":  acc.DirectoryServicesID,
		"X-Dsid":       acc.DirectoryServicesID,
	}

	var out downloadResult

	res, err := c.send("request", http.MethodPost, fmt.Sprintf("%s?guid=%s", baseURL, g), headers, &apphttp.XMLPayload{Content: payload}, nil, formatXML, &out)
	if err != nil {
		debugf("downloadProduct %s key=%s ver=%q: send error: %v", baseURL, versionKey, externalVersionID, err)
		return downloadResult{}, 0, fmt.Errorf("download: %w", err)
	}

	debugf("downloadProduct %s key=%s ver=%q: status=%d failureType=%q customerMessage=%q items=%d",
		baseURL, versionKey, externalVersionID, res.StatusCode, out.FailureType, out.CustomerMessage, len(out.Items))

	return out, res.StatusCode, nil
}

// classifyDownload interprets a download-product response. decided is false
// only for an empty or "no longer available" response, which signals the
// caller to fall back to another endpoint.
func classifyDownload(res downloadResult) (item downloadItem, decided bool, err error) {
	switch {
	case res.FailureType == failurePasswordTokenExpired,
		res.FailureType == failureSignInRequired,
		res.FailureType == failureDeviceVerificationFailed,
		res.FailureType == failureLicenseAlreadyExists:
		return downloadItem{}, true, ErrPasswordTokenExpired
	case res.FailureType == failureLicenseNotFound:
		return downloadItem{}, true, ErrLicenseRequired
	case res.FailureType != "" && res.CustomerMessage != "":
		return downloadItem{}, true, errors.New(res.CustomerMessage)
	case res.FailureType != "":
		return downloadItem{}, true, fmt.Errorf("download: %s", res.FailureType)
	case len(res.Items) > 0:
		return res.Items[0], true, nil
	}

	return downloadItem{}, false, nil
}

// validateVersionedDownload confirms a redownload/update response matches the
// requested app and pinned version, guarding against the endpoint returning a
// different build or platform.
func validateVersionedDownload(res downloadResult, app App, externalVersionID string) error {
	if res.FailureType != "" {
		return nil
	}

	if len(res.Items) != 1 {
		return errors.New("download: update response must contain exactly one item")
	}

	meta := res.Items[0].Metadata
	if metaString(meta, "itemId") != fmt.Sprint(app.ID) ||
		metaString(meta, "softwareVersionExternalIdentifier") != externalVersionID {
		return errors.New("download: update response does not match the requested app or version")
	}

	bundleID := metaString(meta, "softwareVersionBundleId")
	if bundleID == "" || (app.BundleID != "" && bundleID != app.BundleID) {
		return errors.New("download: update response does not match the requested bundle identifier")
	}

	return nil
}

func podVolumeStoreURL(acc *Account) string {
	podPrefix := ""
	if acc.Pod != "" {
		podPrefix = "p" + acc.Pod + "-"
	}

	return fmt.Sprintf("https://%s%s%s", podPrefix, storeDomain, downloadPath)
}

// downloadDispatchURL validates a bag-provided redownload/update endpoint:
// it must be an exact https://downloaddispatch.itunes.apple.com URL on the
// expected path with no query, fragment or userinfo.
func downloadDispatchURL(endpoint, path string) (string, error) {
	parsed, err := url.ParseRequestURI(endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.Host != downloadDispatchDomain ||
		parsed.Path != path || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.User != nil {
		return "", fmt.Errorf("download: invalid %s endpoint in bag", path)
	}

	return endpoint, nil
}

// CompleteDownload fetches the IPA described by `ticket` into outPath.
// If onProgress is non-nil it is called periodically (throttled to
// ~100ms) during the CDN fetch with the running byte count and
// ticket.FileSize() as the total.
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

	item := downloadItem{
		URL:      ticket.URL,
		Sinfs:    ticket.Sinfs,
		Metadata: ticket.Metadata,
	}

	tmp := outPath + ".tmp"
	if err := fetchToFile(c.http, item.URL, tmp, ticket.FileSize(), onProgress); err != nil {
		return DownloadOutput{}, err
	}

	if err := applyPatches(tmp, outPath, item, acc); err != nil {
		return DownloadOutput{}, err
	}

	if err := os.Remove(tmp); err != nil {
		return DownloadOutput{}, fmt.Errorf("remove tmp: %w", err)
	}

	return DownloadOutput{DestinationPath: outPath, Sinfs: item.Sinfs}, nil
}

func fetchToFile(hc *http.Client, url, dst string, total int64, onProgress func(cur, total int64)) error {
	f, err := os.OpenFile(dst, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return fmt.Errorf("open %s: %w", dst, err)
	}

	defer f.Close()

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}

	var resumeFrom int64
	if stat, err := f.Stat(); err == nil && stat.Size() > 0 {
		resumeFrom = stat.Size()
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-", resumeFrom))
	}

	res, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("fetch: %w", err)
	}

	defer res.Body.Close()

	switch {
	case resumeFrom > 0 && res.StatusCode == http.StatusPartialContent:
		if _, err := f.Seek(resumeFrom, io.SeekStart); err != nil {
			return fmt.Errorf("seek %s: %w", dst, err)
		}
	case res.StatusCode == http.StatusOK:
		if resumeFrom > 0 {
			if err := f.Truncate(0); err != nil {
				return fmt.Errorf("truncate %s: %w", dst, err)
			}

			if _, err := f.Seek(0, io.SeekStart); err != nil {
				return fmt.Errorf("seek %s: %w", dst, err)
			}

			resumeFrom = 0
		}
	default:
		return fmt.Errorf("fetch: status %d", res.StatusCode)
	}

	// Prefer the ticket-reported size when available; fall back to
	// Content-Length adjusted for any Range resume.
	if total <= 0 {
		if res.ContentLength > 0 {
			total = resumeFrom + res.ContentLength
		}
	}

	var w io.Writer = f
	if onProgress != nil {
		w = &progressWriter{w: f, total: total, written: resumeFrom, onProgress: onProgress}
	}

	if _, err := io.Copy(w, res.Body); err != nil {
		return fmt.Errorf("write %s: %w", dst, err)
	}

	if onProgress != nil && total > 0 {
		onProgress(total, total)
	}

	return nil
}

// progressWriter counts bytes written and invokes onProgress at most
// once every 100ms. Callers are expected to emit the final count
// themselves after io.Copy returns.
type progressWriter struct {
	w          io.Writer
	total      int64
	written    int64
	last       time.Time
	onProgress func(cur, total int64)
}

func (p *progressWriter) Write(b []byte) (int, error) {
	n, err := p.w.Write(b)
	p.written += int64(n)

	now := time.Now()
	if now.Sub(p.last) >= 100*time.Millisecond {
		p.last = now
		p.onProgress(p.written, p.total)
	}

	return n, err
}

// applyPatches rebuilds src into dst with iTunesMetadata.plist injected and
// sinfs replicated into either manifest-listed paths or the SC_Info fallback.
func applyPatches(src, dst string, item downloadItem, acc *Account) error {
	zr, err := zip.OpenReader(src)
	if err != nil {
		return fmt.Errorf("open %s: %w", src, err)
	}

	defer zr.Close()

	df, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("open %s: %w", dst, err)
	}

	defer df.Close()

	zw := zip.NewWriter(df)

	for _, f := range zr.File {
		if err := copyZipEntry(f, zw); err != nil {
			return err
		}
	}

	if err := writeMetadataEntry(zw, item.Metadata, acc); err != nil {
		return err
	}

	bundleName, err := readBundleName(zr)
	if err != nil {
		return err
	}

	manifest, err := readManifest(zr)
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
		info, err := readInfo(zr)
		if err != nil {
			return err
		}

		if info == nil {
			return errors.New("no Info.plist in package")
		}

		if len(item.Sinfs) == 0 {
			return errors.New("no sinfs in download response")
		}

		entry := fmt.Sprintf("Payload/%s.app/SC_Info/%s.sinf", bundleName, info.BundleExecutable)
		if err := writeEntry(zw, entry, item.Sinfs[0].Data); err != nil {
			return err
		}
	}

	if err := zw.Close(); err != nil {
		return fmt.Errorf("close zip: %w", err)
	}

	return nil
}

func copyZipEntry(f *zip.File, zw *zip.Writer) error {
	rc, err := f.Open()
	if err != nil {
		return err
	}

	defer rc.Close()

	hdr := f.FileHeader

	w, err := zw.CreateHeader(&hdr)
	if err != nil {
		return err
	}

	_, err = io.Copy(w, rc)

	return err
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
		if !strings.Contains(f.Name, ".app/Info.plist") || strings.Contains(f.Name, "/Watch/") {
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
