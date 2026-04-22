package appstore

import (
	"archive/zip"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

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

// ExternalVersionID returns the stable App Store identifier for this
// specific release (e.g. "847134900"). Useful as a cache key since it can't
// collide across releases the way human version strings can.
func (t DownloadTicket) ExternalVersionID() string {
	return metaString(t.Metadata, "softwareVersionExternalIdentifier")
}

// BundleID returns softwareVersionBundleId from the metadata - handy when
// the caller doesn't already know it.
func (t DownloadTicket) BundleID() string {
	return metaString(t.Metadata, "softwareVersionBundleId")
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

	return DownloadTicket{
		URL:       item.URL,
		Sinfs:     item.Sinfs,
		Metadata:  item.Metadata,
		AssetInfo: item.AssetInfo,
	}, nil
}

// volumeDownload is the shared POST to the volumeStoreDownloadProduct
// endpoint used for both authorized downloads and metadata-only lookups
// (list versions, get per-version metadata). The endpoint is the same;
// whether externalVersionID is set decides what is returned.
func (c *Client) volumeDownload(acc *Account, app App, externalVersionID string) (downloadItem, error) {
	g, err := guid()
	if err != nil {
		return downloadItem{}, err
	}

	podPrefix := ""
	if acc.Pod != "" {
		podPrefix = "p" + acc.Pod + "-"
	}

	url := fmt.Sprintf("https://%s%s%s?guid=%s", podPrefix, storeDomain, downloadPath, g)

	payload := map[string]any{
		"creditDisplay": "",
		"guid":          g,
		"salableAdamId": app.ID,
	}
	if externalVersionID != "" {
		payload["externalVersionId"] = externalVersionID
	}

	body, err := plistBody(payload)
	if err != nil {
		return downloadItem{}, err
	}

	headers := map[string]string{
		"Content-Type": "application/x-apple-plist",
		"iCloud-DSID":  acc.DirectoryServicesID,
		"X-Dsid":       acc.DirectoryServicesID,
	}

	var out downloadResult
	if _, err := c.send(http.MethodPost, url, headers, body, formatXML, &out); err != nil {
		return downloadItem{}, fmt.Errorf("download: %w", err)
	}

	switch {
	case out.FailureType == failurePasswordTokenExpired,
		out.FailureType == failureSignInRequired,
		out.FailureType == failureDeviceVerificationFailed,
		out.FailureType == failureLicenseAlreadyExists:
		return downloadItem{}, ErrPasswordTokenExpired
	case out.FailureType == failureLicenseNotFound:
		return downloadItem{}, ErrLicenseRequired
	case out.FailureType != "" && out.CustomerMessage != "":
		return downloadItem{}, errors.New(out.CustomerMessage)
	case out.FailureType != "":
		return downloadItem{}, fmt.Errorf("download: %s", out.FailureType)
	case len(out.Items) == 0:
		return downloadItem{}, errors.New("download: empty songList")
	}

	return out.Items[0], nil
}

// CompleteDownload fetches the IPA described by `ticket` into outPath,
// injects iTunesMetadata.plist, and replicates sinfs. outPath must be a
// file path, not a directory.
func (c *Client) CompleteDownload(acc *Account, ticket DownloadTicket, outPath string) (DownloadOutput, error) {
	if outPath == "" {
		return DownloadOutput{}, errors.New("download: outPath is required (must be a file path)")
	}
	if info, err := os.Stat(outPath); err == nil && info.IsDir() {
		return DownloadOutput{}, fmt.Errorf("download: outPath %q is a directory; CompleteDownload expects a file path", outPath)
	} else if err != nil && !os.IsNotExist(err) {
		return DownloadOutput{}, fmt.Errorf("download: stat outPath: %w", err)
	}

	item := downloadItem{
		URL:      ticket.URL,
		Sinfs:    ticket.Sinfs,
		Metadata: ticket.Metadata,
	}

	tmp := outPath + ".tmp"
	if err := fetchToFile(c.http, item.URL, tmp); err != nil {
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

func fetchToFile(hc *http.Client, url, dst string) error {
	f, err := os.OpenFile(dst, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return fmt.Errorf("open %s: %w", dst, err)
	}

	defer f.Close()

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}

	if stat, err := f.Stat(); err == nil && stat.Size() > 0 {
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-", stat.Size()))
	}

	res, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("fetch: %w", err)
	}

	defer res.Body.Close()

	if _, err := io.Copy(f, res.Body); err != nil {
		return fmt.Errorf("write %s: %w", dst, err)
	}

	return nil
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

	defer zw.Close()

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

		return nil
	}

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

	return writeEntry(zw, entry, item.Sinfs[0].Data)
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

func writeMetadataEntry(zw *zip.Writer, metadata map[string]interface{}, acc *Account) error {
	metadata["apple-id"] = acc.Email
	metadata["userName"] = acc.Email

	data, err := plist.Marshal(metadata, plist.BinaryFormat)
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
