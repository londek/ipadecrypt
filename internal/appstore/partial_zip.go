package appstore

import (
	"archive/zip"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"howett.net/plist"
)

var infoPlistReleaseDateKeys = []string{
	"releaseDate",
	"ReleaseDate",
}

var infoPlistDisplayVersionKeys = []string{
	"CFBundleShortVersionString",
	"bundleShortVersionString",
}

type versionMetadata struct {
	DisplayVersion   string
	ReleaseDate      time.Time
	MinimumOSVersion string
}

// httpRangeReader is the io.ReaderAt that archive/zip drives when it is handed
// a URL instead of a local file: each ReadAt is one HTTP Range GET.
type httpRangeReader struct {
	client *http.Client
	url    string
	size   int64
}

func newHTTPRangeReader(client *http.Client, url string) (*httpRangeReader, int64, error) {
	if url == "" {
		return nil, 0, errors.New("range fetch: no URL")
	}

	size, err := remoteFileSize(client, url)
	if err != nil {
		return nil, 0, err
	}

	return &httpRangeReader{
		client: client,
		url:    url,
		size:   size,
	}, size, nil
}

func remoteFileSize(client *http.Client, url string) (int64, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}

	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("Range", "bytes=0-0")

	res, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("range fetch: %w", err)
	}

	if res != nil && res.Body != nil {
		defer res.Body.Close()
	}

	if res.StatusCode != http.StatusPartialContent {
		return 0, fmt.Errorf("range fetch %s status %d", url, res.StatusCode)
	}

	size, err := parseContentRangeSize(res.Header.Get("Content-Range"))
	if err != nil {
		return 0, err
	}

	return size, nil
}

func parseContentRangeSize(header string) (int64, error) {
	if header == "" {
		return 0, errors.New("range fetch: no Content-Range")
	}

	slash := strings.LastIndex(header, "/")
	if slash == -1 || slash == len(header)-1 {
		return 0, fmt.Errorf("range fetch: invalid Content-Range %q", header)
	}

	sizeText := header[slash+1:]
	if sizeText == "*" {
		return 0, fmt.Errorf("range fetch: invalid Content-Range %q", header)
	}

	size, err := strconv.ParseInt(sizeText, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("range fetch: parse Content-Range %q: %w", header, err)
	}

	return size, nil
}

func (r *httpRangeReader) ReadAt(p []byte, off int64) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	if off < 0 {
		return 0, errors.New("range fetch: negative offset")
	}

	if off >= r.size {
		return 0, io.EOF
	}

	requestEnd := off + int64(len(p)) - 1
	rangeEnd := requestEnd

	if rangeEnd >= r.size {
		rangeEnd = r.size - 1
	}

	req, err := http.NewRequest(http.MethodGet, r.url, nil)
	if err != nil {
		return 0, err
	}

	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", off, rangeEnd))

	res, err := r.client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("range fetch: %w", err)
	}

	if res != nil && res.Body != nil {
		defer res.Body.Close()
	}

	if res.StatusCode != http.StatusPartialContent {
		return 0, fmt.Errorf("range fetch %s status %d", r.url, res.StatusCode)
	}

	readLength := int(rangeEnd-off) + 1

	n, err := io.ReadFull(res.Body, p[:readLength])
	if err == io.ErrUnexpectedEOF || err == io.EOF {
		return n, io.EOF
	}

	if err != nil {
		return n, err
	}

	if requestEnd >= r.size {
		return n, io.EOF
	}

	return n, nil
}

// readVersionMetadataFromIPA reads the display version and release date from
// the main app Info.plist of a remote IPA using range requests. The reads use
// the plain CDN client: the versions screen runs this for every row, and one
// emulated request per range read is slow and can stall the guest.
func (c *Client) readVersionMetadataFromIPA(url string) (versionMetadata, error) {
	reader, size, err := newHTTPRangeReader(c.http, url)
	if err != nil {
		return versionMetadata{}, err
	}

	zr, err := zip.NewReader(reader, size)
	if err != nil {
		return versionMetadata{}, fmt.Errorf("open zip: %w", err)
	}

	for _, f := range zr.File {
		if !isTopLevelAppInfoPlist(f.Name) {
			continue
		}

		metadata, err := readVersionMetadataFromInfoPlist(f)
		if err != nil {
			return versionMetadata{}, err
		}

		return metadata, nil
	}

	return versionMetadata{}, errors.New("no Info.plist in IPA")
}

func readVersionMetadataFromInfoPlist(f *zip.File) (versionMetadata, error) {
	data, err := readZipFile(f)
	if err != nil {
		return versionMetadata{}, fmt.Errorf("read Info.plist: %w", err)
	}

	metadata := map[string]any{}
	if _, err := plist.Unmarshal(data, &metadata); err != nil {
		return versionMetadata{}, fmt.Errorf("parse Info.plist: %w", err)
	}

	displayVersion, err := readDisplayVersionFromMetadata(metadata)
	if err != nil {
		return versionMetadata{}, err
	}

	releaseDate, err := readReleaseDateFromInfoPlist(metadata, f.Modified)
	if err != nil {
		return versionMetadata{}, err
	}

	minimumOSVersion, _ := metadata["MinimumOSVersion"].(string)

	return versionMetadata{
		DisplayVersion:   displayVersion,
		ReleaseDate:      releaseDate,
		MinimumOSVersion: minimumOSVersion,
	}, nil
}

func readDisplayVersionFromMetadata(metadata map[string]any) (string, error) {
	for _, key := range infoPlistDisplayVersionKeys {
		value, ok := metadata[key]
		if !ok {
			continue
		}

		displayVersion := strings.TrimSpace(fmt.Sprintf("%v", value))
		if displayVersion == "" || displayVersion == "<nil>" {
			return "", fmt.Errorf("%s is empty", key)
		}

		return displayVersion, nil
	}

	return "", errors.New("no display version in Info.plist")
}

func readReleaseDateFromInfoPlist(metadata map[string]any, modified time.Time) (time.Time, error) {
	for _, key := range infoPlistReleaseDateKeys {
		value, ok := metadata[key]
		if !ok {
			continue
		}

		releaseDate, err := parseReleaseDateValue(value)
		if err != nil {
			return time.Time{}, fmt.Errorf("parse release date: %w", err)
		}

		return releaseDate, nil
	}

	if modified.IsZero() {
		return time.Time{}, errors.New("no release date in Info.plist")
	}

	return modified.UTC(), nil
}

func parseReleaseDateValue(value any) (time.Time, error) {
	switch val := value.(type) {
	case time.Time:
		return val.UTC(), nil
	case string:
		return parseReleaseDateString(val)
	case int:
		return time.Unix(int64(val), 0).UTC(), nil
	case int64:
		return time.Unix(val, 0).UTC(), nil
	case uint64:
		if val > math.MaxInt64 {
			return time.Time{}, fmt.Errorf("timestamp is too large: %d", val)
		}

		return time.Unix(int64(val), 0).UTC(), nil
	case float64:
		return time.Unix(int64(val), 0).UTC(), nil
	default:
		return time.Time{}, fmt.Errorf("unsupported release date type %T", value)
	}
}

func parseReleaseDateString(value string) (time.Time, error) {
	value = strings.TrimSpace(value)

	for _, layout := range []string{
		time.RFC3339,
		time.RFC3339Nano,
		"Monday, January 2, 2006",
		"2006-01-02",
	} {
		parsed, err := time.Parse(layout, value)
		if err == nil {
			return parsed.UTC(), nil
		}
	}

	return time.Time{}, fmt.Errorf("invalid release date: %s", value)
}
