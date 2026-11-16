package appstore

import (
	"errors"
	"fmt"
	"time"
)

type ListVersionsOutput struct {
	// ExternalVersionIDs is the full list of externalVersionIds Apple
	// reports for this app, in the order Apple returns them
	// (observationally oldest -> newest).
	ExternalVersionIDs []string
	// LatestExternalVersionID is the id Apple flags as the current
	// release (softwareVersionExternalIdentifier).
	LatestExternalVersionID string
	// Raw is the complete metadata dict so callers (typically the
	// response logger) can inspect keys we don't yet parse.
	Raw map[string]any
}

type VersionMetadata struct {
	ExternalVersionID string
	DisplayVersion    string
	BundleVersion     string
	SupportedDevices  []int
	ReleaseDate       time.Time
	// MinimumOSVersion comes from the same Info.plist read; "" when absent.
	MinimumOSVersion string
	// URL and FileSize describe the signed CDN download; they're populated
	// from the same volumeDownload call that produces metadata so callers
	// can range-fetch the zip central directory without a second hit on
	// Apple's auth endpoint.
	URL      string
	FileSize int64
	Raw      map[string]any
}

func (c *Client) ListVersions(acc *Account, app App) (ListVersionsOutput, error) {
	res, _, err := c.volumeDownload(acc, app, "")
	if err != nil {
		return ListVersionsOutput{}, err
	}

	item, err := classifyDownload(res.Data, failurePasswordTokenExpired, failureSignInRequired)
	if err != nil {
		return ListVersionsOutput{}, err
	}

	rawIdentifiers, ok := item.Metadata["softwareVersionExternalIdentifiers"].([]any)
	if !ok {
		return ListVersionsOutput{}, errors.New("list versions: no softwareVersionExternalIdentifiers in metadata")
	}

	ids := make([]string, len(rawIdentifiers))
	for i, v := range rawIdentifiers {
		ids[i] = fmt.Sprintf("%v", v)
	}

	latest, ok := item.Metadata["softwareVersionExternalIdentifier"]
	if !ok || latest == nil {
		return ListVersionsOutput{}, errors.New("list versions: no softwareVersionExternalIdentifier in metadata")
	}

	return ListVersionsOutput{
		ExternalVersionIDs:      ids,
		LatestExternalVersionID: fmt.Sprintf("%v", latest),
		Raw:                     item.Metadata,
	}, nil
}

// GetVersionMetadata describes one version. DisplayVersion and ReleaseDate
// come from the IPA's main Info.plist, read with range requests, because the
// download API can return stale values; the other fields come from the item
// metadata.
func (c *Client) GetVersionMetadata(acc *Account, app App, externalVersionID string) (VersionMetadata, error) {
	if externalVersionID == "" {
		return VersionMetadata{}, errors.New("get version metadata: externalVersionID is required")
	}

	res, _, err := c.volumeDownload(acc, app, externalVersionID)
	if err != nil {
		return VersionMetadata{}, err
	}

	item, err := classifyDownload(res.Data, failurePasswordTokenExpired, failureSignInRequired)
	if err != nil {
		return VersionMetadata{}, err
	}

	ticket := DownloadTicket(item)

	metadata, err := c.readVersionMetadataFromIPA(item.URL)
	if err != nil {
		return VersionMetadata{}, fmt.Errorf("get version metadata: %w", err)
	}

	return VersionMetadata{
		ExternalVersionID: externalVersionID,
		DisplayVersion:    metadata.DisplayVersion,
		BundleVersion:     metaString(item.Metadata, "bundleVersion"),
		SupportedDevices:  metaIntSlice(item.Metadata, "softwareSupportedDeviceIds"),
		ReleaseDate:       metadata.ReleaseDate,
		MinimumOSVersion:  metadata.MinimumOSVersion,
		URL:               item.URL,
		FileSize:          ticket.FileSize(),
		Raw:               item.Metadata,
	}, nil
}
