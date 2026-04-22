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
	Raw               map[string]any
}

func (c *Client) ListVersions(acc *Account, app App) (ListVersionsOutput, error) {
	item, err := c.volumeDownload(acc, app, "")
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

func (c *Client) GetVersionMetadata(acc *Account, app App, externalVersionID string) (VersionMetadata, error) {
	if externalVersionID == "" {
		return VersionMetadata{}, errors.New("get version metadata: externalVersionID is required")
	}

	item, err := c.volumeDownload(acc, app, externalVersionID)
	if err != nil {
		return VersionMetadata{}, err
	}

	out := VersionMetadata{
		ExternalVersionID: externalVersionID,
		DisplayVersion:    metaString(item.Metadata, "bundleShortVersionString"),
		BundleVersion:     metaString(item.Metadata, "bundleVersion"),
		SupportedDevices:  metaIntSlice(item.Metadata, "softwareSupportedDeviceIds"),
		Raw:               item.Metadata,
	}

	if rd := metaString(item.Metadata, "releaseDate"); rd != "" {
		if t, err := time.Parse(time.RFC3339, rd); err == nil {
			out.ReleaseDate = t
		}
	}

	return out, nil
}
