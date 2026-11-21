package testflight

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
)

type App struct {
	ID            int64  `json:"appId"`
	Name          string `json:"name"`
	DeveloperName string `json:"developerName"`
}

func (c *Client) ListApps(ctx context.Context) ([]App, error) {
	path := "/v4/accounts/" + url.PathEscape(c.session.AccountID) + "/apps"

	var response struct {
		Data struct {
			Apps []App `json:"apps"`
		} `json:"data"`
	}
	if err := c.send(ctx, http.MethodGet, path, nil, &response); err != nil {
		return nil, err
	}

	apps := response.Data.Apps
	slices.SortFunc(apps, func(a, b App) int {
		return cmp.Or(cmp.Compare(a.DeveloperName, b.DeveloperName), cmp.Compare(a.Name, b.Name), cmp.Compare(a.ID, b.ID))
	})

	return apps, nil
}

type Version struct {
	Name string `json:"trainVersion"`
}

type build struct {
	ID         int64  `json:"id"`
	BundleID   string `json:"bundleId"`
	Version    string `json:"cfBundleShortVersion"`
	UploadDate string `json:"uploadDate"`
	Latest     bool   `json:"latestAvailableBuild"`
}

func (c *Client) ListVersions(ctx context.Context, appID int64) ([]Version, error) {
	if appID <= 0 {
		return nil, errors.New("TestFlight app ID must be positive")
	}

	path := c.accountPath() + "/apps/" + strconv.FormatInt(appID, 10) + "/platforms/ios/trains"

	var response struct {
		Data []Version `json:"data"`
	}
	if err := c.send(ctx, http.MethodGet, path, nil, &response); err != nil {
		return nil, err
	}

	versions := make([]Version, 0, len(response.Data))

	seen := make(map[string]bool, len(response.Data))
	for _, version := range response.Data {
		version.Name = strings.TrimSpace(version.Name)
		if version.Name == "" || seen[version.Name] {
			continue
		}

		seen[version.Name] = true
		versions = append(versions, version)
	}

	return versions, nil
}

func (c *Client) resolveBuild(ctx context.Context, appID int64, version string) (build, error) {
	if appID <= 0 || strings.TrimSpace(version) == "" {
		return build{}, errors.New("TestFlight app ID and version are required")
	}

	path := c.accountPath() + "/apps/" + strconv.FormatInt(appID, 10) +
		"/platforms/ios/trains/" + url.PathEscape(version) + "/builds"

	var response struct {
		Data []build `json:"data"`
	}
	if err := c.send(ctx, http.MethodGet, path, nil, &response); err != nil {
		return build{}, err
	}

	selected := newestBuild(response.Data, version)
	if selected.ID == 0 {
		return build{}, fmt.Errorf("no active TestFlight build is available for version %s", version)
	}

	return selected, nil
}

func newestBuild(builds []build, version string) build {
	var (
		best     build
		bestDate time.Time
	)

	for _, candidate := range builds {
		if candidate.ID <= 0 || (candidate.Version != "" && candidate.Version != version) ||
			(candidate.BundleID != "" && !identityToken.MatchString(candidate.BundleID)) {
			continue
		}

		date, _ := time.Parse(time.RFC3339, candidate.UploadDate)
		if best.ID == 0 || (candidate.Latest && !best.Latest) ||
			(candidate.Latest == best.Latest && (date.After(bestDate) || (date.Equal(bestDate) && candidate.ID > best.ID))) {
			best, bestDate = candidate, date
		}
	}

	return best
}

func selectVersion(versions []Version, requested string) (string, error) {
	requested = strings.TrimSpace(requested)
	if requested == "" {
		if len(versions) == 0 {
			return "", errors.New("no TestFlight versions are available")
		}

		return versions[0].Name, nil
	}

	for _, version := range versions {
		if version.Name == requested {
			return requested, nil
		}
	}

	return "", fmt.Errorf("TestFlight version %q is not available", requested)
}

func (c *Client) accountPath() string {
	return "/v2/accounts/" + url.PathEscape(c.session.AccountID)
}
