package appstore

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"

	apphttp "github.com/londek/ipadecrypt/internal/apphttp"
	"github.com/londek/ipadecrypt/internal/sap/assets"
	"github.com/londek/ipadecrypt/internal/sap/machine"
)

const entDownloadPath = "/WebObjects/DownloadDispatch.woa/wa/ent/download"

// kbsyncStore memoizes the account+device attestation blob for the process so
// repeated downloads in one run do not re-run the StoreAgent guest.
type kbsyncStore struct {
	mu   sync.Mutex
	dsid uint64
	guid string
	blob string
}

// TestFlightKBSync returns the account-bound FairPlay device information that
// TestFlight requires when authorizing a build download.
func (c *Client) TestFlightKBSync(ctx context.Context, dsid uint64, hardwareID []byte) (string, error) {
	if len(hardwareID) != 20 {
		return "", errors.New("TestFlight kbsync requires a twenty-byte device identity")
	}

	return c.generateKBSync(ctx, hardwareID, dsid)
}

// generateKBSync returns the base64 FairPlay attestation blob the ent/download
// endpoint requires, producing it with the StoreAgent guest. Mirrors ipatool
// generateKBSync.
func (c *Client) generateKBSync(ctx context.Context, hardwareID []byte, dsid uint64) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", fmt.Errorf("generate kbsync: %w", err)
	}

	bundle, err := assets.Load(ctx)
	if err != nil {
		return "", fmt.Errorf("load assets for kbsync: %w", err)
	}

	data, err := machine.GenerateKBSync(ctx, bundle, hardwareID, dsid)
	if err != nil {
		return "", fmt.Errorf("generate kbsync: %w", err)
	}

	if err := ctx.Err(); err != nil {
		return "", fmt.Errorf("generate kbsync: %w", err)
	}

	if len(data) == 0 {
		return "", errors.New("generated kbsync is empty")
	}

	return base64.StdEncoding.EncodeToString(data), nil
}

// storeKBSync caches only blobs that have served a valid ent/download response.
func (c *Client) storeKBSync(dsid uint64, g, blob string) {
	c.kbsync.mu.Lock()
	defer c.kbsync.mu.Unlock()

	c.kbsync.dsid, c.kbsync.guid, c.kbsync.blob = dsid, g, blob
}

func (c *Client) cachedKBSync(dsid uint64, g string) string {
	c.kbsync.mu.Lock()
	defer c.kbsync.mu.Unlock()

	if c.kbsync.dsid == dsid && c.kbsync.guid == g && c.kbsync.blob != "" {
		return c.kbsync.blob
	}

	return ""
}

// invalidateKBSync drops the cache only if it still holds the rejected blob.
func (c *Client) invalidateKBSync(dsid uint64, g, blob string) {
	c.kbsync.mu.Lock()
	defer c.kbsync.mu.Unlock()

	if c.kbsync.dsid == dsid && c.kbsync.guid == g && c.kbsync.blob == blob {
		c.kbsync.dsid, c.kbsync.guid, c.kbsync.blob = 0, "", ""
	}
}

// entDownload attempts the attested ent/download path, which Apple's modern
// AppleMediaServices framework fully supports (unlike the legacy
// redownload/update endpoints), pinning the current iOS version when none was
// requested. Any error lets the caller fall back to the legacy volumeStore
// chain.
func (c *Client) entDownload(endpoint string, acc *Account, app App, g, externalVersionID string) (apphttp.Result[downloadResult], error) {
	entURL, err := downloadDispatchURL(endpoint, entDownloadPath)
	if err != nil {
		return apphttp.Result[downloadResult]{}, err
	}

	if externalVersionID == "" {
		externalVersionID, err = c.lookupLatestExternalVersionID(acc, app)
		if err != nil {
			return apphttp.Result[downloadResult]{}, fmt.Errorf("ent/download: resolve version: %w", err)
		}
	}

	return c.sendEntDownload(entURL, acc, app, g, externalVersionID)
}

// sendEntDownload sends ent/download with a cached kbsync blob when one exists,
// retrying once with a fresh blob if the cached one is rejected. An empty
// externalVersionID lets Apple pick the entitled build.
func (c *Client) sendEntDownload(endpoint string, acc *Account, app App, g, externalVersionID string) (apphttp.Result[downloadResult], error) {
	hardwareID, err := hex.DecodeString(g)
	if err != nil || len(hardwareID) != 6 {
		return apphttp.Result[downloadResult]{}, errors.New("ent/download requires a six-byte device GUID")
	}

	dsid, err := strconv.ParseUint(acc.DirectoryServicesID, 10, 64)
	if err != nil || dsid == 0 {
		return apphttp.Result[downloadResult]{}, errors.New("ent/download requires a nonzero numeric account DSID")
	}

	// Asset loading and guest execution also honor this deadline.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	if cached := c.cachedKBSync(dsid, g); cached != "" {
		res, err := c.sendEntDownloadRequest(ctx, endpoint, acc, app, g, externalVersionID, hardwareID, cached)
		if err == nil {
			return res, nil
		}

		if ctx.Err() != nil {
			return res, fmt.Errorf("ent/download canceled: %w", ctx.Err())
		}

		debugf("ent/download with cached kbsync: %v", err)

		c.invalidateKBSync(dsid, g, cached)
	}

	blob, err := c.generateKBSync(ctx, hardwareID, dsid)
	if err != nil {
		return apphttp.Result[downloadResult]{}, err
	}

	res, err := c.sendEntDownloadRequest(ctx, endpoint, acc, app, g, externalVersionID, hardwareID, blob)
	if err == nil {
		c.storeKBSync(dsid, g, blob)
	}

	return res, err
}

// sendEntDownloadRequest accepts only a validated success; failures, including
// structured ones, are returned as errors.
func (c *Client) sendEntDownloadRequest(ctx context.Context, endpoint string, acc *Account, app App, g, externalVersionID string, hardwareID []byte, blob string) (apphttp.Result[downloadResult], error) {
	serial := append([]byte{0x54, 0xc8, 0xb0, 0xa9, 0x88}, hardwareID[2:]...)
	request := downloadProductRequest(endpoint, "", acc, app, g, "")

	requestContext, cancelRequest := context.WithTimeout(ctx, apphttp.DefaultAuthenticationTimeout)
	defer cancelRequest()

	request.Context = requestContext
	request.Headers["Content-Type"] = "application/x-www-form-urlencoded; charset=utf-8"

	proof, err := c.storeAMDProof(ctx, request.URL, hardwareID)
	if err != nil {
		return apphttp.Result[downloadResult]{}, err
	}

	for key, value := range proof {
		request.Headers[key] = value
	}

	payload := map[string]any{
		"creditDisplay": "",
		"guid":          g,
		"kbsync":        blob,
		"salableAdamId": strconv.FormatInt(app.ID, 10),
		"serialNumber":  base64.StdEncoding.EncodeToString(serial),
	}
	if externalVersionID != "" {
		payload["externalVersionId"] = externalVersionID
	}

	request.Payload = &apphttp.XMLPayload{Content: payload}

	res, err := c.downloadClient().Send(request)
	if err != nil {
		return res, fmt.Errorf("ent/download request: %w", err)
	}

	res.Data = normalizeDownloadFailure(res.Data)

	debugf("ent/download ver=%q: status=%d failureType=%q customerMessage=%q items=%d",
		externalVersionID, res.StatusCode, res.Data.FailureType, res.Data.CustomerMessage, len(res.Data.Items))

	if res.Data.FailureType != "" {
		return res, fmt.Errorf("ent/download: %s", res.Data.FailureType)
	}

	if err := validateVersionedDownload(res, app, externalVersionID, "ent/download"); err != nil {
		return res, err
	}

	if res.Data.Items[0].URL == "" {
		return res, errors.New("ent/download response has no package URL")
	}

	return res, nil
}
