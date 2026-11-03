package appstore

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"sync"

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

// generateKBSync returns the base64 FairPlay attestation blob the ent/download
// endpoint requires, producing it with the StoreAgent guest (and caching it per
// account/device for the process). Mirrors ipatool generateKBSync.
func (c *Client) generateKBSync(ctx context.Context, hardwareID []byte, dsid uint64, g string) (string, error) {
	c.kbsync.mu.Lock()
	if c.kbsync.blob != "" && c.kbsync.dsid == dsid && c.kbsync.guid == g {
		blob := c.kbsync.blob
		c.kbsync.mu.Unlock()

		return blob, nil
	}
	c.kbsync.mu.Unlock()

	bundle, err := assets.Load(ctx)
	if err != nil {
		return "", fmt.Errorf("load assets for kbsync: %w", err)
	}

	data, err := machine.GenerateKBSync(ctx, bundle, hardwareID, dsid)
	if err != nil {
		return "", fmt.Errorf("generate kbsync: %w", err)
	}

	if len(data) == 0 {
		return "", errors.New("generated kbsync is empty")
	}

	blob := base64.StdEncoding.EncodeToString(data)

	c.kbsync.mu.Lock()
	c.kbsync.dsid, c.kbsync.guid, c.kbsync.blob = dsid, g, blob
	c.kbsync.mu.Unlock()

	return blob, nil
}

// entDownload attempts the attested ent/download path, which Apple's modern
// AppleMediaServices framework fully supports (unlike the legacy
// redownload/update endpoints). It returns handled=false to fall back to the
// legacy volumeStore chain when the bag has no ent endpoint or attestation
// cannot be produced. Mirrors ipatool sendEntDownload.
func (c *Client) entDownload(acc *Account, app App, g, externalVersionID string) (item downloadItem, handled bool, err error) {
	bag, err := c.fetchURLBag()
	if err != nil || bag.EntDownloadEndpoint == "" {
		return downloadItem{}, false, nil
	}

	entURL, err := downloadDispatchURL(bag.EntDownloadEndpoint, entDownloadPath)
	if err != nil {
		return downloadItem{}, false, nil
	}

	hardwareID, err := hex.DecodeString(g)
	if err != nil || len(hardwareID) != 6 {
		return downloadItem{}, false, nil
	}

	dsid, err := strconv.ParseUint(acc.DirectoryServicesID, 10, 64)
	if err != nil || dsid == 0 {
		return downloadItem{}, false, nil
	}

	if externalVersionID == "" {
		externalVersionID, err = c.lookupLatestExternalVersionID(acc, app)
		if err != nil {
			debugf("ent/download: resolve version: %v", err)
			return downloadItem{}, false, nil
		}
	}

	blob, err := c.generateKBSync(context.Background(), hardwareID, dsid, g)
	if err != nil {
		debugf("ent/download: %v", err)
		return downloadItem{}, false, nil
	}

	serial := append([]byte{0x54, 0xc8, 0xb0, 0xa9, 0x88}, hardwareID[2:]...)

	payload := map[string]any{
		"creditDisplay":     "",
		"guid":              g,
		"kbsync":            blob,
		"salableAdamId":     strconv.FormatInt(app.ID, 10),
		"serialNumber":      base64.StdEncoding.EncodeToString(serial),
		"externalVersionId": externalVersionID,
	}

	headers := map[string]string{
		"Content-Type":        "application/x-www-form-urlencoded; charset=utf-8",
		"iCloud-DSID":         acc.DirectoryServicesID,
		"X-Dsid":              acc.DirectoryServicesID,
		"X-Apple-Store-Front": acc.StoreFront,
		"X-Token":             acc.PasswordToken,
	}

	var out downloadResult

	res, err := c.send("request", http.MethodPost, fmt.Sprintf("%s?guid=%s", entURL, g), headers, &apphttp.XMLPayload{Content: payload}, nil, formatXML, &out)
	if err != nil {
		return downloadItem{}, false, fmt.Errorf("ent/download request: %w", err)
	}

	debugf("ent/download ver=%q: status=%d failureType=%q customerMessage=%q items=%d",
		externalVersionID, res.StatusCode, out.FailureType, out.CustomerMessage, len(out.Items))

	if res.StatusCode == http.StatusForbidden {
		return downloadItem{}, false, nil
	}

	if item, decided, ferr := classifyDownload(out); decided {
		return item, true, ferr
	}

	return downloadItem{}, false, nil
}
