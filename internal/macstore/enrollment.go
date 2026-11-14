package macstore

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/londek/ipadecrypt/internal/sap/machine"
	"github.com/londek/ipadecrypt/internal/storeauth"
	store "github.com/majd/ipatool/v2/pkg/appstore"
)

const entDownloadPath = "/WebObjects/DownloadDispatch.woa/wa/ent/download"

// Enroll creates account content state in an empty guest. The caller must verify
// recovery against an account-personalized IPA before publishing a credential.
// Neither this method nor its ticket callback acquires a license.
func (s *Session) Enroll(ctx context.Context, account store.Account, app CatalogApp) ([]byte, []byte, error) {
	dsid, err := strconv.ParseUint(account.DirectoryServicesID, 10, 64)
	if err != nil || dsid == 0 || app.App.ID <= 0 || !digits.MatchString(app.ExternalVersionID) {
		return nil, nil, errors.New("invalid enrollment account or app version")
	}

	hardware, err := s.hardwareID()
	if err != nil {
		return nil, nil, err
	}

	guid := strings.ToUpper(hex.EncodeToString(hardware))

	endpoint, err := s.enrollmentEndpoint(ctx, guid)
	if err != nil {
		return nil, nil, err
	}

	headers, err := s.enrollmentHeaders(ctx, account, endpoint, hardware)
	if err != nil {
		return nil, nil, err
	}

	sidb, err := machine.EnrollContent(ctx, hardware, dsid, func(ctx context.Context, blob []byte) ([]byte, error) {
		serial := append([]byte{0x54, 0xc8, 0xb0, 0xa9, 0x88}, hardware[2:]...)

		response, err := s.sendPlist(ctx, "request", endpoint, headers, map[string]any{
			"creditDisplay":     "",
			"guid":              guid,
			"kbsync":            base64.StdEncoding.EncodeToString(blob),
			"salableAdamId":     strconv.FormatInt(app.App.ID, 10),
			"serialNumber":      base64.StdEncoding.EncodeToString(serial),
			"externalVersionId": app.ExternalVersionID,
		})
		if err != nil {
			return nil, err
		}

		return enrollmentKeybag(response, account, app)
	})

	return sidb, hardware, err
}

func enrollmentKeybag(response map[string]any, account store.Account, app CatalogApp) ([]byte, error) {
	if err := storeInteraction(response); err != nil {
		return nil, err
	}

	if response["jingleDocType"] != "purchaseSuccess" || fmt.Sprint(response["status"]) != "0" {
		return nil, errors.New("enrollment ticket was not confirmed by Apple")
	}

	if fmt.Sprint(response["dsPersonId"]) != account.DirectoryServicesID {
		return nil, errors.New("enrollment response account mismatch")
	}

	items, ok := response["songList"].([]any)
	if !ok || len(items) != 1 {
		return nil, errors.New("enrollment requires exactly one owned download ticket")
	}

	item, _ := items[0].(map[string]any)

	meta, _ := item["metadata"].(map[string]any)
	if fmt.Sprint(meta["itemId"]) != strconv.FormatInt(app.App.ID, 10) || meta["softwareVersionBundleId"] != app.App.BundleID || fmt.Sprint(meta["softwareVersionExternalIdentifier"]) != app.ExternalVersionID {
		return nil, errors.New("enrollment response app/version mismatch")
	}

	keybag, ok := response["keybag"].([]byte)
	if !ok || len(keybag) == 0 || len(keybag) > 1<<20 {
		return nil, errors.New("enrollment response has no valid keybag")
	}

	return keybag, nil
}

func (s *Session) enrollmentEndpoint(ctx context.Context, guid string) (string, error) {
	bag, err := s.sendPlist(ctx, "bag-direct", "https://init.itunes.apple.com/bag.xml?ix=6&guid="+guid, map[string]string{"User-Agent": storeUserAgent}, nil)
	if err != nil {
		return "", err
	}

	if nested, ok := bag["urlBag"].(map[string]any); ok {
		bag = nested
	}

	endpoint, _ := bag["volumeStoreDownloadProduct"].(string)

	u, err := storeEndpoint(endpoint, entDownloadPath)
	if err != nil {
		return "", err
	}

	u.RawQuery = "guid=" + guid

	return u.String(), nil
}

func (s *Session) enrollmentHeaders(ctx context.Context, account store.Account, endpoint string, hardware []byte) (map[string]string, error) {
	// Preparing AMD before opening the content runtime avoids keeping a second
	// set of FairPlay guests alive during expensive provisioning work.
	encoded, err := s.keys.Get("anisette-v4")
	if err != nil {
		return nil, errors.New("the Mac Store sign-in state is missing; sign in again")
	}
	defer clear(encoded)

	proof, updated, err := storeauth.StoreAMDHeaders(ctx, encoded, endpoint, hardware)
	if err != nil {
		return nil, fmt.Errorf("prepare enrollment signing: %w", err)
	}
	defer clear(updated)

	if err = s.keys.Set("anisette-v4", updated); err != nil {
		return nil, err
	}

	s.reloadAPI()

	headers := accountHeaders(account)

	headers["Content-Type"] = "application/x-www-form-urlencoded; charset=utf-8"
	for k, v := range proof {
		headers[k] = v
	}

	return headers, nil
}
