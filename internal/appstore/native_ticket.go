package appstore

import (
	"errors"
	"fmt"

	"howett.net/plist"
)

// DecodeNativeDownloadTicket validates an original on-device Store response.
func DecodeNativeDownloadTicket(data []byte) (DownloadTicket, error) {
	var response struct {
		JingleDocType string         `plist:"jingleDocType,omitempty"`
		Items         []downloadItem `plist:"songList,omitempty"`
	}
	if _, err := plist.Unmarshal(data, &response); err != nil {
		return DownloadTicket{}, fmt.Errorf("decode native purchase ticket: %w", err)
	}

	if response.JingleDocType != "purchaseSuccess" {
		return DownloadTicket{}, errors.New("native purchase response is not purchaseSuccess")
	}

	if len(response.Items) != 1 || response.Items[0].URL == "" {
		return DownloadTicket{}, errors.New("native purchase response must contain one download item")
	}

	if len(response.Items[0].Sinfs) == 0 {
		return DownloadTicket{}, errors.New("native purchase response has no SINF")
	}

	return DownloadTicket(response.Items[0]), nil
}
