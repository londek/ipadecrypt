package appstore

import (
	"testing"

	"howett.net/plist"
)

func TestDecodeNativeDownloadTicket(t *testing.T) {
	data, err := plist.Marshal(map[string]any{
		"jingleDocType": "purchaseSuccess",
		"songList": []any{map[string]any{
			"URL":        "https://iosapps.itunes.apple.com/example.ipa",
			"sinfs":      []any{map[string]any{"id": int64(1), "sinf": []byte{1, 2, 3}}},
			"metadata":   map[string]any{"bundleShortVersionString": "1.2.3"},
			"asset-info": map[string]any{"file-size": int64(42)},
		}},
	}, plist.XMLFormat)
	if err != nil {
		t.Fatal(err)
	}

	ticket, err := DecodeNativeDownloadTicket(data)
	if err != nil {
		t.Fatal(err)
	}

	if ticket.Version() != "1.2.3" || ticket.FileSize() != 42 || len(ticket.Sinfs) != 1 {
		t.Fatalf("unexpected ticket: %+v", ticket)
	}
}
