package emulator

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/londek/ipadecrypt/internal/sap/assets"
	"github.com/londek/ipadecrypt/internal/store/profile"
	"howett.net/plist"
)

// Opt in because Apple runtime assets may need downloading. All Store traffic
// is replaced locally; no account or purchase is needed for this regression.
func TestRawPurchaseResponses(t *testing.T) {
	if os.Getenv("IPADECRYPT_TEST_APPLE_RUNTIME") != "1" {
		t.Skip("requires pinned Apple runtime assets")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	bundle, err := assets.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := profile.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, response := range []map[string]any{
		{"jingleDocType": "buyProductFailure", "action": map[string]any{"kind": "Goto", "target": "main", "url": "https://p42-buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/com.apple.jingle.app.finance.DirectAction/termsPage"}},
		{"jingleDocType": "buyProductFailure", "failureType": "2034", "customerMessage": "Sign In to the iTunes Store"},
		{"jingleDocType": "purchaseSuccess", "status": uint64(0)},
	} {
		t.Run(response["jingleDocType"].(string), func(t *testing.T) {
			guest, err := Open(ctx, bundle.AppleMediaServices, prepared)
			if err != nil {
				t.Fatal(err)
			}
			defer guest.Close()
			body, err := plist.Marshal(response, plist.XMLFormat)
			if err != nil {
				t.Fatal(err)
			}
			calls := 0
			out, err := guest.Execute(Request{
				Operation: "purchase", Method: "POST", URL: "https://p42-buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/buyProduct", Raw: true, NoRedirects: true,
				HardwareID: []byte{2, 3, 4, 5, 6, 7}, Bag: map[string]any{"countryCode": "USA"},
				Headers:    http.Header{"X-Dsid": []string{"12345"}, "X-Token": []string{"synthetic-token"}, "X-Apple-Store-Front": []string{"143441-1,29"}},
				Parameters: map[string]any{"guid": "020304050607", "price": "0", "productType": "C", "salableAdamId": int64(123), "pricingParameters": "STDQ"},
				Transport: func(req *http.Request) (*http.Response, error) {
					calls++
					if req.URL.Path != "/WebObjects/MZFinance.woa/wa/buyProduct" || req.Method != "POST" {
						t.Errorf("unexpected request: %s %s", req.Method, req.URL.Path)
					}
					return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/x-apple-plist"}}, Body: io.NopCloser(bytes.NewReader(body)), Request: req}, nil
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			defer out.Body.Close()
			got, err := io.ReadAll(out.Body)
			if err != nil || !bytes.Equal(got, body) || calls != 1 {
				t.Fatalf("raw response lost or UI action executed: calls=%d error=%v", calls, err)
			}
		})
	}
}
