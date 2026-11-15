package anisettecapture

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/londek/ipadecrypt/internal/fridarpc"
	"howett.net/plist"
)

type purchaseObserver struct {
	mu            sync.Mutex
	ticket        []byte
	authorization string
	err           error
	complete      chan struct{}
	progress      func(string)
}

func findPurchaseValue(value any, key string) any {
	switch v := value.(type) {
	case map[string]any:
		for name, value := range v {
			if strings.EqualFold(name, key) {
				return value
			}
		}

		for _, value := range v {
			if found := findPurchaseValue(value, key); found != nil {
				return found
			}
		}
	case []any:
		for _, value := range v {
			if found := findPurchaseValue(value, key); found != nil {
				return found
			}
		}
	}

	return nil
}

func (o *purchaseObserver) event(event fridarpc.Event) {
	var p struct {
		Event     string `json:"event"`
		URL       string `json:"url"`
		Confirmed bool   `json:"confirmed"`
	}
	if json.Unmarshal(event.Payload, &p) != nil {
		return
	}

	o.mu.Lock()
	defer o.mu.Unlock()

	switch p.Event {
	case "purchaseComplete":
		select {
		case o.complete <- struct{}{}:
		default:
		}
	case "purchaseAuthenticate":
		if o.progress != nil {
			o.progress("authenticate")
		}
	case "purchaseDialog", "purchasePaymentSheet":
		if p.Confirmed && o.progress != nil {
			o.progress("confirmed")
		}
	case "response":
		if !strings.Contains(p.URL, "buyProduct") || len(event.Data) == 0 {
			return
		}

		body, err := decodePurchaseBody(event.Data)
		if err != nil {
			o.err = err
			return
		}

		var value any
		if _, err = plist.Unmarshal(body, &value); err != nil {
			o.err = errors.New("invalid native purchase response")
			return
		}

		if findPurchaseValue(value, "jingleDocType") == "purchaseSuccess" {
			o.ticket = append([]byte(nil), body...)
		}

		dialog := findPurchaseValue(value, "dialog")

		action := findPurchaseValue(dialog, "okButtonAction")
		if parameters, ok := findPurchaseValue(action, "buyParams").(string); ok && parameters != "" {
			o.authorization = parameters
		}
	}
}
func decodePurchaseBody(body []byte) ([]byte, error) {
	if len(body) > 16<<20 {
		return nil, errors.New("native purchase response exceeds limit")
	}

	if !bytes.HasPrefix(body, []byte{0x1f, 0x8b}) {
		return body, nil
	}

	r, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer r.Close()

	decoded, err := io.ReadAll(io.LimitReader(r, (16<<20)+1))
	if err != nil {
		return nil, err
	}

	if len(decoded) > 16<<20 {
		return nil, errors.New("native purchase response exceeds limit")
	}

	return decoded, nil
}

// Purchase obtains the original personalized Store response in memory. It only
// retries a rejected request once when Apple supplies authorization parameters.
func Purchase(ctx context.Context, remote string, appID int64, progress func(string)) ([]byte, error) {
	if appID <= 0 {
		return nil, errors.New("invalid native purchase app ID")
	}

	assets, err := embeddedAssets()
	if err != nil {
		return nil, err
	}

	source, err := os.ReadFile(assets.purchaseAgent)
	if err != nil {
		return nil, err
	}

	o := &purchaseObserver{complete: make(chan struct{}, 1), progress: progress}

	script, err := fridarpc.Attach(ctx, remote, "itunesstored", string(source), o.event)
	if err != nil {
		return nil, err
	}
	defer script.Close()

	return runPurchase(ctx, script, script.PID, appID, o)
}
func runPurchase(ctx context.Context, script agentRPC, pid uint32, appID int64, o *purchaseObserver) ([]byte, error) {
	params := fmt.Sprintf("productType=C&price=0&pg=default&appExtVrsId=0&pricingParameters=STDQ&salableAdamId=%d", appID)

	for attempt := 0; attempt < 2; attempt++ {
		callCtx, cancel := context.WithTimeout(ctx, 180*time.Second)
		raw, _, err := script.Call(callCtx, "purchaseShim", pid, "com.apple.itunesstored", params)

		cancel()

		if err != nil {
			return nil, fmt.Errorf("native purchase: %w", err)
		}

		var result struct {
			Error json.RawMessage `json:"error"`
		}
		if err = json.Unmarshal(raw, &result); err != nil {
			return nil, errors.New("invalid native purchase result")
		}

		failed := len(result.Error) > 0 && string(result.Error) != "null"

		o.mu.Lock()
		authorization := o.authorization
		eventErr := o.err
		o.authorization = ""
		o.mu.Unlock()

		if eventErr != nil {
			return nil, eventErr
		}

		if failed && attempt == 0 && authorization != "" {
			query, err := url.ParseQuery(authorization)
			if err != nil {
				return nil, errors.New("invalid Store authorization parameters")
			}

			if id := query.Get("salableAdamId"); id != "" && id != strconv.FormatInt(appID, 10) {
				return nil, errors.New("store authorization changed the app ID")
			}

			select {
			case <-o.complete:
			default:
			}

			params = authorization

			continue
		}

		if failed {
			return nil, errors.New("native purchase rejected")
		}

		timer := time.NewTimer(5 * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
			return nil, errors.New("native purchase returned without completion")
		case <-o.complete:
			timer.Stop()
		}

		o.mu.Lock()
		ticket := append([]byte(nil), o.ticket...)
		eventErr = o.err
		o.mu.Unlock()

		if eventErr != nil {
			return nil, eventErr
		}

		if len(ticket) == 0 {
			return nil, errors.New("native purchase returned no ticket")
		}

		return ticket, nil
	}

	return nil, errors.New("native purchase authorization rejected")
}
