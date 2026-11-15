package anisettecapture

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/londek/ipadecrypt/internal/fridarpc"
	"howett.net/plist"
)

func purchaseResponse(t *testing.T, o *purchaseObserver, value any, compressed bool) []byte {
	t.Helper()

	body, err := plist.Marshal(value, plist.XMLFormat)
	if err != nil {
		t.Fatal(err)
	}

	data := body

	if compressed {
		var b bytes.Buffer

		w := gzip.NewWriter(&b)
		if _, err := w.Write(body); err != nil {
			t.Fatal(err)
		}

		if err := w.Close(); err != nil {
			t.Fatal(err)
		}

		data = b.Bytes()
	}

	o.event(fridarpc.Event{Payload: json.RawMessage(`{"event":"response","url":"https://store.invalid/buyProduct"}`), Data: data})

	return body
}

func TestNativePurchaseAuthorizedRetry(t *testing.T) {
	o := &purchaseObserver{complete: make(chan struct{}, 1)}

	const authorization = "salableAdamId=123&authorization=fixture"

	calls := 0

	var want []byte

	rpc := snapshotRPCFunc(func(ctx context.Context, name string, args ...any) (json.RawMessage, []byte, error) {
		calls++

		if name != "purchaseShim" || args[0] != uint32(42) || args[1] != "com.apple.itunesstored" {
			t.Fatal("incorrect native purchase invocation")
		}

		if calls == 1 {
			if !strings.Contains(args[2].(string), "salableAdamId=123") {
				t.Fatal("incorrect app ID")
			}

			purchaseResponse(t, o, map[string]any{"dialog": map[string]any{"okButtonAction": map[string]any{"buyParams": authorization}}}, false)
			o.event(fridarpc.Event{Payload: json.RawMessage(`{"event":"purchaseComplete"}`)})

			return json.RawMessage(`{"error":{"code":1}}`), nil, nil
		}

		if calls != 2 || args[2] != authorization {
			t.Fatal("authorization not used exactly once")
		}

		want = purchaseResponse(t, o, map[string]any{"jingleDocType": "purchaseSuccess", "payload": "personalized fixture"}, true)
		o.event(fridarpc.Event{Payload: json.RawMessage(`{"event":"purchaseComplete"}`)})

		return json.RawMessage(`{"error":null}`), nil, nil
	})

	got, err := runPurchase(context.Background(), rpc, 42, 123, o)
	if err != nil || calls != 2 || !bytes.Equal(got, want) {
		t.Fatalf("authorized purchase: calls=%d, err=%v, ticket matches=%t", calls, err, bytes.Equal(got, want))
	}
}

func TestNativePurchaseRejectsWithoutBlindRetry(t *testing.T) {
	for _, tc := range []struct {
		name, authorization, response string
		calls                         int
	}{
		{"no authorization", "", `{"error":{"code":1}}`, 1},
		{"different app", "salableAdamId=456", `{"error":{"code":1}}`, 1},
		{"repeated rejection", "salableAdamId=123", `{"error":{"code":1}}`, 2},
		{"no ticket", "", `{"error":null}`, 1},
		{"invalid result", "", `invalid`, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := &purchaseObserver{complete: make(chan struct{}, 1)}
			calls := 0

			rpc := snapshotRPCFunc(func(context.Context, string, ...any) (json.RawMessage, []byte, error) {
				calls++

				o.mu.Lock()
				o.authorization = tc.authorization
				o.mu.Unlock()
				o.event(fridarpc.Event{Payload: json.RawMessage(`{"event":"purchaseComplete"}`)})

				return json.RawMessage(tc.response), nil, nil
			})
			if _, err := runPurchase(context.Background(), rpc, 42, 123, o); err == nil || calls != tc.calls {
				t.Fatalf("calls=%d, error=%v", calls, err)
			}
		})
	}
}

func TestNativePurchaseWaitCancellation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	o := &purchaseObserver{complete: make(chan struct{}, 1)}

	rpc := snapshotRPCFunc(func(context.Context, string, ...any) (json.RawMessage, []byte, error) {
		return json.RawMessage(`{"error":null}`), nil, nil
	})
	if _, err := runPurchase(ctx, rpc, 42, 123, o); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("completion wait ignored cancellation: %v", err)
	}
}

func TestNativePurchaseMalformedAndOversizedResponse(t *testing.T) {
	var compressed bytes.Buffer

	w := gzip.NewWriter(&compressed)
	_, _ = w.Write(bytes.Repeat([]byte("x"), (16<<20)+1))
	_ = w.Close()

	for _, data := range [][]byte{{0x1f, 0x8b}, []byte("not a plist"), compressed.Bytes()} {
		o := &purchaseObserver{complete: make(chan struct{}, 1)}
		o.event(fridarpc.Event{Payload: json.RawMessage(`{"event":"response","url":"https://store.invalid/buyProduct"}`), Data: data})

		if o.err == nil || len(o.ticket) != 0 {
			t.Fatal("malformed or oversized response accepted")
		}
	}
}
