package anisettecapture

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/londek/ipadecrypt/internal/config"
	"github.com/londek/ipadecrypt/internal/device"
)

// Explicit opt-in only: captures into a separate directory and never replaces
// the user's configured snapshots, logs in, or buys an app.
func TestLiveGoSnapshot(t *testing.T) {
	path, output := os.Getenv("IPADECRYPT_TEST_IDENTITY_CONFIG"), os.Getenv("IPADECRYPT_TEST_CAPTURE_OUTPUT")
	if path == "" || output == "" {
		t.Skip("requires explicit device config and isolated capture output")
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()

	client, err := device.Connect(ctx, cfg.Device)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	if os.Getenv("IPADECRYPT_TEST_CAPTURE_AMD") != "" {
		err = CaptureAMD(ctx, client, output)
	} else {
		err = Capture(ctx, client, output)
	}

	if err != nil {
		t.Fatal(err)
	}
}

type snapshotRPCFunc func(context.Context, string, ...any) (json.RawMessage, []byte, error)

func (f snapshotRPCFunc) Call(ctx context.Context, name string, args ...any) (json.RawMessage, []byte, error) {
	return f(ctx, name, args...)
}

func TestCachedHeadersCannotEstablishCapture(t *testing.T) {
	for _, method := range []string{"requestGsa", "requestAmd"} {
		t.Run(method, func(t *testing.T) {
			var calls atomic.Int32

			rpc := snapshotRPCFunc(func(ctx context.Context, name string, args ...any) (json.RawMessage, []byte, error) {
				calls.Add(1)
				return json.RawMessage(`{"otpB64":"cached","amdB64":"cached","epoch30":1}`), nil, nil
			})
			start := time.Now()

			_, err := awaitReference(context.Background(), rpc, method, make(chan reference), nil, 30*time.Millisecond)
			if !errors.Is(err, context.DeadlineExceeded) || calls.Load() != 1 {
				t.Fatalf("cached result accepted or request repeated: %v, calls=%d", err, calls.Load())
			}

			if time.Since(start) > time.Second {
				t.Fatal("reference wait was not bounded")
			}
		})
	}
}
func TestCaptureAcceptsOnlyDaemonReference(t *testing.T) {
	refs := make(chan reference, 1)

	want := reference{CaptureID: 7, Epoch: 1, OTP: "bound-to-adid"}
	refs <- want

	rpc := snapshotRPCFunc(func(context.Context, string, ...any) (json.RawMessage, []byte, error) {
		t.Fatal("request made after reference arrived")
		return nil, nil, nil
	})

	got, err := awaitReference(context.Background(), rpc, "requestGsa", refs, nil, time.Second)
	if err != nil || got != want {
		t.Fatal("lost daemon reference", err)
	}
}

func TestRoutingReplySurvivesEarlierDaemonReference(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	refs := make(chan reference, 1)
	routing := make(chan string, 1)
	release := make(chan struct{})
	rpc := snapshotRPCFunc(func(ctx context.Context, name string, args ...any) (json.RawMessage, []byte, error) {
		refs <- reference{CaptureID: 42}

		select {
		case <-release:
			return json.RawMessage(`{"routingInfo":"17106176"}`), nil, nil
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		}
	})

	ref, err := awaitReference(ctx, rpc, "requestGsa", refs, routing, time.Second)
	if err != nil || ref.CaptureID != 42 {
		t.Fatal("lost daemon reference", err)
	}

	close(release)

	select {
	case value := <-routing:
		if value != "17106176" {
			t.Fatal("lost routing information")
		}
	case <-time.After(time.Second):
		t.Fatal("request was cancelled before routing information arrived")
	}
}
func TestMemorySelectionExcludesLargeUnrelatedMappings(t *testing.T) {
	info := snapshotInfo{Base: "0x1000", Size: 4096}

	selected, err := selectRanges(info, []memoryRange{
		{Base: "0x1000", Size: 4096, Protection: "r-x", File: "/usr/libexec/adid"},
		{Base: "0x800000000", Size: 256 << 20, Protection: "r--", File: "/dyld_shared_cache"},
		{Base: "0x20000", Size: 4096, Protection: "rw-"},
	})
	if err != nil || len(selected) != 2 || !selected[0].LiveFallback {
		t.Fatalf("selection: %+v %v", selected, err)
	}

	if _, err = selectRanges(info, []memoryRange{{Base: "0x1000", Size: captureMemoryLimit + 1, Protection: "r-x", File: "adid"}}); err == nil {
		t.Fatal("oversized snapshot accepted")
	}
}
