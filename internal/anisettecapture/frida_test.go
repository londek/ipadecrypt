package anisettecapture

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/londek/ipadecrypt/internal/config"
	"github.com/londek/ipadecrypt/internal/device"
)

func TestDEBMember(t *testing.T) {
	var archive bytes.Buffer
	archive.WriteString("!<arch>\n")

	for _, member := range []struct {
		name string
		data []byte
	}{
		{"debian-binary", []byte("2.0\n")},
		{"data.tar.xz", []byte("payload")},
	} {
		fmt.Fprintf(&archive, "%-16s%-12d%-6d%-6d%-8o%-10d`\n", member.name, 0, 0, 0, 0o644, len(member.data))
		archive.Write(member.data)

		if len(member.data)%2 != 0 {
			archive.WriteByte('\n')
		}
	}

	path := filepath.Join(t.TempDir(), "package.deb")
	if err := os.WriteFile(path, archive.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}

	data, err := debMember(path, "data.tar.xz")
	if err != nil {
		t.Fatal(err)
	}

	if string(data) != "payload" {
		t.Fatalf("member = %q, want payload", data)
	}
}

// Explicit opt-in: verifies server ownership and loads the purchase agent without
// calling its purchase RPC. No Store sign-in or purchase is performed.
func TestLiveFridaOwnershipAndPurchaseAgentLoad(t *testing.T) {
	path := os.Getenv("IPADECRYPT_TEST_IDENTITY_CONFIG")
	if path == "" {
		t.Skip("requires explicit device configuration")
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	client, err := device.Connect(ctx, cfg.Device)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	artifacts, err := ensureFridaArtifacts(ctx)
	if err != nil {
		t.Fatal(err)
	}

	first, err := startFridaServerAt(client, artifacts, "127.0.0.1:27042")
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()

	second, err := startFridaServerAt(client, artifacts, "127.0.0.1:27042")
	if err != nil {
		t.Fatal(err)
	}

	if len(second.startedPIDs) != 0 {
		t.Fatal("second instance claimed an existing server")
	}

	if err = second.Close(); err != nil {
		t.Fatal(err)
	}

	if err = second.Close(); err != nil {
		t.Fatal(err)
	}

	assets, err := embeddedAssets()
	if err != nil {
		t.Fatal(err)
	}

	if err = EnsureItunesstored(client); err != nil {
		t.Fatal(err)
	}

	script, err := attachDeviceScript(ctx, client, "itunesstored", assets.purchaseAgent, nil)
	if err != nil {
		t.Fatal(err)
	}

	if err = script.Close(); err != nil {
		t.Fatal(err)
	}

	if err = first.Close(); err != nil {
		t.Fatal(err)
	}

	remaining, err := first.pids()
	if err != nil {
		t.Fatal(err)
	}

	for _, owned := range first.startedPIDs {
		for _, pid := range remaining {
			if pid == owned {
				t.Fatal("owned server survived cleanup")
			}
		}
	}

	t.Logf("ownership and purchase-agent load passed; owned server started: %t", len(first.startedPIDs) > 0)
}
