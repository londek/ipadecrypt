package machine

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/londek/ipadecrypt/internal/sap/unicorn"
)

func TestContentEnrollmentCancellation(t *testing.T) {
	if os.Getenv("IPADECRYPT_TEST_APPLE_RUNTIME") != "1" {
		t.Skip("requires pinned Apple runtime assets")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	called := false
	sidb, err := EnrollContent(ctx, []byte{2, 3, 4, 5, 6, 7}, 12345, func(ctx context.Context, blob []byte) ([]byte, error) {
		called = true
		if len(blob) == 0 {
			t.Error("empty KBSync")
		}
		cancel()
		return []byte("must not be imported after cancellation"), nil
	})
	if !called || len(sidb) != 0 || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled enrollment published state: called=%v size=%d error=%v", called, len(sidb), err)
	}
}

func newServiceTestMachine(t *testing.T) *Machine {
	t.Helper()

	engine, err := unicorn.New(context.Background())
	if err != nil {
		t.Fatalf("create Unicorn engine: %v", err)
	}

	for _, region := range []struct {
		address uint64
		size    uint64
	}{
		{returnAddress, pageSize},
		{scratchBase, scratchSize},
		{heapBase, heapSize},
		{stackBase, stackSize},
	} {
		if err := engine.MemMap(region.address, region.size); err != nil {
			_ = engine.Close()

			t.Fatal(err)
		}
	}

	if err := engine.MemWrite(returnAddress, []byte{0x00, 0x00, 0x20, 0xd4}); err != nil {
		_ = engine.Close()

		t.Fatal(err)
	}

	services, err := newShims(engine, map[string]uint64{}, nil)
	if err != nil {
		_ = engine.Close()

		t.Fatal(err)
	}

	machine := &Machine{engine: engine, services: services}

	t.Cleanup(func() {
		if err := machine.Close(); err != nil {
			t.Errorf("close machine: %v", err)
		}
	})

	return machine
}
