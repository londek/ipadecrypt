package anisette

import (
	"testing"
	"time"
)

func TestClosedProviderCannotRestartPregeneration(t *testing.T) {
	p := &NativeProvider{}
	window := Window(time.Now())
	p.storeLocked(window, map[string]string{HeaderMD: "cached"})
	p.Close()
	p.Close()

	if _, err := p.Headers(time.Now()); err == nil {
		t.Fatal("closed provider served headers and could restart its timer")
	}

	p.pregenerate(window + 1) // A timer callback may already be waiting on the mutex.

	if p.prewarm != nil || p.cache[window+1] != nil {
		t.Fatal("closed provider restarted pregeneration")
	}
}
