package anisette

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/londek/ipadecrypt/internal/anisette/nativegen"
)

const pregenerateLead = 3 * time.Second

// NativeProvider generates anisette headers from captured adid state.
// It caches one result per 30-second window and
// pregenerates the next window shortly before the boundary.
type NativeProvider struct {
	Snapshot    string
	SnapshotAMD string
	// Static holds window-independent headers to merge (e.g. X-Apple-I-MD-RINFO
	// and device-identity fields captured once).
	Static map[string]string

	mu      sync.Mutex
	cache   map[int64]map[string]string
	prewarm *time.Timer
	closed  bool
}

func (p *NativeProvider) Headers(t time.Time) (map[string]string, error) {
	window := Window(t)

	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return nil, errors.New("anisette provider is closed")
	}

	if headers := p.cache[window]; headers != nil {
		p.scheduleNextLocked(window)
		return clone(headers), nil
	}

	headers, err := p.generate(window)
	if err != nil {
		return nil, err
	}

	p.storeLocked(window, headers)
	p.scheduleNextLocked(window)

	return clone(headers), nil
}

// Close stops pending pregeneration.
func (p *NativeProvider) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.closed = true

	if p.prewarm != nil {
		p.prewarm.Stop()
		p.prewarm = nil
	}
}

func (p *NativeProvider) generate(window int64) (map[string]string, error) {
	if p.Snapshot == "" {
		return nil, errors.New("offline anisette: snapshot path is required")
	}

	emu, err := nativegen.New(p.Snapshot, window)
	if err != nil {
		return nil, err
	}

	otp, err := emu.Run()
	if err != nil {
		return nil, fmt.Errorf("native offline anisette: %w", err)
	}

	md, err := EncodeMD(otp)
	if err != nil {
		return nil, err
	}

	mid, err := EncodeMID(emu.MID())
	if err != nil {
		return nil, err
	}

	headers := make(map[string]string, len(p.Static)+3)
	for k, v := range p.Static {
		headers[k] = v
	}

	headers[HeaderMD] = md
	headers[HeaderMDM] = mid
	headers["X-Apple-I-Client-Time"] = time.Unix(window*windowSize+1, 0).UTC().Format("2006-01-02T15:04:05Z")

	if p.SnapshotAMD != "" {
		amdEmu, err := nativegen.New(p.SnapshotAMD, window)
		if err != nil {
			return nil, fmt.Errorf("native offline AMD anisette: %w", err)
		}

		amdOTP, err := amdEmu.Run()
		if err != nil {
			return nil, fmt.Errorf("native offline AMD anisette: %w", err)
		}

		amd, err := EncodeAMD(amdOTP)
		if err != nil {
			return nil, err
		}

		amdMID, err := EncodeMID(amdEmu.MID())
		if err != nil {
			return nil, err
		}

		headers[HeaderAMD] = amd
		headers[HeaderAMDM] = amdMID
	}

	return headers, nil
}

func (p *NativeProvider) storeLocked(window int64, headers map[string]string) {
	if p.cache == nil {
		p.cache = make(map[int64]map[string]string)
	}

	for cachedWindow := range p.cache {
		if cachedWindow < window-1 || cachedWindow > window+1 {
			delete(p.cache, cachedWindow)
		}
	}

	p.cache[window] = clone(headers)
}

func (p *NativeProvider) scheduleNextLocked(window int64) {
	if window != Window(time.Now()) {
		return
	}

	if p.prewarm != nil {
		p.prewarm.Stop()
	}

	nextStart := time.Unix((window+1)*windowSize, 0)
	delay := time.Until(nextStart.Add(-pregenerateLead))
	nextWindow := window + 1
	p.prewarm = time.AfterFunc(delay, func() {
		p.pregenerate(nextWindow)
	})
}

func (p *NativeProvider) pregenerate(window int64) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed || p.cache[window] != nil {
		return
	}

	headers, err := p.generate(window)
	if err != nil {
		return
	}

	p.storeLocked(window, headers)
}
