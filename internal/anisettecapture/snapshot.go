package anisettecapture

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/londek/ipadecrypt/internal/anisette/nativegen"
	"github.com/londek/ipadecrypt/internal/device"
	"github.com/londek/ipadecrypt/internal/fridarpc"
)

const captureMemoryLimit = 128 << 20
const captureChunk = 256 << 10
const captureVAMask = 0xfffffffff

type memoryRange struct {
	Base         string `json:"base"`
	Size         int    `json:"size"`
	Protection   string `json:"prot,omitempty"`
	File         string `json:"file,omitempty"`
	LiveFallback bool   `json:"liveFallback,omitempty"`
	FileOffset   int    `json:"fileOff"`
}
type snapshotInfo struct {
	Base           string            `json:"base"`
	Size           int               `json:"size"`
	Path           string            `json:"path"`
	Imports        map[string]string `json:"imports"`
	StackGuard     json.RawMessage   `json:"stackGuard"`
	HandlerAddress string            `json:"handlerAddress"`
	HandlerBytes   string            `json:"handlerBytes"`
}
type reference struct {
	Event     string `json:"event"`
	CaptureID int64  `json:"captureId"`
	Epoch     int64  `json:"epoch30"`
	OTP       string `json:"otpB64"`
	AMD       string `json:"amdB64"`
	MID       string `json:"midB64"`
}
type agentRPC interface {
	Call(context.Context, string, ...any) (json.RawMessage, []byte, error)
}

func rpcJSON(ctx context.Context, s agentRPC, method string, out any, args ...any) error {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	raw, _, err := s.Call(ctx, method, args...)
	if err != nil {
		return fmt.Errorf("%s: %w", method, err)
	}

	if out == nil {
		return nil
	}

	return json.Unmarshal(raw, out)
}
func hexAddress(s string) (uint64, error) {
	return strconv.ParseUint(strings.TrimPrefix(s, "0x"), 16, 64)
}
func writeCapture(path string, value []byte) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}

	_, err = f.Write(value)

	return errors.Join(err, f.Close())
}
func writeCaptureJSON(path string, value any) error {
	b, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}

	return writeCapture(path, append(b, '\n'))
}
func captureLog(format string, args ...any) { fmt.Fprintf(os.Stderr, "[bc] "+format+"\n", args...) }

func selectRanges(info snapshotInfo, ranges []memoryRange) ([]memoryRange, error) {
	base, err := hexAddress(info.Base)
	if err != nil {
		return nil, err
	}

	var selected []memoryRange

	total := 0

	for _, r := range ranges {
		addr, err := hexAddress(r.Base)
		if err != nil || r.Size <= 0 {
			return nil, errors.New("invalid adid memory range")
		}

		if strings.Contains(r.File, "adid") || (addr >= base && addr-base < uint64(info.Size)) || (r.File == "" && strings.HasPrefix(r.Protection, "rw") && r.Size <= 4<<20) {
			r.LiveFallback = strings.HasSuffix(r.Protection, "x")
			selected = append(selected, r)

			total += r.Size
			if total > captureMemoryLimit {
				return nil, errors.New("adid memory selection exceeds limit")
			}
		}
	}

	if len(selected) == 0 {
		return nil, errors.New("empty adid memory selection")
	}

	return selected, nil
}

func captureSnapshot(ctx context.Context, client *device.Client, assets captureAssets, output string, amd bool) (retErr error) {
	ctx, cancelCapture := context.WithCancel(ctx)
	defer cancelCapture()

	started := time.Now()
	references := make(chan reference, 4)
	events := func(event fridarpc.Event) {
		var r reference
		if json.Unmarshal(event.Payload, &r) == nil && r.Event == "adid-locked" && r.CaptureID > 0 {
			select {
			case references <- r:
			default:
			}
		}
	}

	captureLog("attaching to adid")

	dump, err := attachDeviceScript(ctx, client, "adid", assets.dumpAgent, events)
	if err != nil {
		return err
	}

	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()

		_ = rpcJSON(cleanup, dump, "finish", nil)
		if err := dump.Close(); err != nil {
			// The owner verifies the executable path before releasing this PID.
			retErr = errors.Join(retErr, releaseCapturedAdid(client, int(dump.PID)))
		}
	}()

	if amd {
		if err = rpcJSON(ctx, dump, "target", nil, 4); err != nil {
			return err
		}
	}

	var (
		info   snapshotInfo
		ranges []memoryRange
	)

	if err = rpcJSON(ctx, dump, "info", &info); err != nil {
		return err
	}

	if err = rpcJSON(ctx, dump, "ranges", &ranges); err != nil {
		return err
	}

	selected, err := selectRanges(info, ranges)
	if err != nil {
		return err
	}

	encoded, err := json.Marshal(selected)
	if err != nil {
		return err
	}

	if err = rpcJSON(ctx, dump, "prepare", nil, string(encoded)); err != nil {
		return err
	}

	trigger, err := attachDeviceScript(ctx, client, "itunesstored", assets.triggerAgent, nil)
	if err != nil {
		return err
	}
	defer trigger.Close()

	var static map[string]string
	if !amd {
		if err = rpcJSON(ctx, trigger, "staticHeaders", &static); err != nil {
			return err
		}
	}

	request := "requestGsa"
	if amd {
		request = "requestAmd"
	}

	captureLog("requesting %s once; waiting for the matching adid reply", request)

	routing := make(chan string, 1)

	ref, err := awaitReference(ctx, trigger, request, references, routing, 25*time.Second)
	if err != nil {
		return err
	}

	if amd {
		var frozen bool
		if err = rpcJSON(ctx, dump, "freeze", &frozen); err != nil {
			return err
		}

		if !frozen {
			return errors.New("adid rejected deferred freeze")
		}
	}

	var captured map[string]json.RawMessage

	contextCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	for captured == nil {
		if err = rpcJSON(contextCtx, dump, "context", &captured); err != nil {
			return err
		}

		if captured == nil {
			select {
			case <-contextCtx.Done():
				return contextCtx.Err()
			case <-time.After(20 * time.Millisecond):
			}
		}
	}

	var captureID int64
	if err = json.Unmarshal(captured["captureId"], &captureID); err != nil {
		return err
	}

	if captureID != ref.CaptureID {
		return errors.New("adid reference/context invocation mismatch")
	}

	var (
		regs         map[string]string
		frozenErrors map[string]any
	)

	if err = json.Unmarshal(captured["regs"], &regs); err != nil {
		return err
	}

	_ = json.Unmarshal(captured["frozenErrors"], &frozenErrors)

	sp, err := hexAddress(regs["sp"])
	if err != nil || sp < 0x80000 {
		return errors.New("invalid captured stack pointer")
	}

	var (
		layout []memoryRange
		blob   []byte
	)

	transferStarted := time.Now()

	for _, r := range selected {
		base, _ := hexAddress(r.Base)
		if !r.LiveFallback && base < sp+0x80000 && sp-0x80000 < base+uint64(r.Size) {
			continue
		}

		if frozenErrors[r.Base] != nil && !r.LiveFallback {
			return errors.New("selected adid memory could not be frozen")
		}

		r.FileOffset = len(blob)
		for offset := 0; offset < r.Size; offset += captureChunk {
			n := min(captureChunk, r.Size-offset)
			callCtx, stop := context.WithTimeout(ctx, 20*time.Second)

			_, chunk, e := dump.Call(callCtx, "readFrozenBytes", r.Base, offset, n)
			if e == nil && chunk == nil && r.LiveFallback {
				_, chunk, e = dump.Call(callCtx, "readLiveBytes", fmt.Sprintf("0x%x", base+uint64(offset)), n)
			}

			stop()

			if e != nil {
				return fmt.Errorf("transfer frozen adid memory: %w", e)
			}

			if len(chunk) != n {
				return errors.New("incomplete frozen adid memory chunk")
			}

			blob = append(blob, chunk...)
		}

		layout = append(layout, memoryRange{Base: r.Base, Size: r.Size, FileOffset: r.FileOffset})
	}

	transferSeconds := time.Since(transferStarted).Seconds()

	if err = restoreHandler(blob, layout, info); err != nil {
		return err
	}

	if err = writeCapture(filepath.Join(output, "adidmem.bin"), blob); err != nil {
		return err
	}

	var local map[string]string
	if err = rpcJSON(ctx, dump, "localImports", &local); err != nil {
		return err
	}

	if info.Imports == nil {
		info.Imports = map[string]string{}
	}

	for key, value := range local {
		info.Imports[key] = value
	}

	if err = resolveSharedImports(ctx, client, info.Imports); err != nil {
		return err
	}

	slots := importSlots(blob, layout, info.Imports)

	manifest := map[string]any{"moduleBase": info.Base, "moduleSize": info.Size, "path": info.Path, "imports": info.Imports, "importSlots": slots, "blob": "adidmem.bin", "ranges": layout}
	if len(info.StackGuard) > 0 && string(info.StackGuard) != "null" {
		manifest["stackGuard"] = info.StackGuard
	}

	if err = writeCaptureJSON(filepath.Join(output, "manifest.json"), manifest); err != nil {
		return err
	}

	var stack []byte
	if err = json.Unmarshal(captured["stack"], &stack); err != nil || len(stack) == 0 {
		return errors.New("captured adid stack is empty")
	}

	if err = writeCapture(filepath.Join(output, "stack.bin"), stack); err != nil {
		return err
	}

	delete(captured, "stack")

	key, otpType := ref.OTP, 5
	if amd {
		key, otpType = ref.AMD, 4
	}

	for name, value := range map[string]any{"refOtpB64": key, "refEpoch30": ref.Epoch, "refMidB64": ref.MID, "otpType": otpType} {
		captured[name], _ = json.Marshal(value)
	}

	if err = writeCaptureJSON(filepath.Join(output, "ctx.json"), captured); err != nil {
		return err
	}

	if err = primeSnapshot(ctx, dump, output, key, ref.MID, ref.Epoch, amd); err != nil {
		return err
	}

	select {
	case value := <-routing:
		if value != "" && !amd {
			if static == nil {
				static = make(map[string]string)
			}

			static["X-Apple-I-MD-RINFO"] = value
		}
	default:
	}

	if len(static) > 0 {
		if err = writeCaptureJSON(filepath.Join(output, "static.json"), static); err != nil {
			return err
		}
	}

	captureLog("snapshot verified; %d bytes captured in %.1fs", len(blob), time.Since(started).Seconds())

	return writeCaptureJSON(filepath.Join(output, "capture-metrics.json"), map[string]any{"totalSeconds": time.Since(started).Seconds(), "transferSeconds": transferSeconds, "snapshotBytes": len(blob), "transferChunkBytes": captureChunk, "referenceSource": "adid-reply", "selfCheckMatched": true})
}

func awaitReference(ctx context.Context, trigger agentRPC, method string, refs <-chan reference, routing chan<- string, timeout time.Duration) (reference, error) {
	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	select {
	case ref := <-refs:
		return ref, nil
	default:
	}

	result := make(chan error, 1)

	go func() {
		var reply struct {
			Unavailable bool   `json:"unavailable"`
			RoutingInfo string `json:"routingInfo"`
		}
		// The daemon event can precede the AuthKit reply. Keep the request alive
		// until the capture ends so its optional routing header is not lost.
		err := rpcJSON(ctx, trigger, method, &reply)
		if err == nil && routing != nil {
			select {
			case routing <- reply.RoutingInfo:
			default:
			}
		}

		if reply.Unavailable {
			err = errors.New("native anisette request is unavailable")
		}

		result <- err
	}()

	for {
		select {
		case ref := <-refs:
			return ref, nil
		case err := <-result:
			if err != nil && !errors.Is(err, context.DeadlineExceeded) {
				return reference{}, err
			}

			result = nil
		case <-waitCtx.Done():
			return reference{}, fmt.Errorf("no matching adid invocation captured; unlock the iPhone and check App Store sign-in: %w", waitCtx.Err())
		}
	}
}

func restoreHandler(blob []byte, layout []memoryRange, info snapshotInfo) error {
	address, err := hexAddress(info.HandlerAddress)
	if err != nil {
		return err
	}

	data, err := base64.StdEncoding.DecodeString(info.HandlerBytes)
	if err != nil || len(data) == 0 {
		return errors.New("invalid original adid handler bytes")
	}

	for _, r := range layout {
		base, _ := hexAddress(r.Base)
		if address >= base && address-base+uint64(len(data)) <= uint64(r.Size) {
			copy(blob[r.FileOffset+int(address-base):], data)
			return nil
		}
	}

	return errors.New("adid handler is missing from the snapshot")
}
func importSlots(blob []byte, layout []memoryRange, imports map[string]string) map[string]string {
	targets := map[uint64]string{}

	for name, value := range imports {
		if addr, err := hexAddress(value); err == nil {
			targets[addr&captureVAMask] = name
		}
	}

	slots := map[string]string{}

	for _, r := range layout {
		base, _ := hexAddress(r.Base)
		for offset := 0; offset+8 <= r.Size; offset += 8 {
			value := binary.LittleEndian.Uint64(blob[r.FileOffset+offset:])
			if name, ok := targets[value&captureVAMask]; ok {
				slots[fmt.Sprintf("0x%x", base+uint64(offset))] = name
			}
		}
	}

	return slots
}

func resolveSharedImports(ctx context.Context, client *device.Client, imports map[string]string) error {
	const source = `rpc.exports={resolve(names){const out={};for(const name of names){try{const p=Module.getGlobalExportByName(name);if(p)out[name]=p.toString();}catch(e){}}return out;}};`

	conn, err := client.DialContext(ctx, "127.0.0.1:27042")
	if err != nil {
		return err
	}

	s, err := fridarpc.AttachConn(ctx, conn, "127.0.0.1:27042", "itunesstored", source, nil)
	if err != nil {
		return err
	}
	defer s.Close()

	names := []string{"pthread_getspecific", "pthread_setspecific", "pthread_key_create", "pthread_key_init_np", "malloc_type_malloc", "malloc_type_calloc", "malloc_type_realloc", "malloc_type_free", "malloc_type_zone_malloc", "malloc_type_zone_calloc"}

	var values map[string]string
	if err = rpcJSON(ctx, s, "resolve", &values, names); err != nil {
		return err
	}

	for name, value := range values {
		if imports[name] == "" {
			imports[name] = value
		}
	}

	return nil
}

func primeSnapshot(ctx context.Context, dump agentRPC, output, otpB64, midB64 string, epoch int64, amd bool) error {
	reference, err := base64.StdEncoding.DecodeString(otpB64)

	want := 28
	if amd {
		want = 24
	}

	if err != nil || len(reference) != want || epoch <= 0 {
		return errors.New("invalid device anisette reference")
	}

	emu, err := nativegen.New(output, epoch)
	if err != nil {
		return err
	}

	emu.Fetch = func(address uint64, size int) ([]byte, error) {
		for attempt := 0; attempt < 3; attempt++ {
			var encoded string
			if err := rpcJSON(ctx, dump, "readLive", &encoded, fmt.Sprintf("0x%x", address), size); err != nil {
				return nil, err
			}

			if encoded != "" {
				return base64.StdEncoding.DecodeString(encoded)
			}

			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(20 * time.Millisecond):
			}
		}

		return nil, fmt.Errorf("live adid page unavailable at %#x", address)
	}

	captureLog("priming snapshot with the Go emulator")

	otp, err := emu.RunContext(ctx)
	if err != nil {
		return err
	}

	if !bytes.Equal(otp, reference[8:24]) {
		return errors.New("snapshot OTP does not match the captured adid reply")
	}

	if len(emu.MID()) != 60 {
		return errors.New("snapshot did not produce a valid MID")
	}

	if midB64 != "" {
		mid, err := base64.StdEncoding.DecodeString(midB64)
		if err != nil || !bytes.Equal(mid, emu.MID()) {
			return errors.New("snapshot MID does not match the captured adid reply")
		}
	}

	pages := map[string]string{}
	for address, value := range emu.FetchedPages {
		pages[fmt.Sprintf("0x%x", address)] = base64.StdEncoding.EncodeToString(value)
	}

	if err = writeCaptureJSON(filepath.Join(output, "fetched_pages.json"), pages); err != nil {
		return err
	}
	// A second run must succeed using only the newly persisted snapshot.
	offline, err := nativegen.New(output, epoch)
	if err != nil {
		return err
	}

	otp, err = offline.RunContext(ctx)
	if err != nil {
		return err
	}

	if !bytes.Equal(otp, reference[8:24]) || !bytes.Equal(offline.MID(), emu.MID()) {
		return errors.New("offline snapshot verification failed")
	}

	return nil
}
