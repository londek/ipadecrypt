// Package nativegen implements adid OTP emulation in Go on top of
// internal/sap/unicorn. The whitebox crypto runs natively
// inside Unicorn; this package only provides the thin control layer: arm64e PAC
// handling, libSystem/XPC import stubs, snapshot loading, and OTP capture.
//
// Opt-in reference tests compare OTP and MID against captured device replies;
// synthetic tests cover the emulator's import and instruction handling.
package nativegen

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/londek/ipadecrypt/internal/sap/unicorn"
)

const (
	vaMask     = 0xFFFFFFFFF // 36-bit user VA; strips arm64e PAC high bits
	page       = 0x1000
	stackBase  = 0x900000000
	stackSize  = 0x400000
	heapBase   = 0xA00000000
	heapSize   = 0x4000000
	inputBase  = 0xB00000000
	sentinel   = 0xC00000000
	onceReturn = 0xC00001000
	mmapBase   = 0xD00000000
	tlsBase    = 0xE00001000
	handlerOff = 0x116f8c
	defltCap   = 10_000_000
)

// adi.pb struct stat (regular file, size 915) so the provisioning lstat does not
// short-circuit.
const adiPBStatHex = "0a000001b68101008bab000000000000f5010000feffffff0000000000000000" +
	"a5feed6a00000000a8330a1b00000000f50fee6a00000000c439852500000000" +
	"f50fee6a00000000c439852500000000a5feed6a00000000a8330a1b00000000" +
	"930300000000000008000000000000000010000000000000000000000000000000" +
	"000000000000000000000000000000000000"

var retInsn = []byte{0xc0, 0x03, 0x5f, 0xd6} // RET

func regX(n int) int { return unicorn.RegX0 + n }

func alignDown(x uint64) uint64 { return x &^ (page - 1) }
func alignUp(x uint64) uint64   { return (x + page - 1) &^ (page - 1) }

func parseHex(s string) (uint64, error) {
	s = strings.TrimPrefix(strings.TrimSpace(s), "0x")
	return strconv.ParseUint(s, 16, 64)
}

type rangeEntry struct {
	Base  string `json:"base"`
	Size  int    `json:"size"`
	FileO int    `json:"fileOff"`
}

type stackGuard struct {
	Address string `json:"address"`
	Value   string `json:"value"`
}

type manifest struct {
	ModuleBase  string            `json:"moduleBase"`
	Blob        string            `json:"blob"`
	Ranges      []rangeEntry      `json:"ranges"`
	Imports     map[string]string `json:"imports"`
	ImportSlots map[string]string `json:"importSlots"`
	StackGuard  *stackGuard       `json:"stackGuard"`
}

type ctxFile struct {
	Regs       map[string]string `json:"regs"`
	StackLo    string            `json:"stackLo"`
	X0         string            `json:"x0"`
	Input      json.RawMessage   `json:"input"`
	RefEpoch30 int64             `json:"refEpoch30"`
	RefOTPB64  string            `json:"refOtpB64"`
	OTPType    uint32            `json:"otpType"`
}

// Emu is one offline emulation of adid's XPC OTP handler over a frozen snapshot.
type Emu struct {
	// Fetch supplies live shared-cache pages during initial snapshot priming.
	// Offline runs leave it nil. Successfully fetched pages can be persisted.
	Fetch         func(address uint64, size int) ([]byte, error)
	FetchedPages  map[uint64][]byte
	importPages   map[uint64]bool
	runContext    context.Context
	dir           string
	man           manifest
	blob          []byte
	modBase       uint64
	epochOverride int64
	counterSec    uint64
	InsnCap       int
	OTPType       uint32

	eng         *unicorn.Engine
	mapped      [][2]uint64
	heapPtr     uint64
	mmapPtr     uint64
	importByAdr map[uint64]string
	actCache    map[uint64]action
	onceStack   []uint64
	cfTSD       uint64            // cached CF thread-specific-data table (singleton)
	tls         map[uint64]uint64 // pthread per-key thread-local storage
	pthreadKey  uint64            // next pthread_key_create id

	insnCount int
	otp16     []byte
	midBlock  []byte
	done      bool
	fault     error

	RefOTPB64 string
}

type actKind uint8

const (
	actNormal          actKind = iota // 0: Unicorn runs it
	actBranch                         // 1: braa/blraa family (indirect branch w/ auth)
	actRet                            // 2: retaa/retab
	actSwap                           // 3: swp* atomic
	actStrip                          // 4: aut*/xpac* (strip reg)
	actSkip                           // 5: pac* (identity-skip)
	actCompareSwap                    // 6: casa/casal
	actTLS                            // 7: mrs tpidrro_el0
	actLoadClear                      // 8: ldclr*
	actLoadSet                        // 9: ldset*
	actSyscall                        // 10: svc
	actCompareSwapPair                // 11: casp*
	actAtomic                         // 12: ldadd/ldclr/ldset/ldeor/ld*max/ld*min/swap
	actLoadAcquire                    // 13: ldapr*
)

type action struct {
	kind   actKind
	reg    int  // branch target reg / strip reg
	isLink bool // bl* variant
	// swap operands
	rs, rt, rn int
	rs2, rt2   int
	width      int
	op         uint32
}

// New loads a snapshot. epoch30>0 pins the OTP window; 0 uses the snapshot's
// own refEpoch30.
func New(dir string, epoch30 int64) (*Emu, error) {
	e := &Emu{
		dir:           dir,
		epochOverride: epoch30,
		InsnCap:       defltCap,
		OTPType:       5,
		heapPtr:       heapBase,
		mmapPtr:       mmapBase,
		importByAdr:   map[uint64]string{},
		actCache:      map[uint64]action{},
		tls:           map[uint64]uint64{},
		pthreadKey:    0x40,
	}
	if epoch30 > 0 {
		e.counterSec = uint64(epoch30*30 + 1)
	}

	mb, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal(mb, &e.man); err != nil {
		return nil, fmt.Errorf("manifest: %w", err)
	}

	if !filepath.IsLocal(e.man.Blob) {
		return nil, fmt.Errorf("manifest blob must be a local relative path")
	}

	for _, r := range e.man.Ranges {
		base, err := parseHex(r.Base)
		if err != nil || r.FileO < 0 || r.Size <= 0 || uint64(r.Size) > ^uint64(0)-base {
			return nil, fmt.Errorf("invalid snapshot memory range %q", r.Base)
		}
	}

	if e.modBase, err = parseHex(e.man.ModuleBase); err != nil {
		return nil, fmt.Errorf("moduleBase: %w", err)
	}

	return e, nil
}

func (e *Emu) overlaps(a0, a1 uint64) bool {
	for _, r := range e.mapped {
		if a0 < r[1] && r[0] < a1 {
			return true
		}
	}

	return false
}

func (e *Emu) mapPage(addr uint64) error {
	p := alignDown(addr)
	if !e.overlaps(p, p+page) {
		if err := e.eng.MemMap(p, page); err != nil {
			return err
		}

		e.mapped = append(e.mapped, [2]uint64{p, p + page})
	}

	return nil
}

func (e *Emu) mapRegion(base uint64, data []byte) error {
	ab := alignDown(base)

	ae := alignUp(base + uint64(len(data)))
	if !e.overlaps(ab, ae) {
		if err := e.eng.MemMap(ab, ae-ab); err != nil {
			return err
		}

		e.mapped = append(e.mapped, [2]uint64{ab, ae})
	} else {
		for off := ab; off < ae; off += page {
			if err := e.mapPage(off); err != nil {
				return err
			}
		}
	}

	if len(data) > 0 {
		return e.eng.MemWrite(base, data)
	}

	return nil
}

func (e *Emu) snapshotRead(addr uint64, size int) []byte {
	if size < 0 {
		return nil
	}

	for _, r := range e.man.Ranges {
		b, err := parseHex(r.Base)
		if err != nil {
			continue
		}

		if b <= addr && addr-b <= uint64(r.Size) && uint64(size) <= uint64(r.Size)-(addr-b) {
			off := r.FileO + int(addr-b)
			if off >= 0 && off <= len(e.blob) && size <= len(e.blob)-off {
				return e.blob[off : off+size]
			}
		}
	}

	return nil
}

func (e *Emu) malloc(size uint64) uint64 {
	p := e.heapPtr
	e.heapPtr = (e.heapPtr + size + 15) &^ 15

	return p
}

func (e *Emu) load() error {
	var err error
	if e.blob, err = os.ReadFile(filepath.Join(e.dir, e.man.Blob)); err != nil {
		return err
	}

	for _, r := range e.man.Ranges {
		base, err := parseHex(r.Base)
		if err != nil {
			return err
		}

		if r.FileO > len(e.blob) || r.Size > len(e.blob)-r.FileO {
			return fmt.Errorf("snapshot range %s exceeds memory blob", r.Base)
		}

		if err := e.mapRegion(base, e.blob[r.FileO:r.FileO+r.Size]); err != nil {
			return fmt.Errorf("map range %s: %w", r.Base, err)
		}
	}
	// Shared-cache pages are optional, but a present cache must be readable.
	fp, err := os.ReadFile(filepath.Join(e.dir, "fetched_pages.json"))
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("read fetched pages: %w", err)
	}

	if err == nil {
		var pages map[string]string
		if err := json.Unmarshal(fp, &pages); err != nil {
			return fmt.Errorf("decode fetched pages: %w", err)
		}

		for k, v := range pages {
			addr, err := parseHex(k)
			if err != nil {
				return fmt.Errorf("fetched page address: %w", err)
			}

			data, err := base64.StdEncoding.DecodeString(v)
			if err != nil {
				return fmt.Errorf("fetched page data: %w", err)
			}

			if err := e.mapRegion(addr, data); err != nil {
				return fmt.Errorf("map fetched page: %w", err)
			}
		}
	}
	// scratch regions
	for _, m := range [][2]uint64{{stackBase, stackSize}, {heapBase, heapSize}, {inputBase, page}} {
		if err := e.eng.MemMap(m[0], m[1]); err != nil {
			return err
		}

		e.mapped = append(e.mapped, [2]uint64{m[0], m[0] + m[1]})
	}

	if err := e.mapPage(sentinel); err != nil {
		return err
	}

	if err := e.eng.MemWrite(sentinel, retInsn); err != nil {
		return err
	}

	if err := e.eng.MemMap(onceReturn, page); err != nil {
		return err
	}

	e.mapped = append(e.mapped, [2]uint64{onceReturn, onceReturn + page})
	if err := e.eng.MemWrite(onceReturn, retInsn); err != nil {
		return err
	}

	if err := e.eng.MemMap(tlsBase-0x10000, 0x20000); err != nil {
		return err
	}

	e.mapped = append(e.mapped, [2]uint64{tlsBase - 0x10000, tlsBase + 0x10000})

	return e.setupStubs()
}

func (e *Emu) setupStubs() error {
	e.importPages = map[uint64]bool{}
	imports := map[string]uint64{}

	for name, a := range e.man.Imports {
		if a == "" {
			continue
		}

		addr, err := parseHex(a)
		if err != nil {
			continue
		}

		addr &= vaMask
		imports[name] = addr
		e.importByAdr[addr] = name

		e.importPages[alignDown(addr)] = true
		if err := e.mapPage(addr); err != nil {
			return err
		}

		if err := e.eng.MemWrite(addr, retInsn); err != nil {
			return err
		}
	}

	for slot, name := range e.man.ImportSlots {
		target, ok := imports[name]
		if !ok {
			continue
		}

		addr, err := parseHex(slot)
		if err != nil {
			continue
		}

		var b [8]byte
		binary.LittleEndian.PutUint64(b[:], target)
		_ = e.eng.MemWrite(addr, b[:])
	}

	if g := e.man.StackGuard; g != nil {
		addr, err1 := parseHex(g.Address)

		val, err2 := parseHex(g.Value)
		if err1 == nil && err2 == nil {
			addr &= vaMask
			_ = e.mapPage(addr)

			var b [8]byte
			binary.LittleEndian.PutUint64(b[:], val)
			_ = e.eng.MemWrite(addr, b[:])
		}
	}

	return nil
}

// Run executes the handler and returns the 16-byte OTP (and populates MID()).
func (e *Emu) Run() ([]byte, error) {
	return e.RunContext(context.Background())
}

func (e *Emu) RunContext(runContext context.Context) ([]byte, error) {
	e.runContext = runContext

	eng, err := unicorn.New(runContext)
	if err != nil {
		return nil, err
	}

	e.eng = eng
	defer eng.Close()

	if err := e.load(); err != nil {
		return nil, err
	}

	cb, err := os.ReadFile(filepath.Join(e.dir, "ctx.json"))
	if err != nil {
		return nil, err
	}

	var ctx ctxFile
	if err := json.Unmarshal(cb, &ctx); err != nil {
		return nil, fmt.Errorf("ctx: %w", err)
	}

	e.RefOTPB64 = ctx.RefOTPB64
	if ctx.OTPType != 0 {
		e.OTPType = ctx.OTPType
	}

	if e.OTPType != 4 && e.OTPType != 5 {
		return nil, fmt.Errorf("unsupported OTP TLV type %d", e.OTPType)
	}

	if ctx.RefEpoch30 != 0 && e.epochOverride == 0 {
		e.counterSec = uint64(ctx.RefEpoch30*30 + 1)
	}

	sp, err := parseHex(ctx.Regs["sp"])
	if err != nil {
		return nil, fmt.Errorf("sp: %w", err)
	}

	stLo := alignDown(sp - 0x80000)
	if !e.overlaps(stLo, stLo+0x100000) {
		if err := eng.MemMap(stLo, 0x100000); err != nil {
			return nil, err
		}

		e.mapped = append(e.mapped, [2]uint64{stLo, stLo + 0x100000})
	}

	stack, err := os.ReadFile(filepath.Join(e.dir, "stack.bin"))
	if err != nil {
		return nil, err
	}

	stackLo, err := parseHex(ctx.StackLo)
	if err != nil {
		return nil, err
	}

	if err := eng.MemWrite(stackLo, stack); err != nil {
		return nil, err
	}

	for i := 0; i < 29; i++ {
		v, err := parseHex(ctx.Regs[fmt.Sprintf("x%d", i)])
		if err != nil {
			return nil, fmt.Errorf("x%d: %w", i, err)
		}

		if err := eng.RegWrite(regX(i), v); err != nil {
			return nil, err
		}
	}

	for name, reg := range map[string]int{"fp": unicorn.RegX29, "lr": unicorn.RegLR, "sp": unicorn.RegSP} {
		v, err := parseHex(ctx.Regs[name])
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}

		if err := eng.RegWrite(reg, v); err != nil {
			return nil, err
		}
	}

	inAddr, err := parseHex(ctx.X0)
	if err != nil {
		return nil, fmt.Errorf("x0: %w", err)
	}

	req := e.requestBytes(ctx, inAddr)
	if err := eng.MemWrite(inAddr, req); err != nil {
		return nil, err
	}

	entry, err := parseHex(ctx.Regs["pc"])
	if err != nil {
		return nil, fmt.Errorf("pc: %w", err)
	}

	hook, err := eng.AddCodeHook(0, ^uint64(0), e.step)
	if err != nil {
		return nil, err
	}
	defer hook.Close()

	fault, err := eng.AddMemoryFaultHook(e.onFault)
	if err != nil {
		return nil, err
	}
	defer fault.Close()

	runErr := eng.StartBounded(entry, 0, 3*time.Minute, uint64(e.InsnCap)+1_000_000)
	if e.fault != nil {
		pc, _ := eng.RegRead(unicorn.RegPC)
		return e.otp16, fmt.Errorf("%w at pc=%#x after %d instructions", e.fault, pc, e.insnCount)
	}

	if e.otp16 == nil {
		pc, _ := eng.RegRead(unicorn.RegPC)
		if runErr != nil {
			return nil, fmt.Errorf("%w at pc=%#x after %d instructions", runErr, pc, e.insnCount)
		}

		return nil, fmt.Errorf("emulation stopped without OTP at pc=%#x after %d instructions", pc, e.insnCount)
	}

	return e.otp16, nil
}

func (e *Emu) requestBytes(ctx ctxFile, inAddr uint64) []byte {
	if len(ctx.Input) > 0 {
		// try []int
		var ints []int
		if err := json.Unmarshal(ctx.Input, &ints); err == nil && len(ints) > 0 {
			b := make([]byte, len(ints))
			for i, v := range ints {
				b[i] = byte(v)
			}

			return b
		}
		// try base64 / hex string
		var s string
		if err := json.Unmarshal(ctx.Input, &s); err == nil && s != "" {
			if b, err := base64.StdEncoding.DecodeString(s); err == nil {
				return b
			}

			if b, err := hex.DecodeString(s); err == nil {
				return b
			}
		}
	}

	if b := e.snapshotRead(inAddr, 20); b != nil {
		return b
	}
	// fallback: >IIIq type=1 nonce flag=1 dsid=-2
	b := make([]byte, 20)
	binary.BigEndian.PutUint32(b[0:], 1)
	binary.BigEndian.PutUint32(b[4:], 0x11111111)
	binary.BigEndian.PutUint32(b[8:], 1)
	binary.BigEndian.PutUint64(b[12:], ^uint64(1)) // -2

	return b
}

// step is the per-instruction code hook. It must not panic through the C ABI.
func (e *Emu) step(address uint64, _ uint32) {
	defer func() {
		if p := recover(); p != nil {
			e.fault = fmt.Errorf("native emu panic at %#x: %v", address, p)
			_ = e.eng.Stop()
		}
	}()

	e.insnCount++
	if e.insnCount%1024 == 0 && e.runContext != nil {
		if err := e.runContext.Err(); err != nil {
			e.fault = err
			_ = e.eng.Stop()

			return
		}
	}

	if e.Fetch != nil && e.importPages[alignDown(address)] {
		instruction, err := e.eng.MemRead(address, 4)
		if err == nil && len(instruction) == 4 && binary.LittleEndian.Uint32(instruction) == 0 {
			p := alignDown(address)
			if err = e.fetchPage(p); err != nil {
				e.fault = err
				_ = e.eng.Stop()

				return
			}

			for addr := range e.importByAdr {
				if alignDown(addr) == p {
					_ = e.eng.MemWrite(addr, retInsn)
				}
			}

			for addr := range e.actCache {
				if alignDown(addr) == p {
					delete(e.actCache, addr)
				}
			}

			if err = e.eng.FlushTranslationCache(); err != nil {
				e.fault = err
				_ = e.eng.Stop()

				return
			}

			_ = e.eng.RegWrite(unicorn.RegPC, address)

			return
		}
	}

	if e.insnCount > e.InsnCap {
		e.fault = fmt.Errorf("instruction cap %d reached at %#x", e.InsnCap, address)
		_ = e.eng.Stop()

		return
	}

	switch address {
	case onceReturn:
		if n := len(e.onceStack); n > 0 {
			caller := e.onceStack[n-1]
			e.onceStack = e.onceStack[:n-1]
			_ = e.eng.RegWrite(unicorn.RegLR, caller)
			_ = e.eng.RegWrite(unicorn.RegPC, caller)
		} else {
			_ = e.eng.Stop()
		}

		return
	case sentinel:
		_ = e.eng.Stop()
		return
	}

	if name, ok := e.importByAdr[address]; ok {
		e.emulateImport(name)
		return
	}

	if code, err := e.eng.MemRead(address, 4); err == nil && len(code) == 4 {
		w := binary.LittleEndian.Uint32(code)
		if w&0xfc000000 == 0x94000000 {
			displacement := int64(int32(w&0x03ffffff) << 2)
			if target := uint64(int64(address) + displacement); target == 0x18589ad40 || target == 0x1858935e8 {
				_ = e.eng.RegWrite(unicorn.RegPC, address+4)
				return
			}
		}
	}

	act := e.classify(address)
	switch act.kind {
	case actNormal:
		return
	case actBranch:
		tgt, _ := e.eng.RegRead(act.reg)

		tgt &= vaMask
		if tgt == 0x18589ad40 || tgt == 0x1858935e8 {
			_ = e.eng.RegWrite(unicorn.RegPC, address+4)
			return
		}

		if tgt == 0 {
			e.fault = fmt.Errorf("branch to zero at %#x (x20=%#x)", address, e.reg(20))
			_ = e.eng.Stop()

			return
		}

		if act.isLink {
			_ = e.eng.RegWrite(unicorn.RegLR, address+4)
		}

		_ = e.eng.RegWrite(unicorn.RegPC, tgt)
	case actRet:
		lr, _ := e.eng.RegRead(unicorn.RegLR)
		_ = e.eng.RegWrite(unicorn.RegPC, lr&vaMask)
	case actStrip:
		v, _ := e.eng.RegRead(act.reg)
		_ = e.eng.RegWrite(act.reg, v&vaMask)
		_ = e.eng.RegWrite(unicorn.RegPC, address+4)
	case actSkip:
		_ = e.eng.RegWrite(unicorn.RegPC, address+4)
	case actCompareSwap:
		base, _ := e.eng.RegRead(act.rn)
		_ = e.onFault(base, uint32(act.width))
		oldBytes, _ := e.eng.MemRead(base, uint64(act.width))

		var previous uint64
		for i := len(oldBytes) - 1; i >= 0; i-- {
			previous = previous<<8 | uint64(oldBytes[i])
		}

		mask := uint64(1)<<(uint(act.width)*8) - 1

		expected, _ := e.eng.RegRead(act.rs)
		if previous == expected&mask {
			replacement, _ := e.eng.RegRead(act.rt)

			var wb [8]byte
			binary.LittleEndian.PutUint64(wb[:], replacement&mask)
			_ = e.eng.MemWrite(base, wb[:act.width])
		}

		_ = e.eng.RegWrite(act.rs, previous)
		_ = e.eng.RegWrite(unicorn.RegPC, address+4)
	case actTLS:
		_ = e.eng.RegWrite(act.reg, tlsBase)
		_ = e.eng.RegWrite(unicorn.RegPC, address+4)
	case actLoadClear:
		base, _ := e.eng.RegRead(act.rn)
		_ = e.onFault(base, uint32(act.width))
		oldBytes, _ := e.eng.MemRead(base, uint64(act.width))

		var previous uint64
		for i := len(oldBytes) - 1; i >= 0; i-- {
			previous = previous<<8 | uint64(oldBytes[i])
		}

		_ = e.eng.MemWrite(base, make([]byte, act.width))
		_ = e.eng.RegWrite(act.rt, previous)
		_ = e.eng.RegWrite(unicorn.RegPC, address+4)
	case actLoadSet:
		base, _ := e.eng.RegRead(act.rn)
		_ = e.onFault(base, uint32(act.width))
		oldBytes, _ := e.eng.MemRead(base, uint64(act.width))

		var previous uint64
		for i := len(oldBytes) - 1; i >= 0; i-- {
			previous = previous<<8 | uint64(oldBytes[i])
		}

		source, _ := e.eng.RegRead(act.rs)
		mask := uint64(1)<<(uint(act.width)*8) - 1

		var wb [8]byte
		binary.LittleEndian.PutUint64(wb[:], (previous|(source&mask))&mask)
		_ = e.eng.MemWrite(base, wb[:act.width])
		_ = e.eng.RegWrite(act.rt, previous)
		_ = e.eng.RegWrite(unicorn.RegPC, address+4)
	case actAtomic:
		base, _ := e.eng.RegRead(act.rn)
		if act.rn == 31 {
			base, _ = e.eng.RegRead(unicorn.RegSP)
		}

		_ = e.onFault(base, uint32(act.width))
		oldBytes, _ := e.eng.MemRead(base, uint64(act.width))

		var oldBuffer [8]byte
		copy(oldBuffer[:], oldBytes)
		previous := binary.LittleEndian.Uint64(oldBuffer[:])
		mask := uint64(1)<<(uint(act.width)*8) - 1
		source, _ := e.eng.RegRead(act.rs)
		source &= mask
		value := previous
		signed := func(x uint64) int64 {
			shift := uint(64 - act.width*8)
			return int64(x<<shift) >> shift
		}

		switch act.op {
		case 0:
			value = previous + source
		case 1:
			value = previous &^ source
		case 2:
			value = previous ^ source
		case 3:
			value = previous | source
		case 4:
			if signed(source) > signed(previous) {
				value = source
			}
		case 5:
			if signed(source) < signed(previous) {
				value = source
			}
		case 6:
			if source > previous {
				value = source
			}
		case 7:
			if source < previous {
				value = source
			}
		case 8:
			value = source
		default:
			panic("unsupported atomic operation")
		}

		var wb [8]byte
		binary.LittleEndian.PutUint64(wb[:], value&mask)

		_ = e.eng.MemWrite(base, wb[:act.width])
		if act.rt != 31 {
			_ = e.eng.RegWrite(act.rt, previous)
		}

		_ = e.eng.RegWrite(unicorn.RegPC, address+4)
	case actLoadAcquire:
		base, _ := e.eng.RegRead(act.rn)
		_ = e.onFault(base, uint32(act.width))
		oldBytes, _ := e.eng.MemRead(base, uint64(act.width))

		var previous uint64
		for i := len(oldBytes) - 1; i >= 0; i-- {
			previous = previous<<8 | uint64(oldBytes[i])
		}

		if act.rt != 31 {
			_ = e.eng.RegWrite(act.rt, previous)
		}

		_ = e.eng.RegWrite(unicorn.RegPC, address+4)
	case actCompareSwapPair:
		base, _ := e.eng.RegRead(act.rn)
		_ = e.onFault(base, 16)
		oldBytes, _ := e.eng.MemRead(base, 16)

		var oldLo, oldHi uint64
		if len(oldBytes) == 16 {
			oldLo = binary.LittleEndian.Uint64(oldBytes[:8])
			oldHi = binary.LittleEndian.Uint64(oldBytes[8:])
		}

		expectedLo, _ := e.eng.RegRead(act.rs)

		expectedHi, _ := e.eng.RegRead(act.rs2)
		if oldLo == expectedLo && oldHi == expectedHi {
			replacementLo, _ := e.eng.RegRead(act.rt)
			replacementHi, _ := e.eng.RegRead(act.rt2)

			var wb [16]byte
			binary.LittleEndian.PutUint64(wb[:8], replacementLo)
			binary.LittleEndian.PutUint64(wb[8:], replacementHi)
			_ = e.eng.MemWrite(base, wb[:])
		}

		_ = e.eng.RegWrite(act.rs, oldLo)
		_ = e.eng.RegWrite(act.rs2, oldHi)
		_ = e.eng.RegWrite(unicorn.RegPC, address+4)
	case actSyscall:
		_ = e.eng.RegWrite(regX(0), 0)
		_ = e.eng.RegWrite(unicorn.RegPC, address+4)
	case actSwap:
		base, _ := e.eng.RegRead(act.rn)
		_ = e.onFault(base, uint32(act.width))
		mask := uint64(1)<<(uint(act.width)*8) - 1
		old, _ := e.eng.MemRead(base, uint64(act.width))
		src, _ := e.eng.RegRead(act.rs)

		var wb [8]byte
		binary.LittleEndian.PutUint64(wb[:], src&mask)
		_ = e.eng.MemWrite(base, wb[:act.width])

		var prev uint64
		for i := len(old) - 1; i >= 0; i-- {
			prev = prev<<8 | uint64(old[i])
		}

		_ = e.eng.RegWrite(act.rt, prev)
		_ = e.eng.RegWrite(unicorn.RegPC, address+4)
	}
}

// classify decodes the 4-byte instruction word and caches a PAC action. Only the
// arm64e instructions the adid OTP path uses need special handling; everything
// else is actNormal and runs natively.
func (e *Emu) classify(address uint64) action {
	if a, ok := e.actCache[address]; ok {
		return a
	}

	code, err := e.eng.MemRead(address, 4)

	var a action
	if err != nil || len(code) < 4 {
		a = action{kind: actNormal}
		e.actCache[address] = a

		return a
	}

	w := binary.LittleEndian.Uint32(code)
	a = decode(w)
	e.actCache[address] = a

	return a
}

// decode classifies one arm64 instruction word.
func decode(w uint32) action {
	rn := int((w >> 5) & 0x1f)

	rd := int(w & 0x1f)
	if w&0xffe0001f == 0xd4000001 {
		return action{kind: actSyscall}
	}
	// Unconditional branch (register), auth variants: bits[31:25]=1101011,
	// op2(bits[20:16])=11111, op3(bits[15:11])=00001 (key = bit10).
	if (w>>25)&0x7f == 0x6b && (w>>16)&0x1f == 0x1f && (w>>11)&0x1f == 0x01 {
		switch (w >> 21) & 0xf {
		case 0b1000, 0b0000: // braa/brab, braaz/brabz
			return action{kind: actBranch, reg: regX(rn), isLink: false}
		case 0b1001, 0b0001: // blraa/blrab, blraaz/blrabz
			return action{kind: actBranch, reg: regX(rn), isLink: true}
		case 0b0010: // retaa/retab (uses LR)
			return action{kind: actRet}
		}
	}

	if w&0x3f20fc00 == 0x3820c000 {
		size := (w >> 30) & 3
		return action{kind: actLoadAcquire, rt: regX(rd), rn: regX(rn), width: 1 << size}
	}

	if w&0x3f200c00 == 0x38200000 && (w>>12)&15 <= 8 {
		size := (w >> 30) & 3

		return action{kind: actAtomic, op: (w >> 12) & 15,
			rs: regX(int((w >> 16) & 0x1f)), rt: regX(rd), rn: regX(rn), width: 1 << size}
	}

	if w&0x3f20fc00 == 0x38201000 {
		size := (w >> 30) & 0x3
		return action{kind: actLoadClear, rt: regX(rd), rn: regX(rn), width: 1 << size}
	}

	if w&0x3f20fc00 == 0x38203000 {
		size := (w >> 30) & 0x3

		return action{kind: actLoadSet,
			rs: regX(int((w >> 16) & 0x1f)), rt: regX(rd), rn: regX(rn), width: 1 << size}
	}

	if w&0x3f20fc00 == 0x0820fc00 {
		size := (w >> 30) & 0x3
		rs := int((w >> 16) & 0x1f)

		return action{kind: actCompareSwapPair,
			rs: regX(rs), rs2: regX(rs + 1), rt: regX(rd), rt2: regX(rd + 1),
			rn: regX(rn), width: 8 << size}
	}
	// CAS* atomic compare-and-swap: same operand layout as SWP, bits[15:10]=111111.
	if w&0x3f20fc00 == 0x08207c00 {
		size := (w >> 30) & 0x3

		return action{kind: actCompareSwap,
			rs: regX(int((w >> 16) & 0x1f)), rt: regX(rd), rn: regX(rn), width: 1 << size}
	}

	if w&0xffffffe0 == 0xd53bd060 {
		return action{kind: actTLS, reg: regX(rd)}
	}
	// SWP* (atomic memory, no FEAT_LSE128): bits[29:24]=111000, bit21=1,
	// bits[15:10]=100000. size=bits[31:30], Rs=bits[20:16], Rn=bits[9:5], Rt=bits[4:0].
	if w&0x3f20fc00 == 0x38208000 {
		size := (w >> 30) & 0x3

		width := 4
		if size == 0b11 {
			width = 8
		}

		return action{kind: actSwap,
			rs: regX(int((w >> 16) & 0x1f)), rt: regX(rd), rn: regX(rn), width: width}
	}

	if w&0xffe0fc00 == 0x9ac03000 {
		return action{kind: actSkip}
	}
	// Data-processing (1 source), PAC/AUT/XPAC register forms:
	// sf=1, bits[30:21]=1011010110, opcode2(bits[20:16])=00001, opcode6=bits[15:10].
	if w&0xffe00000 == 0xdac00000 && (w>>16)&0x1f == 0x01 {
		opc := (w >> 10) & 0x3f
		switch {
		case opc <= 0x03 || (opc >= 0x08 && opc <= 0x0b): // PACI*/PACD* (+Z)
			return action{kind: actSkip}
		case (opc >= 0x04 && opc <= 0x07) || (opc >= 0x0c && opc <= 0x0f) || opc == 0x10 || opc == 0x11: // AUT*/XPAC*
			return action{kind: actStrip, reg: regX(rd)}
		}
	}
	// PAC*SP / AUT*SP / XPACLRI hint-space (operate implicitly on LR/SP):
	// 1101 0101 0000 0011 0010 0011 xxx 11111.
	if w&0xfffff81f == 0xd503201f {
		op := (w >> 5) & 0x7f
		switch op {
		case 0b0110001, 0b0110011, 0b0110101, 0b0110111: // paciasp/pacibsp/... (sign)
			return action{kind: actSkip}
		case 0b0111001, 0b0111011, 0b0111101, 0b0111111: // autiasp/autibsp/... (strip LR)
			return action{kind: actStrip, reg: unicorn.RegLR}
		case 0b0000111, 0b0000110: // xpaclri / xpacd-lri
			return action{kind: actStrip, reg: unicorn.RegLR}
		}
	}

	return action{kind: actNormal}
}

// onFault maps missing guest memory (offline: zero-filled) and retries the access.
func (e *Emu) onFault(address uint64, _ uint32) bool {
	p := alignDown(address)
	if !e.overlaps(p, p+page) {
		if err := e.eng.MemMap(p, page); err != nil {
			return false
		}

		e.mapped = append(e.mapped, [2]uint64{p, p + page})
		if e.Fetch != nil {
			if err := e.fetchPage(p); err != nil {
				e.fault = err
				return false
			}
		}
	}

	return true
}

func (e *Emu) fetchPage(address uint64) error {
	data, err := e.Fetch(address, page)
	if err != nil {
		return err
	}

	if len(data) != page {
		return fmt.Errorf("live shared-cache page has size %d, want %d", len(data), page)
	}

	if err = e.eng.MemWrite(address, data); err != nil {
		return err
	}

	if e.FetchedPages == nil {
		e.FetchedPages = map[uint64][]byte{}
	}

	e.FetchedPages[address] = append([]byte(nil), data...)

	return nil
}

// OTP returns the captured 16-byte OTP (nil until Run succeeds).
func (e *Emu) OTP() []byte { return e.otp16 }

// MID returns the captured 60-byte machine token.
func (e *Emu) MID() []byte { return e.midBlock }
