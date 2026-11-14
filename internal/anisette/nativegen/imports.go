package nativegen

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strconv"

	"github.com/londek/ipadecrypt/internal/sap/unicorn"
)

var errStackCheck = errors.New("__stack_chk_fail (canary mismatch)")

var (
	midTLV  = []byte{0, 0, 0, 0, 0, 0, 0, 0x3c} // reply element: type=0, len=60
	adiStat []byte
)

func otpTLV(typ uint32) []byte {
	header := make([]byte, 8)
	binary.BigEndian.PutUint32(header, typ)
	binary.BigEndian.PutUint32(header[4:], 16)

	return header
}

func init() {
	adiStat = mustHex(adiPBStatHex)
}

func mustHex(s string) []byte {
	b := make([]byte, len(s)/2)
	for i := 0; i < len(b); i++ {
		hi := hexNibble(s[2*i])
		lo := hexNibble(s[2*i+1])
		b[i] = hi<<4 | lo
	}

	return b
}

func hexNibble(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	}

	return 0
}

func (e *Emu) reg(i int) uint64 {
	v, _ := e.eng.RegRead(regX(i))
	return v
}

func (e *Emu) setX0(v uint64) { _ = e.eng.RegWrite(regX(0), v) }

func (e *Emu) writeU64(addr, v uint64) {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], v)
	_ = e.eng.MemWrite(addr, b[:])
}

// emulateImport implements libSystem/XPC stubs. The RET placed at
// each import address returns to the caller after this runs (unless we redirect).
func (e *Emu) emulateImport(name string) {
	x0, x1, x2, x3 := e.reg(0), e.reg(1), e.reg(2), e.reg(3)

	switch name {
	case "gettimeofday":
		if x0 != 0 {
			var b [16]byte
			binary.LittleEndian.PutUint64(b[0:], e.counterSec) // tv_sec
			_ = e.eng.MemWrite(x0, b[:])
		}

		e.setX0(0)
	case "time":
		if x0 != 0 {
			e.writeU64(x0, e.counterSec)
		}

		e.setX0(e.counterSec)
	case "__chkstk_darwin":
		// no-op
	case "lstat", "lstat64", "stat", "stat64":
		if x1 != 0 {
			_ = e.eng.MemWrite(x1, adiStat)
		}

		e.setX0(0)
	case "malloc", "malloc_type_malloc", "malloc_zone_malloc", "malloc_type_zone_malloc":
		size := x0
		if name == "malloc_zone_malloc" || name == "malloc_type_zone_malloc" {
			size = x1
		}

		if size == 0 {
			size = 16
		}

		e.setX0(e.malloc(size))
	case "calloc", "malloc_type_calloc", "malloc_type_zone_calloc":
		n := x0

		m := x1
		if name == "malloc_type_zone_calloc" {
			n, m = x1, x2
		}

		if n == 0 {
			n = 1
		}

		if m == 0 {
			m = 1
		}

		p := e.malloc(n * m)
		_ = e.eng.MemWrite(p, make([]byte, n*m))
		e.setX0(p)
	case "realloc", "malloc_type_realloc":
		sz := x1
		if sz == 0 {
			sz = 16
		}

		e.setX0(e.malloc(sz + 0x1000))
	case "free", "malloc_type_free":
		e.setX0(0)
	case "mmap":
		length := x1
		if length == 0 {
			length = page
		}

		sz := (length + 0xffff) &^ 0xffff

		p := e.mmapPtr
		if err := e.eng.MemMap(p, sz); err == nil {
			e.mapped = append(e.mapped, [2]uint64{p, p + sz})
		}

		e.mmapPtr += sz + 0x10000
		e.setX0(p)
	case "munmap":
		e.setX0(0)
	case "memcpy":
		if x2 != 0 {
			if data, err := e.eng.MemRead(x1, x2); err == nil {
				_ = e.eng.MemWrite(x0, data)
			}
		}

		e.setX0(x0)
	case "memset":
		if x2 != 0 {
			buf := bytes.Repeat([]byte{byte(x1 & 0xff)}, int(x2))
			_ = e.eng.MemWrite(x0, buf)
		}

		e.setX0(x0)
	case "__stack_chk_fail":
		e.fault = errStackCheck
		_ = e.eng.Stop()
	case "xpc_dictionary_get_data":
		if x2 != 0 {
			e.writeU64(x2, 20)
		}

		e.setX0(inputBase)
	case "xpc_dictionary_set_data":
		var data []byte
		if x3 != 0 {
			data, _ = e.eng.MemRead(x2, x3)
		}

		if idx := bytes.Index(data, otpTLV(e.OTPType)); idx >= 0 && idx+24 <= len(data) {
			e.otp16 = append([]byte(nil), data[idx+8:idx+24]...)
			if mp := bytes.Index(data, midTLV); mp >= 0 && len(data) >= mp+68 {
				e.midBlock = append([]byte(nil), data[mp+8:mp+68]...)
			}

			e.done = true
			_ = e.eng.Stop()
		}
	case "xpc_dictionary_create_reply", "CFStringCreateWithCStringNoCopy",
		"SecTaskCreateWithAuditToken", "SecTaskCopyValueForEntitlement":
		e.setX0(e.malloc(0x100))
	case "__CFTSDGetTable":
		// Per-thread singleton: must be the same pointer every call, or CF spins.
		if e.cfTSD == 0 {
			e.cfTSD = e.malloc(0x2000)
			_ = e.eng.MemWrite(e.cfTSD, make([]byte, 0x2000))
		}

		e.setX0(e.cfTSD)
	case "pthread_getspecific", "_pthread_getspecific_direct":
		e.setX0(e.tls[x0])
	case "pthread_setspecific", "_pthread_setspecific_direct":
		e.tls[x0] = x1
		e.setX0(0)
	case "pthread_key_create":
		e.pthreadKey++

		if x0 != 0 {
			var b [4]byte
			binary.LittleEndian.PutUint32(b[:], uint32(e.pthreadKey))
			_ = e.eng.MemWrite(x0, b[:])
		}

		e.setX0(0)
	case "pthread_key_init_np", "pthread_main_np":
		e.setX0(0)
	case "CFNumberGetTypeID":
		e.setX0(22)
	case "CFGetTypeID", "CFStringGetTypeID":
		e.setX0(7)
	case "CFNumberGetValue":
		if x2 != 0 {
			e.writeU64(x2, 1)
		}

		e.setX0(1)
	case "CFStringGetCString":
		val := []byte("347420559\x00")
		if x1 != 0 && x2 >= uint64(len(val)) {
			_ = e.eng.MemWrite(x1, val)
			e.setX0(1)
		} else {
			e.setX0(0)
		}
	case "strtoul":
		raw, _ := e.eng.MemRead(x0, 64)
		if i := bytes.IndexByte(raw, 0); i >= 0 {
			raw = raw[:i]
		}

		base := int(x2)
		if base == 0 {
			base = 10
		}

		v, _ := strconv.ParseUint(string(raw), base, 64)
		if x1 != 0 {
			e.writeU64(x1, x0+uint64(len(raw)))
		}

		e.setX0(v)
	case "pthread_once", "dispatch_once":
		initialized := uint64(1)

		if x0 != 0 {
			if b, err := e.eng.MemRead(x0, 8); err == nil {
				initialized = binary.LittleEndian.Uint64(b)
			}
		}

		if initialized == 0 && x1 != 0 {
			e.writeU64(x0, 1)
			caller, _ := e.eng.RegRead(unicorn.RegLR)
			e.onceStack = append(e.onceStack, caller&vaMask)
			_ = e.eng.RegWrite(unicorn.RegLR, onceReturn)
			_ = e.eng.RegWrite(unicorn.RegPC, x1&vaMask)
		} else {
			e.setX0(0)
		}
	case "xpc_dictionary_send_reply":
		e.setX0(0)
	default:
		e.setX0(0)
	}
}
