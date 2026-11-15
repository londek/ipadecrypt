package machine

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/londek/ipadecrypt/internal/sap/unicorn"
)

// Connect the emulated client to the emulated daemon.
// No bootstrap lookup or Mach message is sent to macOS.
func (v *contentFS) installContentRPC(a *ModernADI) error {
	ports := map[uint32]contentMachPort{1: {handle: fakeHandle, callback: a.fairplay.services.machPortCallback, info: a.fairplay.services.machPortInfo}}
	if err := v.installContentPorts(a.fairplay.services, ports); err != nil {
		return err
	}
	s := a.runtime.services
	original := s.entries[s.symbols["_bootstrap_look_up"]].handler
	// This isolated process has no activity voucher to attach.
	if e := s.replaceFunction("_voucher_mach_msg_set", s.returnZero); e != nil {
		return e
	}
	if e := s.replaceFunction("_bootstrap_look_up", func() error {
		p, e := s.argument(1)
		if e != nil {
			return e
		}
		service, e := s.readCString(p)
		if e != nil {
			return e
		}
		if service != "com.apple.fpsd" {
			return original()
		}
		p, e = s.argument(2)
		if e != nil {
			return e
		}
		if e = s.writeUint32(p, 1); e != nil {
			return e
		}
		return s.setResult(0)
	}); e != nil {
		return e
	}
	return s.replaceFunction("_mach_msg", func() error {
		p, e := s.argument(0)
		if e != nil {
			return e
		}
		options, e := s.argument(1)
		if e != nil {
			return e
		}
		n, e := s.argument(2)
		if e != nil {
			return e
		}
		capacity, e := s.argument(3)
		if e != nil {
			return e
		}
		if n < 24 || n > 1<<20 || capacity < 24 || capacity > 1<<20 || options&3 != 3 {
			return errors.New("unsupported content Mach call shape")
		}
		request, e := s.engine.MemRead(p, n)
		if e != nil {
			return e
		}
		id := binary.LittleEndian.Uint32(request[20:24])
		complex := binary.LittleEndian.Uint32(request[:4])&0x80000000 != 0
		// mach_msg uses send_size, not the sender's msgh_size field.
		binary.LittleEndian.PutUint32(request[4:8], uint32(n))
		versionRPC := id == 1203 && !complex && n == 24
		if versionRPC {
			// The pinned daemon's MIG table inserts a 100-byte complex call at
			// 1203; its 24-byte/four-word version operation is 1204. Translate
			// only this structurally identified older client request and reply.
			binary.LittleEndian.PutUint32(request[20:24], 1204)
		}
		reply, e := v.contentRPC(a, request, ports)
		if e != nil {
			return e
		}
		if len(reply) < 24 || len(reply) > int(capacity) {
			return errors.New("invalid content Mach response")
		}
		if versionRPC {
			if binary.LittleEndian.Uint32(reply[20:24]) != 1304 {
				return errors.New("wrong version RPC response ID")
			}
			binary.LittleEndian.PutUint32(reply[20:24], 1303)
		}
		// The synchronous client requests the minimum (8-byte) trailer.
		if len(reply)+8 > int(capacity) {
			return errors.New("Mach reply trailer exceeds receive capacity")
		}
		reply = append(reply, 0, 0, 0, 0, 8, 0, 0, 0)
		if e = s.engine.MemWrite(p, reply); e != nil {
			return fmt.Errorf("copy virtual Mach reply: %w", e)
		}
		return s.setResult(0)
	})
}

// Translate only the user-space ABI observed by the pinned runtime. Unknown descriptor
// types fail closed. Port numbers are private names in these two virtual tasks.
func contentReceive(src, dst *Machine, sent []byte, destination uint32) ([]byte, error) {
	if len(sent) < 24 || int(binary.LittleEndian.Uint32(sent[4:8])) != len(sent) {
		return nil, errors.New("invalid Mach header size")
	}
	r := append([]byte(nil), sent...)
	bits := binary.LittleEndian.Uint32(r[:4])
	right := func(disposition uint32) (uint32, error) {
		switch disposition {
		case 0, 16, 17, 18:
			return disposition, nil
		case 19, 20:
			return 17, nil
		case 21:
			return 18, nil
		default:
			return 0, fmt.Errorf("unsupported Mach disposition %d", disposition)
		}
	}
	remote, err := right(bits >> 8 & 255)
	if err != nil {
		return nil, err
	}
	local, err := right(bits & 255)
	if err != nil {
		return nil, err
	}
	binary.LittleEndian.PutUint32(r[:4], bits&0x80000000|remote|local<<8)
	binary.LittleEndian.PutUint32(r[8:12], binary.LittleEndian.Uint32(sent[12:16]))
	binary.LittleEndian.PutUint32(r[12:16], destination)
	binary.LittleEndian.PutUint32(r[16:20], 0)
	if bits&0x80000000 == 0 {
		return r, nil
	}
	if len(r) < 28 {
		return nil, errors.New("missing Mach descriptor count")
	}
	count := binary.LittleEndian.Uint32(r[24:28])
	if count > 64 {
		return nil, errors.New("too many content Mach descriptors")
	}
	offset := 28
	var total uint64
	for i := uint32(0); i < count; i++ {
		if offset+12 > len(r) {
			return nil, errors.New("truncated Mach descriptor")
		}
		kind := r[offset+11]
		if kind == 0 {
			disposition, err := right(uint32(r[offset+10]))
			if err != nil {
				return nil, err
			}
			r[offset+10] = byte(disposition)
			offset += 12
			continue
		}
		if kind != 1 || offset+16 > len(r) {
			return nil, fmt.Errorf("unsupported Mach descriptor type %d", kind)
		}
		d := r[offset : offset+16]
		address := binary.LittleEndian.Uint64(d[:8])
		size := uint64(binary.LittleEndian.Uint32(d[12:16]))
		total += size
		if total > 16<<20 {
			return nil, errors.New("Mach OOL size exceeds content limit")
		}
		var target uint64
		if size != 0 {
			data, e := src.engine.MemRead(address, size)
			if e != nil {
				return nil, fmt.Errorf("read Mach OOL: %w", e)
			}
			target, e = dst.services.allocate(size)
			if e != nil {
				return nil, e
			}
			if e = dst.engine.MemWrite(target, data); e != nil {
				return nil, e
			}
		}
		binary.LittleEndian.PutUint64(d[:8], target)
		d[8], d[9], d[10] = 1, 1, 0
		offset += 16
	}
	return r, nil
}

type contentMachPort struct{ handle, callback, info uint64 }

func (v *contentFS) installContentPorts(s *shims, ports map[uint32]contentMachPort) error {
	// Run this guest worker before its parent resumes. This explores one
	// valid ordering, not a general pthread scheduler or a concurrency proof.
	if err := s.replaceFunction("_pthread_detach", func() error {
		thread, err := s.argument(0)
		if err != nil {
			return err
		}
		if thread != 42 {
			return errors.New("unknown synchronous guest thread")
		}
		return s.setResult(0)
	}); err != nil {
		return err
	}
	if err := s.replaceFunction("_pthread_create", func() error {
		out, err := s.argument(0)
		if err != nil {
			return err
		}
		entry, err := s.argument(2)
		if err != nil {
			return err
		}
		arg, err := s.argument(3)
		if err != nil {
			return err
		}
		if err = s.writeUint64(out, 42); err != nil {
			return err
		}
		if err = s.engine.RegWrite(unicorn.RegX0, arg); err != nil {
			return err
		}
		return s.invokeCallback(entry)
	}); err != nil {
		return err
	}
	if err := s.replaceFunction("_CFMachPortCreate", func() error {
		if len(ports) >= 32 {
			return errors.New("content Mach port limit exceeded")
		}
		callback, err := s.argument(1)
		if err != nil {
			return err
		}
		context, err := s.argument(2)
		if err != nil {
			return err
		}
		var info uint64
		if context != 0 {
			info, err = s.readUint64(context + 8)
			if err != nil {
				return err
			}
			// Current caller has no retain/release callbacks. Fail closed otherwise.
			for _, off := range []uint64{16, 24} {
				cb, e := s.readUint64(context + off)
				if e != nil {
					return e
				}
				if cb != 0 {
					return errors.New("CFMachPort context lifetime callback not implemented")
				}
			}
		}
		flag, err := s.argument(3)
		if err != nil {
			return err
		}
		if flag != 0 {
			if err = s.engine.MemWrite(flag, []byte{0}); err != nil {
				return err
			}
		}
		handle, err := s.allocate(16)
		if err != nil {
			return err
		}
		port := uint32(len(ports) + 10)
		ports[port] = contentMachPort{handle: handle, callback: callback, info: info}
		return s.setResult(handle)
	}); err != nil {
		return err
	}
	return s.replaceFunction("_CFMachPortGetPort", func() error {
		handle, err := s.argument(0)
		if err != nil {
			return err
		}
		for port, item := range ports {
			if item.handle == handle {
				return s.setResult(uint64(port))
			}
		}
		return errors.New("unknown virtual CFMachPort")
	})
}

func (v *contentFS) contentRPC(a *ModernADI, request []byte, ports map[uint32]contentMachPort) ([]byte, error) {
	fp := a.fairplay
	destination := binary.LittleEndian.Uint32(request[8:12])
	port, exists := ports[destination]
	if !exists {
		return nil, fmt.Errorf("unknown content destination %d", destination)
	}
	fp.beginCall()
	defer fp.clearScratch()
	received, err := contentReceive(a.runtime, fp, request, destination)
	if err != nil {
		return nil, err
	}
	// CFMachPort's run loop requests MACH_RCV_TRAILER_AV: a 68-byte mac trailer.
	// The synthetic audit identity is a guest fixture, never a host credential.
	// The trailer is outside msgh_size; callback size excludes it (CFRunLoop.c).
	trailer := make([]byte, 68)
	binary.LittleEndian.PutUint32(trailer[4:8], 68)
	binary.LittleEndian.PutUint32(trailer[20:24], ^uint32(0))
	binary.LittleEndian.PutUint32(trailer[40:44], 123)
	binary.LittleEndian.PutUint32(trailer[44:48], 100000)
	binary.LittleEndian.PutUint32(trailer[48:52], 1)
	for len(received)%4 != 0 {
		received = append(received, 0)
	}
	received = append(received, trailer...)
	message, err := fp.scratch(received, uint64(len(received)))
	if err != nil {
		return nil, err
	}
	fp.services.machMessageReply = nil

	_, err = fp.invoke(port.callback, port.handle, message, uint64(len(request)), port.info)
	if err != nil {
		return nil, fmt.Errorf("content callback: %w", err)
	}
	if len(fp.services.machMessageReply) == 0 {
		return nil, errors.New("content daemon returned no reply")
	}
	binary.LittleEndian.PutUint32(fp.services.machMessageReply[4:8], uint32(len(fp.services.machMessageReply)))
	return contentReceive(fp, a.runtime, fp.services.machMessageReply, binary.LittleEndian.Uint32(request[12:16]))
}
