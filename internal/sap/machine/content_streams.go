package machine

import (
	"errors"
	"fmt"
	"path"
	"strings"

	"github.com/londek/ipadecrypt/internal/sap/unicorn"
	"howett.net/plist"
)

type contentStream struct {
	path   string
	write  bool
	offset int
	status uint64
	errno  uint64
}

// contentFS holds the runtime's files in memory, without a host filesystem bridge.
type contentFS struct {
	files map[string][]byte
}

func contentPath(p string) string { return strings.TrimPrefix(path.Clean(p), "/private") }

func contentWritable(p string) bool {
	return strings.HasPrefix(p, "/var/db/fpsd/SC Info/") || strings.HasPrefix(p, "/Users/Shared/SC Info/")
}

func (v *contentFS) installStreams(s *shims) error {
	urls := map[uint64]string{}
	streams := map[uint64]*contentStream{}
	next := uint64(0xfff1000000000000)
	newID := func() uint64 { next++; return next }
	if err := s.replaceFunction("_sscanf", func() error {
		p, err := s.argument(0)
		if err != nil {
			return err
		}
		input, err := s.readCString(p)
		if err != nil {
			return err
		}
		p, err = s.argument(1)
		if err != nil {
			return err
		}
		format, err := s.readCString(p)
		if err != nil {
			return err
		}
		if format != "%llu.%llu.%llu" {
			return fmt.Errorf("unsupported content sscanf format %q", format)
		}
		var a, b, c uint64
		count, _ := fmt.Sscanf(input, "%d.%d.%d", &a, &b, &c)
		values := []uint64{a, b, c}
		for i := 0; i < count; i++ {
			// Darwin arm64 variadic arguments begin at the guest stack pointer.
			out, err := s.argument(8 + i)
			if err != nil {
				return err
			}
			if err = s.writeUint64(out, values[i]); err != nil {
				return err
			}
		}
		return s.setResult(uint64(count))
	}); err != nil {
		return err
	}
	// Property-list values are represented by explicit guest handles; unknown
	// system objects retain upstream behavior. This is not a native CF bridge.
	dicts := map[uint64]map[string]any{}
	stringValues := map[uint64]string{}
	newString := func(value string) (uint64, error) {
		if len(stringValues) >= 4096 {
			return 0, errors.New("content string limit exceeded")
		}
		p, err := s.allocate(uint64(len(value) + 1))
		if err != nil {
			return 0, err
		}
		if err = s.engine.MemWrite(p, append([]byte(value), 0)); err != nil {
			return 0, err
		}
		stringValues[p] = value
		return p, nil
	}
	for _, name := range []string{"_CFPropertyListCreateWithStream", "_CFPropertyListCreateFromStream"} {
		if err := s.replaceFunction(name, func() error {
			id, err := s.argument(1)
			if err != nil {
				return err
			}
			st := streams[id]
			if st == nil || st.status != 2 || st.write {
				return errors.New("invalid plist input stream")
			}
			length, err := s.argument(2)
			if err != nil {
				return err
			}
			contents := v.files[st.path]
			if st.offset > len(contents) || len(dicts) >= 4096 {
				return errors.New("invalid content plist stream position or object count")
			}
			b := contents[st.offset:]
			if length != 0 && length < uint64(len(b)) {
				b = b[:length]
			}
			var data map[string]any
			format, err := plist.Unmarshal(b, &data)
			if err != nil {
				return errors.New("virtual plist parse failed")
			}
			st.offset += len(b)
			st.status = 5
			fp, err := s.argument(4)
			if err != nil {
				return err
			}
			if fp != 0 {
				cfFormat := map[int]uint64{plist.XMLFormat: 100, plist.BinaryFormat: 200, plist.OpenStepFormat: 1}[format]
				if cfFormat == 0 {
					return errors.New("unsupported CF property list format")
				}
				if err = s.writeUint64(fp, cfFormat); err != nil {
					return err
				}
			}
			ep, err := s.argument(5)
			if err != nil {
				return err
			}
			if ep != 0 {
				if err = s.writeUint64(ep, 0); err != nil {
					return err
				}
			}
			h := newID()
			dicts[h] = data
			return s.setResult(h)
		}); err != nil {
			return err
		}
	}
	originalDictionary := s.entries[s.symbols["_CFDictionaryGetValue"]].handler
	if err := s.replaceFunction("_CFDictionaryGetValue", func() error {
		d, err := s.argument(0)
		if err != nil {
			return err
		}
		dict, ok := dicts[d]
		if !ok {
			return originalDictionary()
		}
		keyPtr, err := s.argument(1)
		if err != nil {
			return err
		}
		key, ok := stringValues[keyPtr]
		if !ok {
			// Pinned image CF constant ASCII string: flags, bytes, length.
			flags, e := s.readUint64(keyPtr + 8)
			if e != nil {
				return e
			}
			if flags&0xffff != 0x7c8 {
				return fmt.Errorf("unsupported constant CFString flags %#x", flags)
			}
			p, e := s.readUint64(keyPtr + 16)
			if e != nil {
				return e
			}
			n, e := s.readUint64(keyPtr + 24)
			if e != nil {
				return e
			}
			if n > 4096 {
				return errors.New("constant CFString exceeds bound")
			}
			b, e := s.engine.MemRead(p, n)
			if e != nil {
				return e
			}
			key = string(b)
		}
		value, exists := dict[key]
		if !exists {
			return s.setResult(0)
		}
		str, ok := value.(string)
		if !ok {
			return errors.New("unsupported virtual plist value type")
		}
		p, err := newString(str)
		if err != nil {
			return err
		}
		return s.setResult(p)
	}); err != nil {
		return err
	}
	originalCreate := s.entries[s.symbols["_CFStringCreateWithCString"]].handler
	if err := s.replaceFunction("_CFStringCreateWithCString", func() error {
		p, err := s.argument(1)
		if err != nil {
			return err
		}
		str, err := s.readCString(p)
		if err != nil {
			return err
		}
		if str == keySerial || str == keyUUID || str == keyBoard {
			return originalCreate()
		}
		p, err = newString(str)
		if err != nil {
			return err
		}
		return s.setResult(p)
	}); err != nil {
		return err
	}
	for _, name := range []string{"_CFGetTypeID", "_CFStringGetLength", "_CFStringGetCStringPtr"} {
		address, err := s.resolve(name)
		if err != nil {
			return err
		}
		original := s.entries[address].handler
		if err = s.replaceFunction(name, func() error {
			p, err := s.argument(0)
			if err != nil {
				return err
			}
			str, ok := stringValues[p]
			if name == "_CFGetTypeID" {
				if _, ok := dicts[p]; ok {
					return s.setResult(3)
				}
				if ok {
					return s.setResult(2)
				}
			}
			if ok && name == "_CFStringGetLength" {
				return s.setResult(uint64(len(str)))
			}
			if ok && name == "_CFStringGetCStringPtr" {
				return s.setResult(p)
			}
			return original()
		}); err != nil {
			return err
		}
	}
	if err := s.replaceFunction("_CFURLCreateFromFileSystemRepresentation", func() error {
		p, err := s.argument(1)
		if err != nil {
			return err
		}
		n, err := s.argument(2)
		if err != nil {
			return err
		}
		if n == 0 || n > 4096 {
			return errors.New("invalid virtual file URL length")
		}
		b, err := s.engine.MemRead(p, n)
		if err != nil {
			return err
		}
		path := contentPath(string(b))
		if strings.ContainsRune(path, 0) {
			return errors.New("invalid virtual file URL")
		}
		if len(urls) >= 4096 {
			return errors.New("content URL limit exceeded")
		}
		id := newID()
		urls[id] = path
		return s.setResult(id)
	}); err != nil {
		return err
	}
	for _, write := range []bool{false, true} {
		prefix := "_CFReadStream"
		if write {
			prefix = "_CFWriteStream"
		}
		handlers := map[string]shimHandler{
			"CreateWithFile": func() error {
				urlID, err := s.argument(1)
				if err != nil {
					return err
				}
				path, ok := urls[urlID]
				if !ok {
					return errors.New("unknown virtual file URL")
				}
				if len(streams) >= 4096 {
					return errors.New("content stream limit exceeded")
				}
				id := newID()
				streams[id] = &contentStream{path: path, write: write}
				return s.setResult(id)
			},
			"Open": func() error {
				id, err := s.argument(0)
				if err != nil {
					return err
				}
				st := streams[id]
				if st == nil {
					return errors.New("unknown virtual stream")
				}
				if st.status != 0 {
					return s.setResult(0)
				}
				_, exists := v.files[st.path]
				if !st.write && !exists {
					st.status = 7
					st.errno = 2
					return s.setResult(0)
				}
				if st.write {
					if !contentWritable(st.path) {
						return errors.New("content stream write outside private FairPlay directory")
					}
					if !exists && len(v.files) >= 32 {
						return errors.New("content file limit exceeded")
					}
					clear(v.files[st.path])
					v.files[st.path] = []byte{}
				}
				st.status = 2
				return s.setResult(1)
			},
			"Close": func() error {
				id, err := s.argument(0)
				if err != nil {
					return err
				}
				if st := streams[id]; st != nil {
					st.status = 6
				}
				return s.setResult(0)
			},
			"GetStatus": func() error {
				id, err := s.argument(0)
				if err != nil {
					return err
				}
				st := streams[id]
				if st == nil {
					return errors.New("unknown virtual stream")
				}
				return s.setResult(st.status)
			},
			"GetError": func() error {
				id, err := s.argument(0)
				if err != nil {
					return err
				}
				st := streams[id]
				if st == nil {
					return errors.New("unknown virtual stream")
				}
				// arm64 CFStreamError: CFIndex domain in x0, SInt32 error in x1.
				if err = s.engine.RegWrite(unicorn.RegX1, st.errno); err != nil {
					return err
				}
				if st.errno != 0 {
					return s.setResult(1)
				}
				return s.setResult(0)
			},
		}
		operation := "Read"
		if write {
			operation = "Write"
		}
		handlers[operation] = func() error {
			id, err := s.argument(0)
			if err != nil {
				return err
			}
			p, err := s.argument(1)
			if err != nil {
				return err
			}
			n, err := s.argument(2)
			if err != nil {
				return err
			}
			st := streams[id]
			if st == nil {
				return errors.New("unknown virtual stream")
			}
			if st.write != write {
				return errors.New("wrong content stream direction")
			}
			if n > 16<<20 {
				return errors.New("virtual stream transfer exceeds bound")
			}
			if st.status != 2 && st.status != 5 {
				return s.returnMinusOne()
			}
			if st.write {
				if st.offset+int(n) > 16<<20 {
					return errors.New("virtual stream file exceeds bound")
				}
				b, err := s.engine.MemRead(p, n)
				if err != nil {
					return err
				}
				data := v.files[st.path]
				end := st.offset + len(b)
				if end > len(data) {
					data = append(data, make([]byte, end-len(data))...)
				}
				copy(data[st.offset:end], b)
				v.files[st.path] = data
				st.offset += len(b)
				return s.setResult(n)
			}
			b := v.files[st.path]
			count := min(int(n), max(0, len(b)-st.offset))
			if count > 0 {
				if err = s.engine.MemWrite(p, b[st.offset:st.offset+count]); err != nil {
					return err
				}
			}
			st.offset += count
			if st.offset == len(b) {
				st.status = 5
			}
			return s.setResult(uint64(count))
		}
		for suffix, handler := range handlers {
			if err := s.replaceFunction(prefix+suffix, handler); err != nil {
				return err
			}
		}
	}
	return nil
}
