package machine

import (
	"errors"
	"strings"
)

type contentFD struct {
	path   string
	offset int
	flags  uint64
}

// Private content filesystem; no native syscalls or files are used.
func (v *contentFS) installPOSIX(s *shims) error {
	fds := map[uint64]*contentFD{}
	next := uint64(1000)
	allowed := contentWritable
	getPath := func(i int) (string, error) {
		p, e := s.argument(i)
		if e != nil {
			return "", e
		}
		str, e := s.readCString(p)
		return contentPath(str), e
	}
	fail := func(code uint32) error {
		if s.errno != 0 {
			if e := s.writeUint32(s.errno, code); e != nil {
				return e
			}
		}
		return s.returnMinusOne()
	}
	for _, name := range []string{"_open", "_open$UNIX2003"} {
		if e := s.wrapFunction(name, func(original shimHandler) shimHandler {
			return func() error {
				p, e := getPath(0)
				if e != nil {
					return e
				}
				if !allowed(p) {
					return original()
				}
				flags, e := s.argument(1)
				if e != nil {
					return e
				}
				_, exists := v.files[p]
				if len(fds) >= 256 || !exists && len(v.files) >= 32 {
					return fail(24)
				}
				if flags&3 == 3 {
					return fail(22)
				}
				if !exists && flags&0x200 == 0 {
					return fail(2)
				}
				if exists && flags&0xa00 == 0xa00 {
					return fail(17)
				}
				if !exists || flags&0x400 != 0 {
					if flags&0x400 != 0 && flags&3 == 0 {
						return fail(9)
					}
					clear(v.files[p])
					v.files[p] = []byte{}
				}
				next++
				fds[next] = &contentFD{path: p, flags: flags}
				return s.setResult(next)
			}
		}); e != nil {
			return e
		}
	}
	stat := func(out uint64, p string, directory bool) error {
		if e := s.engine.MemWrite(out, make([]byte, 144)); e != nil {
			return e
		}
		mode := []byte{0x80, 0x81}
		if directory {
			mode = []byte{0xc0, 0x41}
		}
		if e := s.engine.MemWrite(out+4, mode); e != nil {
			return e
		}
		if e := s.writeUint64(out+96, uint64(len(v.files[p]))); e != nil {
			return e
		}
		return s.setResult(0)
	}
	for _, name := range []string{"_lstat", "_lstat$INODE64", "_stat", "_stat$INODE64"} {
		if e := s.wrapFunction(name, func(original shimHandler) shimHandler {
			return func() error {
				p, e := getPath(0)
				if e != nil {
					return e
				}
				directory := p == "/var/db/fpsd/SC Info" || p == "/Users/Shared/SC Info"
				if !allowed(p) && !directory {
					return original()
				}

				if _, ok := v.files[p]; !ok && !directory {
					return fail(2)
				}
				out, e := s.argument(1)
				if e != nil {
					return e
				}
				return stat(out, p, directory)
			}
		}); e != nil {
			return e
		}
	}
	for _, name := range []string{"_read", "_read$UNIX2003", "_write", "_write$UNIX2003", "_fstat", "_fstat$INODE64", "_lseek", "_lseek$UNIX2003", "_ftruncate", "_close", "_close$UNIX2003", "_fsync"} {
		if e := s.wrapFunction(name, func(original shimHandler) shimHandler {
			return func() error {
				id, e := s.argument(0)
				if e != nil {
					return e
				}
				fd := fds[id]
				if fd == nil {
					return original()
				}
				a, e := s.argument(1)
				if e != nil {
					return e
				}
				b, e := s.argument(2)
				if e != nil {
					return e
				}
				switch {
				case strings.HasPrefix(name, "_close"):
					delete(fds, id)
					return s.setResult(0)
				case name == "_fsync":
					return s.setResult(0)
				case strings.HasPrefix(name, "_fstat"):
					return stat(a, fd.path, false)
				case strings.HasPrefix(name, "_lseek"):
					position := int64(a)
					switch b {
					case 0:
					case 1:
						position += int64(fd.offset)
					case 2:
						position += int64(len(v.files[fd.path]))
					default:
						return fail(22)
					}
					if position < 0 || position > 16<<20 {
						return fail(22)
					}
					fd.offset = int(position)
					return s.setResult(uint64(position))
				case name == "_ftruncate":
					if fd.flags&3 == 0 {
						return fail(9)
					}
					if a > 16<<20 {
						return fail(27)
					}
					data := v.files[fd.path]
					if int(a) > len(data) {
						data = append(data, make([]byte, int(a)-len(data))...)
					} else {
						clear(data[a:])
						data = data[:a]
					}
					v.files[fd.path] = data
					return s.setResult(0)
				case strings.HasPrefix(name, "_read"):
					if fd.flags&3 == 1 {
						return fail(9)
					}
					if b > 16<<20 {
						return fail(22)
					}
					data := v.files[fd.path]
					n := min(int(b), max(0, len(data)-fd.offset))
					if n > 0 {
						if e = s.engine.MemWrite(a, data[fd.offset:fd.offset+n]); e != nil {
							return e
						}
					}
					fd.offset += n
					return s.setResult(uint64(n))
				case strings.HasPrefix(name, "_write"):
					if fd.flags&3 == 0 {
						return fail(9)
					}
					data := v.files[fd.path]
					if fd.flags&8 != 0 {
						fd.offset = len(data)
					}
					if b > 16<<20 || uint64(fd.offset)+b > 16<<20 {
						return fail(27)
					}
					buf, e := s.engine.MemRead(a, b)
					if e != nil {
						return e
					}
					end := fd.offset + len(buf)
					if end > len(data) {
						data = append(data, make([]byte, end-len(data))...)
					}
					copy(data[fd.offset:end], buf)
					fd.offset = end
					v.files[fd.path] = data
					return s.setResult(b)
				}
				return errors.New("unimplemented virtual descriptor operation")
			}
		}); e != nil {
			return e
		}
	}
	for _, name := range []string{"_unlink", "_rename"} {
		if e := s.wrapFunction(name, func(original shimHandler) shimHandler {
			return func() error {
				p, e := getPath(0)
				if e != nil {
					return e
				}
				if !allowed(p) {
					return original()
				}
				data, ok := v.files[p]
				if !ok {
					return fail(2)
				}
				if name == "_rename" {
					dst, e := getPath(1)
					if e != nil {
						return e
					}
					if !allowed(dst) {
						return fail(13)
					}
					if dst == p {
						return s.setResult(0)
					}
					v.files[dst] = data
				}
				delete(v.files, p)
				return s.setResult(0)
			}
		}); e != nil {
			return e
		}
	}
	return nil
}
