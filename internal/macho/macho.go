// Package macho parses thin and fat Mach-O binaries, scoped to what
// ipadecrypt's pipeline needs: locating LC_ENCRYPTION_INFO, detecting
// cryptid != 0, and picking the slice of a fat binary that matches a
// given (cputype, cpusubtype).
package macho

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	MagicLE    = 0xfeedface // MH_MAGIC
	Magic64LE  = 0xfeedfacf // MH_MAGIC_64
	MagicBE    = 0xcefaedfe // MH_CIGAM
	Magic64BE  = 0xcffaedfe // MH_CIGAM_64
	FatMagic   = 0xcafebabe // FAT_MAGIC; stored big-endian on disk, so a
	FatCigam   = 0xbebafeca // little-endian read of a real fat file
	FatMagic64 = 0xcafebabf // produces the Cigam variant.
	FatCigam64 = 0xbfbafeca

	LCEncryptionInfo   = 0x21
	LCEncryptionInfo64 = 0x2c
)

// IsMagic reports whether b starts with any thin or fat Mach-O magic.
func IsMagic(b []byte) bool {
	if len(b) < 4 {
		return false
	}

	switch binary.LittleEndian.Uint32(b) {
	case MagicLE, Magic64LE, MagicBE, Magic64BE,
		FatMagic, FatCigam, FatMagic64, FatCigam64:
		return true
	}

	return false
}

// EncryptionInfo is a parsed LC_ENCRYPTION_INFO / _64 load command.
type EncryptionInfo struct {
	CryptidOffset uint64 // file offset of the cryptid u32 within the slice
	CryptOff      uint64
	CryptSize     uint64
	Cryptid       uint32
}

// ReadEncryptionInfo parses a thin little-endian Mach-O and returns its
// LC_ENCRYPTION_INFO. Errors when none is present or when the input is
// not a thin LE Mach-O.
func ReadEncryptionInfo(data []byte) (EncryptionInfo, error) {
	var info EncryptionInfo

	if len(data) < 28 {
		return info, errors.New("mach_header truncated")
	}

	bo := binary.LittleEndian

	magic := bo.Uint32(data[0:4])
	if magic != MagicLE && magic != Magic64LE {
		return info, fmt.Errorf("not a thin LE Mach-O magic=0x%x", magic)
	}

	is64 := magic == Magic64LE
	ncmds := bo.Uint32(data[16:20])
	sizeofcmds := bo.Uint32(data[20:24])

	headerSize := uint64(28)
	if is64 {
		headerSize = 32
	}

	if headerSize+uint64(sizeofcmds) > uint64(len(data)) {
		return info, errors.New("load commands truncated")
	}

	want := uint32(LCEncryptionInfo)
	if is64 {
		want = LCEncryptionInfo64
	}

	p := headerSize
	for range ncmds {
		if p+8 > uint64(len(data)) {
			return info, errors.New("load cmd truncated")
		}

		cmd := bo.Uint32(data[p : p+4])

		cmdSize := bo.Uint32(data[p+4 : p+8])
		if cmdSize < 8 || uint64(cmdSize) > uint64(len(data))-p {
			return info, fmt.Errorf("bad cmdsize=%d", cmdSize)
		}

		if cmd == want {
			if cmdSize < 20 {
				return info, errors.New("LC_ENCRYPTION_INFO truncated")
			}

			info.CryptOff = uint64(bo.Uint32(data[p+8 : p+12]))
			info.CryptSize = uint64(bo.Uint32(data[p+12 : p+16]))
			info.CryptidOffset = p + 16
			info.Cryptid = bo.Uint32(data[p+16 : p+20])

			return info, nil
		}

		p += uint64(cmdSize)
	}

	return info, errors.New("no LC_ENCRYPTION_INFO load command")
}

// SliceHasCryptid scans every slice of a thin or fat Mach-O and returns
// true when any slice carries LC_ENCRYPTION_INFO with cryptid != 0.
func SliceHasCryptid(data []byte) (bool, error) {
	if len(data) < 4 {
		return false, errors.New("too short")
	}

	magic := binary.LittleEndian.Uint32(data[:4])
	switch magic {
	case FatMagic, FatCigam:
		return checkFat(data, false)
	case FatMagic64, FatCigam64:
		return checkFat(data, true)
	case MagicLE, Magic64LE:
		return checkThin(data, false)
	case MagicBE, Magic64BE:
		return checkThin(data, true)
	}

	return false, errors.New("not mach-o")
}

// Slice describes one architecture slice's location within a Mach-O. For a
// thin Mach-O the single slice spans the whole file.
type Slice struct {
	Cpu    uint32
	Sub    uint32
	Offset uint64
	Size   uint64
}

// FatSlices returns the architecture slices of a thin or fat Mach-O. A thin
// Mach-O yields one slice covering the whole file.
func FatSlices(data []byte) ([]Slice, error) {
	if len(data) < 4 {
		return nil, errors.New("too short")
	}

	magic := binary.LittleEndian.Uint32(data[:4])
	switch magic {
	case MagicLE, Magic64LE, MagicBE, Magic64BE:
		cpu, sub, err := readAnyThinCpu(data)
		if err != nil {
			return nil, err
		}

		return []Slice{{Cpu: cpu, Sub: sub, Offset: 0, Size: uint64(len(data))}}, nil
	case FatMagic, FatCigam:
		return fatSlices(data, false)
	case FatMagic64, FatCigam64:
		return fatSlices(data, true)
	}

	return nil, fmt.Errorf("not Mach-O magic=0x%x", magic)
}

func readAnyThinCpu(data []byte) (cpu, sub uint32, err error) {
	if len(data) < 16 {
		return 0, 0, errors.New("mach_header truncated")
	}

	magic := binary.LittleEndian.Uint32(data[0:4])

	bo := binary.ByteOrder(binary.LittleEndian)
	if magic == MagicBE || magic == Magic64BE {
		bo = binary.BigEndian
	}

	return bo.Uint32(data[4:8]), bo.Uint32(data[8:12]), nil
}

func fatSlices(data []byte, is64 bool) ([]Slice, error) {
	bo := binary.BigEndian

	if len(data) < 8 {
		return nil, errors.New("fat header truncated")
	}

	nfat := bo.Uint32(data[4:8])
	if nfat == 0 || nfat > 32 {
		return nil, fmt.Errorf("implausible nfat_arch=%d", nfat)
	}

	archSize := 20
	if is64 {
		archSize = 32
	}

	out := make([]Slice, 0, nfat)

	off := 8
	for range nfat {
		if off+archSize > len(data) {
			return nil, errors.New("fat_arch truncated")
		}

		var s Slice

		s.Cpu = bo.Uint32(data[off : off+4])
		s.Sub = bo.Uint32(data[off+4 : off+8])

		if is64 {
			s.Offset = bo.Uint64(data[off+8 : off+16])
			s.Size = bo.Uint64(data[off+16 : off+24])
		} else {
			s.Offset = uint64(bo.Uint32(data[off+8 : off+12]))
			s.Size = uint64(bo.Uint32(data[off+12 : off+16]))
		}

		off += archSize

		if s.Offset+s.Size > uint64(len(data)) {
			return nil, errors.New("fat slice out of range")
		}

		out = append(out, s)
	}

	return out, nil
}

func checkFat(data []byte, is64 bool) (bool, error) {
	bo := binary.BigEndian // fat headers are always big-endian on disk

	if len(data) < 8 {
		return false, errors.New("fat header truncated")
	}

	nfat := bo.Uint32(data[4:8])
	if nfat == 0 || nfat > 32 {
		return false, fmt.Errorf("implausible nfat_arch=%d", nfat)
	}

	archSize := 20
	if is64 {
		archSize = 32
	}

	off := 8
	for range nfat {
		if off+archSize > len(data) {
			return false, errors.New("fat_arch truncated")
		}

		var sliceOff, sliceSize uint64
		if is64 {
			sliceOff = bo.Uint64(data[off+8 : off+16])
			sliceSize = bo.Uint64(data[off+16 : off+24])
		} else {
			sliceOff = uint64(bo.Uint32(data[off+8 : off+12]))
			sliceSize = uint64(bo.Uint32(data[off+12 : off+16]))
		}

		off += archSize

		if sliceOff+sliceSize > uint64(len(data)) {
			return false, errors.New("fat slice out of range")
		}

		if sliceSize < 4 {
			continue
		}

		slice := data[sliceOff : sliceOff+sliceSize]
		m := binary.LittleEndian.Uint32(slice[:4])

		enc, err := checkThin(slice, m == MagicBE || m == Magic64BE)
		if err != nil {
			return false, err
		}

		if enc {
			return true, nil
		}
	}

	return false, nil
}

func checkThin(data []byte, swap bool) (bool, error) {
	var bo binary.ByteOrder = binary.LittleEndian
	if swap {
		bo = binary.BigEndian
	}

	if len(data) < 28 {
		return false, errors.New("mach_header truncated")
	}

	magic := bo.Uint32(data[0:4])
	is64 := magic == Magic64LE || magic == Magic64BE
	ncmds := bo.Uint32(data[16:20])
	sizeofcmds := bo.Uint32(data[20:24])

	headerSize := 28
	if is64 {
		headerSize = 32
	}

	if uint64(headerSize)+uint64(sizeofcmds) > uint64(len(data)) {
		return false, errors.New("load commands truncated")
	}

	if ncmds > 1<<16 {
		return false, fmt.Errorf("implausible ncmds=%d", ncmds)
	}

	p := headerSize
	for range ncmds {
		if p+8 > len(data) {
			return false, errors.New("load cmd truncated")
		}

		cmd := bo.Uint32(data[p : p+4])

		cmdSize := bo.Uint32(data[p+4 : p+8])
		if cmdSize < 8 || int(cmdSize) > len(data)-p {
			return false, fmt.Errorf("bad cmdsize=%d", cmdSize)
		}

		if (is64 && cmd == LCEncryptionInfo64) || (!is64 && cmd == LCEncryptionInfo) {
			if int(cmdSize) < 20 {
				return false, errors.New("LC_ENCRYPTION_INFO truncated")
			}

			cryptid := bo.Uint32(data[p+16 : p+20])
			if cryptid != 0 {
				return true, nil
			}
		}

		p += int(cmdSize)
	}

	return false, nil
}
