// Package fairplay decrypts FairPlay-encrypted App Store Mach-O binaries on the
// host, given the IPA's SINF/SUPF records and a 16-byte per-account credential.
// It is a Go port of the open-source fairplay-decrypt research (core.py) and
// needs no device.
package fairplay

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	cpuTypeARM64 = 0x0100000C
	pageSize     = 4096

	lcEncryptionInfo64 = 0x2C
	machoMagic64LE     = 0xFEEDFACF
)

var (
	workMask    = mustHex("c7626110cecd15963d850f6605f11c4b")
	constant    = mustHex("b4f27cb84eaaff3c1309be4089f02972")
	contextBase = uint64(0x3E4A45B664EBA141)

	roundSelectors = [4][8]byte{
		{0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d},
		{0x38, 0x37, 0x36, 0x39, 0x3a, 0x3d, 0x3c, 0x3b},
		{0x38, 0x36, 0x3a, 0x37, 0x3c, 0x39, 0x3d, 0x3b},
		{0x37, 0x38, 0x3a, 0x36, 0x3d, 0x39, 0x3b, 0x3c},
	}
	roundConstants = [4]uint32{0x6EE6B74F, 0x78B72ABF, 0xD227C8EA, 0x0C0081BC}
	finalSelectors = [4][4]int{{0, 1, 2, 3}, {0, 2, 4, 6}, {0, 3, 5, 7}, {4, 5, 6, 7}}
	finalConstants = [4]uint64{
		0x4F3DAC1FD3361949,
		0x4F3DAC1F631A63A2,
		0x4F3DAC1F87CD2974,
		0x4F3DAC1F7EA63AB1,
	}
)

func mustHex(s string) []byte {
	b := make([]byte, len(s)/2)
	for i := range b {
		var v byte

		for j := range 2 {
			c := s[i*2+j]
			switch {
			case c >= '0' && c <= '9':
				v = v<<4 | (c - '0')
			case c >= 'a' && c <= 'f':
				v = v<<4 | (c - 'a' + 10)
			default:
				panic("invalid hex literal")
			}
		}

		b[i] = v
	}

	return b
}

func xorBytes(a, b []byte) []byte {
	if len(a) != len(b) {
		panic("xor inputs must have equal lengths")
	}

	out := make([]byte, len(a))
	for i := range a {
		out[i] = a[i] ^ b[i]
	}

	return out
}

// machoInfo locates the encrypted arm64 region within a (possibly fat) Mach-O.
type machoInfo struct {
	base          int
	cryptOff      int
	cryptSize     int
	cryptidOffset int
}

// arm64EncryptionInfo parses the Mach-O header(s) and returns the single
// encrypted arm64 slice's region. It mirrors core.py arm64_encryption_info.
func arm64EncryptionInfo(data []byte) (machoInfo, error) {
	var base, sliceSize int

	switch {
	case len(data) >= 4 && data[0] == 0xca && data[1] == 0xfe && data[2] == 0xba && data[3] == 0xbe:
		count := int(binary.BigEndian.Uint32(data[4:]))
		if count <= 0 || count > 16 || 8+count*20 > len(data) {
			return machoInfo{}, errors.New("invalid FAT32 architecture table")
		}

		found := 0

		for i := range count {
			off := 8 + i*20
			cpu := binary.BigEndian.Uint32(data[off:])
			sliceOff := int(binary.BigEndian.Uint32(data[off+8:]))

			size := int(binary.BigEndian.Uint32(data[off+12:]))
			if cpu == cpuTypeARM64 {
				base, sliceSize = sliceOff, size
				found++
			}
		}

		if found != 1 {
			return machoInfo{}, fmt.Errorf("expected one arm64 slice, found %d", found)
		}
	case len(data) >= 4 && data[0] == 0xca && data[1] == 0xfe && data[2] == 0xba && data[3] == 0xbf:
		count := int(binary.BigEndian.Uint32(data[4:]))
		if count <= 0 || count > 16 || 8+count*32 > len(data) {
			return machoInfo{}, errors.New("invalid FAT64 architecture table")
		}

		found := 0

		for i := range count {
			off := 8 + i*32
			cpu := binary.BigEndian.Uint32(data[off:])
			sliceOff := int(binary.BigEndian.Uint64(data[off+8:]))

			size := int(binary.BigEndian.Uint64(data[off+16:]))
			if cpu == cpuTypeARM64 {
				base, sliceSize = sliceOff, size
				found++
			}
		}

		if found != 1 {
			return machoInfo{}, fmt.Errorf("expected one arm64 slice, found %d", found)
		}
	case len(data) >= 4 && data[0] == 0xcf && data[1] == 0xfa && data[2] == 0xed && data[3] == 0xfe:
		base, sliceSize = 0, len(data)
	default:
		return machoInfo{}, errors.New("not a supported arm64 Mach-O")
	}

	if base+sliceSize > len(data) || base+32 > len(data) {
		return machoInfo{}, errors.New("arm64 slice exceeds file")
	}

	magic := binary.LittleEndian.Uint32(data[base:])
	cpu := binary.LittleEndian.Uint32(data[base+4:])
	ncmds := int(binary.LittleEndian.Uint32(data[base+16:]))
	sizeofcmds := int(binary.LittleEndian.Uint32(data[base+20:]))

	if magic != machoMagic64LE || cpu != cpuTypeARM64 || ncmds > 1000 {
		return machoInfo{}, errors.New("invalid arm64 Mach-O header")
	}

	pos := base + 32

	commandsEnd := pos + sizeofcmds
	if commandsEnd > base+sliceSize {
		return machoInfo{}, errors.New("load commands exceed arm64 slice")
	}

	var (
		cryptOff, cryptSize, cryptid, cryptidOffset int
		found                                       int
	)

	for range ncmds {
		if pos+8 > commandsEnd {
			return machoInfo{}, errors.New("truncated load command")
		}

		cmd := binary.LittleEndian.Uint32(data[pos:])

		size := int(binary.LittleEndian.Uint32(data[pos+4:]))
		if size < 8 || pos+size > commandsEnd {
			return machoInfo{}, errors.New("invalid load command")
		}

		if cmd == lcEncryptionInfo64 {
			if size < 24 {
				return machoInfo{}, errors.New("short encryption info command")
			}

			cryptOff = int(binary.LittleEndian.Uint32(data[pos+8:]))
			cryptSize = int(binary.LittleEndian.Uint32(data[pos+12:]))
			cryptid = int(binary.LittleEndian.Uint32(data[pos+16:]))
			cryptidOffset = pos + 16
			found++
		}

		pos += size
	}

	if found != 1 {
		return machoInfo{}, fmt.Errorf("expected one encryption command, found %d", found)
	}

	if cryptid == 0 {
		return machoInfo{}, errCryptidZero
	}

	if cryptid != 1 || cryptSize == 0 || cryptSize%pageSize != 0 {
		return machoInfo{}, fmt.Errorf("unsupported cryptid/size: %d, %d", cryptid, cryptSize)
	}

	if cryptOff+cryptSize > sliceSize || cryptidOffset >= base+cryptOff {
		return machoInfo{}, errors.New("invalid encrypted region bounds")
	}

	return machoInfo{base: base, cryptOff: cryptOff, cryptSize: cryptSize, cryptidOffset: cryptidOffset}, nil
}

// errCryptidZero reports a slice whose cryptid is already 0 (not encrypted).
var errCryptidZero = errors.New("cryptid is zero")

type atom struct {
	tag        [4]byte
	start, end int
}

func atomChildren(data []byte, start, end int) ([]atom, error) {
	var out []atom

	offset := start
	for offset < end {
		if offset+8 > end {
			return nil, errors.New("truncated SINF atom")
		}

		size := int(binary.BigEndian.Uint32(data[offset:]))
		if size < 8 || offset+size > end {
			return nil, fmt.Errorf("invalid SINF atom size at %#x", offset)
		}

		var tag [4]byte
		copy(tag[:], data[offset+4:offset+8])
		out = append(out, atom{tag: tag, start: offset + 8, end: offset + size})
		offset += size
	}

	return out, nil
}

func sinfField(sinf []byte, wanted string) ([]byte, error) {
	roots, err := atomChildren(sinf, 0, len(sinf))
	if err != nil {
		return nil, err
	}

	if len(roots) != 1 || string(roots[0].tag[:]) != "sinf" {
		return nil, errors.New("expected outer sinf atom")
	}

	children, err := atomChildren(sinf, roots[0].start, roots[0].end)
	if err != nil {
		return nil, err
	}

	var schi *atom

	for i := range children {
		if string(children[i].tag[:]) == "schi" {
			if schi != nil {
				return nil, errors.New("expected one schi container")
			}

			schi = &children[i]
		}
	}

	if schi == nil {
		return nil, errors.New("expected one schi container")
	}

	fields, err := atomChildren(sinf, schi.start, schi.end)
	if err != nil {
		return nil, err
	}

	var match *atom

	for i := range fields {
		if string(fields[i].tag[:]) == wanted {
			if match != nil {
				return nil, fmt.Errorf("expected one %q field", wanted)
			}

			match = &fields[i]
		}
	}

	if match == nil {
		return nil, fmt.Errorf("expected one %q field", wanted)
	}

	return sinf[match.start:match.end], nil
}

// deriveWork16 unwraps the account credential against a SINF priv record to
// obtain the per-app 16-byte work key. Mirrors core.py derive_work16.
func deriveWork16(credential, sinf []byte) ([]byte, error) {
	nameField, err := sinfField(sinf, "name")
	if err != nil {
		return nil, err
	}

	name := nameField
	if i := indexByte(name, 0); i >= 0 {
		name = name[:i]
	}

	iviv, err := sinfField(sinf, "iviv")
	if err != nil {
		return nil, err
	}

	rawPriv, err := sinfField(sinf, "priv")
	if err != nil {
		return nil, err
	}

	switch len(rawPriv) {
	case 448:
	case 440:
		if !allZero(rawPriv[len(rawPriv)-8:]) {
			return nil, errors.New("invalid SINF priv-record trailer")
		}

		rawPriv = rawPriv[:len(rawPriv)-8]
	default:
		return nil, errors.New("unsupported SINF priv-record length")
	}

	if len(credential) != 16 || len(iviv) != 16 {
		return nil, errors.New("invalid SINF priv-record dimensions")
	}

	iv := md5.Sum(append(append([]byte{}, name...), iviv...))

	block, err := aes.NewCipher(xorBytes(credential, []byte("0000000000000000")))
	if err != nil {
		return nil, err
	}

	clear := make([]byte, len(rawPriv))
	cipher.NewCBCDecrypter(block, iv[:]).CryptBlocks(clear, rawPriv)

	if string(clear[:4]) != "itun" || string(clear[20:24]) != "key " || string(clear[44:48]) != "iviv" {
		return nil, errors.New("credential does not decode this SINF priv record")
	}

	return xorBytes(clear[24:40], workMask), nil
}

// arm64SupfRecordOffset locates the arm64 per-page record block in a SUPF.
// Mirrors core.py arm64_supf_record_offset.
func arm64SupfRecordOffset(supf []byte, requiredPages int) (int, error) {
	if len(supf) < 12 || (supf[0] != 3 && supf[0] != 5) {
		return 0, errors.New("unsupported SUPF format")
	}

	magic := string(supf[1:4])
	if magic != "507" && magic != "510" && magic != "612" {
		return 0, errors.New("unsupported SUPF format")
	}

	headerSize := 12
	if supf[0] == 3 {
		headerSize = 32
	}

	count := int(binary.BigEndian.Uint32(supf[8:]))
	if count <= 0 || count > 16 {
		return 0, errors.New("invalid SUPF architecture count")
	}

	pos := 12
	for range count {
		if pos+4+headerSize > len(supf) {
			return 0, errors.New("truncated SUPF architecture header")
		}

		length := int(binary.BigEndian.Uint32(supf[pos:]))
		cpu := binary.BigEndian.Uint32(supf[pos+4:])

		subtype := binary.BigEndian.Uint32(supf[pos+8:])
		if length < headerSize || pos+4+length > len(supf) {
			return 0, errors.New("invalid SUPF architecture length")
		}

		pages := int(binary.BigEndian.Uint32(supf[pos+headerSize:]))
		if cpu == cpuTypeARM64 && subtype == 0 {
			if pages < requiredPages || length < headerSize+pages*32 {
				return 0, errors.New("SUPF arm64 page records are incomplete")
			}

			return pos + 4 + headerSize, nil
		}

		pos += length + 4
	}

	return 0, errors.New("arm64 SUPF record missing")
}

func highByteFromContextWord(word uint64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], word^0x2D43FBF6ED1B8833)

	return b[:]
}

func sourceBlocks(wrapped []byte, absoluteIndex uint32) ([16]byte, [16]byte, [16]byte, error) {
	if len(wrapped) != 16 {
		return [16]byte{}, [16]byte{}, [16]byte{}, errors.New("invalid wrapped record")
	}

	context := contextBase ^ (uint64(absoluteIndex) << 12)

	var first, second, third [16]byte

	copy(first[:8], xorBytes(wrapped[8:16], constant[:8]))
	copy(first[8:], highByteFromContextWord(context))

	copy(second[:], xorBytes(wrapped, constant))

	thirdHigh := binary.BigEndian.Uint64(constant[:8]) ^ (uint64(absoluteIndex) << 12)
	binary.BigEndian.PutUint64(third[:8], thirdHigh)
	copy(third[8:], xorBytes(wrapped[:8], constant[8:]))

	return first, second, third, nil
}

func mixRound(before [8]uint32, selectors [8]byte) [8]uint32 {
	var out [8]uint32

	for pair := range 4 {
		a := before[selectors[pair*2]-0x36] ^ 0x18FB
		b := before[selectors[pair*2+1]-0x36] ^ 0x18FB
		mixed := a + b
		square := (mixed*mixed ^ roundConstants[pair])
		high := (mixed >> 16) & 0xFFFF
		low := ((0xCB61 - high*high) ^ square) & 0xFFFF
		out[pair*2] = low ^ 0x18FB
		out[pair*2+1] = (square >> 16) ^ 0x1E49
	}

	return out
}

func finish(state [16]byte) [16]byte {
	var initial [8]uint32
	for i := range 8 {
		initial[i] = uint32(binary.BigEndian.Uint16(state[i*2:])) ^ 0x18FB
	}

	row := initial
	for _, selectors := range roundSelectors {
		row = mixRound(row, selectors)
	}

	var final [8]uint32

	for j, selectors := range finalSelectors {
		var decoded [4]uint32
		for i, sel := range selectors {
			decoded[i] = row[sel] ^ 0x18FB
		}

		left := uint64(decoded[0]) | uint64(decoded[1])<<16
		right := uint64(decoded[2]) | uint64(decoded[3])<<16
		x9 := (left + right) & 0xFFFFFFFF
		x9 *= x9
		x9 ^= 0x4F3DAC1F8847818E
		x19 := finalConstants[j] ^ x9
		x9 = x19 ^ (x9 >> 32)
		low := (x9 ^ 0xB4E4) & 0xFFFF
		high := ((x9 >> 16) ^ 0x4F3D ^ 0x18FB) & 0xFFFF
		final[j*2] = uint32(low)
		final[j*2+1] = uint32(high)
	}

	var out [16]byte
	for i := range 8 {
		binary.BigEndian.PutUint16(out[i*2:], uint16(initial[i]^final[i]))
	}

	return out
}

// blockTransform is the per-page key primitive: an AES-128-ECB encryption of
// source^CONSTANT under the work-derived key. The former 223 KB white-box table
// computed exactly this. Mirrors core.py block_transform.
func blockTransform(block cipher.Block, source [16]byte) [16]byte {
	var out [16]byte
	block.Encrypt(out[:], xorBytes(source[:], constant))

	return out
}

func derivePageKey(block cipher.Block, wrapped []byte, absoluteIndex uint32) ([16]byte, error) {
	first, second, third, err := sourceBlocks(wrapped, absoluteIndex)
	if err != nil {
		return [16]byte{}, err
	}

	a := blockTransform(block, first)
	b := blockTransform(block, second)
	c := blockTransform(block, third)

	fa := finish(a)
	step := finish(xor16(fa, b))

	return finish(xor16(step, c)), nil
}

func xor16(a [16]byte, b [16]byte) [16]byte {
	var out [16]byte
	for i := range out {
		out[i] = a[i] ^ b[i]
	}

	return out
}

// decryptBinary decrypts every encrypted arm64 page of a Mach-O in place and
// clears cryptid. Mirrors core.py decrypt_binary. Returns the decrypted bytes
// and the number of pages processed; errCryptidZero if the slice is not
// encrypted.
func decryptBinary(source, sinf, supf, credential []byte) ([]byte, int, error) {
	info, err := arm64EncryptionInfo(source)
	if err != nil {
		return nil, 0, err
	}

	pageCount := info.cryptSize / pageSize

	recordStart, err := arm64SupfRecordOffset(supf, pageCount)
	if err != nil {
		return nil, 0, err
	}

	work, err := deriveWork16(credential, sinf)
	if err != nil {
		return nil, 0, err
	}

	keyCipher, err := aes.NewCipher(xorBytes(work, workMask))
	if err != nil {
		return nil, 0, err
	}

	result := make([]byte, len(source))
	copy(result, source)

	for localPage := range pageCount {
		record := supf[recordStart+32*localPage : recordStart+32*(localPage+1)]
		if len(record) != 32 {
			return nil, 0, errors.New("truncated SUPF page record")
		}

		absoluteIndex := uint32((info.base+info.cryptOff)/pageSize + localPage)

		key, err := derivePageKey(keyCipher, record[:16], absoluteIndex)
		if err != nil {
			return nil, 0, err
		}

		start := info.base + info.cryptOff + pageSize*localPage
		ciphertext := source[start : start+pageSize]

		block, err := aes.NewCipher(key[:])
		if err != nil {
			return nil, 0, err
		}

		cipher.NewCBCDecrypter(block, record[16:32]).CryptBlocks(result[start:start+pageSize], ciphertext)
	}

	binary.LittleEndian.PutUint32(result[info.cryptidOffset:], 0)

	return result, pageCount, nil
}

func indexByte(b []byte, c byte) int {
	for i := range b {
		if b[i] == c {
			return i
		}
	}

	return -1
}

func allZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}

	return true
}
