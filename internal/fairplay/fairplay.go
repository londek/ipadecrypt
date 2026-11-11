// Package fairplay decrypts FairPlay-encrypted App Store Mach-O binaries on the
// host, given the IPA's SINF and SUPF/SUPP records and a 16-byte per-account
// credential.
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
	cpuTypeARM       = 0x0000000C
	cpuTypeARM64     = 0x0100000C
	cpuTypeARM6432   = 0x0200000C
	cpuSubtypeARMV7  = 9
	cpuSubtypeARM64E = 2
	cpuSubtypeMask   = 0x00FFFFFF
	pageSize         = 4096

	lcEncryptionInfo   = 0x21
	lcEncryptionInfo64 = 0x2C
	machoMagicLE       = 0xFEEDFACE
	machoMagic64LE     = 0xFEEDFACF
)

var (
	roundSelectors = [4][4][2]int{
		{{0, 1}, {2, 3}, {4, 5}, {6, 7}},
		{{2, 1}, {0, 3}, {4, 7}, {6, 5}},
		{{2, 0}, {4, 1}, {6, 3}, {7, 5}},
		{{1, 2}, {4, 0}, {7, 3}, {5, 6}},
	}
	roundConstants = [4]uint32{0x68547C2E, 0x7E05E1DE, 0xD495038B, 0x0AB24ADD}
	finalSelectors = [4][4]int{{0, 1, 2, 3}, {0, 2, 4, 6}, {0, 3, 5, 7}, {4, 5, 6, 7}}
	finalConstants = [4]uint32{0x5B7198C7, 0xEB5DE22C, 0x0F8AA8FA, 0xF6E1BB3F}
)

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

// machoInfo locates the slice to decrypt and its encrypted region within a
// (possibly fat) Mach-O.
type machoInfo struct {
	base          int
	size          int
	cpu           uint32
	subtype       uint32
	cryptOff      int
	cryptSize     int
	cryptidOffset int
}

type armSlice struct {
	base, size   int
	cpu, subtype uint32
}

// armEncryptionInfo parses the Mach-O header(s) and returns the encrypted
// region of the slice the output is thinned to: the plain arm64 slice, else
// arm64e, else arm64_32, else 32-bit ARM (armv7 when there are several). It
// mirrors core.py arm_encryption_infos, which decrypts every ARM slice in
// place instead. errNotEncrypted reports a slice with no active encryption
// command.
func armEncryptionInfo(data []byte) (machoInfo, error) {
	var plain, arm64e, arm6432, arm32 []armSlice

	addSlice := func(cpu, sub uint32, base, size int) {
		s := armSlice{base, size, cpu, sub}

		switch {
		case cpu == cpuTypeARM64 && sub&cpuSubtypeMask == cpuSubtypeARM64E:
			arm64e = append(arm64e, s)
		case cpu == cpuTypeARM64:
			plain = append(plain, s)
		case cpu == cpuTypeARM6432:
			arm6432 = append(arm6432, s)
		case cpu == cpuTypeARM:
			arm32 = append(arm32, s)
		}
	}

	switch {
	case len(data) >= 4 && data[0] == 0xca && data[1] == 0xfe && data[2] == 0xba && data[3] == 0xbe:
		count := int(binary.BigEndian.Uint32(data[4:]))
		if count <= 0 || count > 16 || 8+count*20 > len(data) {
			return machoInfo{}, errors.New("invalid FAT32 architecture table")
		}

		for i := range count {
			off := 8 + i*20
			addSlice(binary.BigEndian.Uint32(data[off:]), binary.BigEndian.Uint32(data[off+4:]),
				int(binary.BigEndian.Uint32(data[off+8:])), int(binary.BigEndian.Uint32(data[off+12:])))
		}
	case len(data) >= 4 && data[0] == 0xca && data[1] == 0xfe && data[2] == 0xba && data[3] == 0xbf:
		count := int(binary.BigEndian.Uint32(data[4:]))
		if count <= 0 || count > 16 || 8+count*32 > len(data) {
			return machoInfo{}, errors.New("invalid FAT64 architecture table")
		}

		for i := range count {
			off := 8 + i*32
			addSlice(binary.BigEndian.Uint32(data[off:]), binary.BigEndian.Uint32(data[off+4:]),
				int(binary.BigEndian.Uint64(data[off+8:])), int(binary.BigEndian.Uint64(data[off+16:])))
		}
	case len(data) >= 28 && (data[0] == 0xce || data[0] == 0xcf) && data[1] == 0xfa && data[2] == 0xed && data[3] == 0xfe:
		addSlice(binary.LittleEndian.Uint32(data[4:]), binary.LittleEndian.Uint32(data[8:]), 0, len(data))
	default:
		return machoInfo{}, errors.New("not a supported ARM Mach-O")
	}

	var slices []armSlice

	for _, group := range [][]armSlice{plain, arm64e, arm6432, arm32} {
		if len(group) > 0 {
			slices = group
			break
		}
	}

	// Fat 32-bit apps pair armv7 with armv7s or armv6; armv7 runs on every
	// device that runs either.
	if len(slices) > 1 && slices[0].cpu == cpuTypeARM {
		var armv7 []armSlice

		for _, s := range slices {
			if s.subtype&cpuSubtypeMask == cpuSubtypeARMV7 {
				armv7 = append(armv7, s)
			}
		}

		slices = armv7
	}

	if len(slices) != 1 {
		return machoInfo{}, fmt.Errorf("expected one ARM slice to decrypt, found %d", len(slices))
	}

	chosen := slices[0]
	base, sliceSize := chosen.base, chosen.size

	// arm64_32 uses the 32-bit header and load command, like 32-bit ARM.
	is64 := chosen.cpu == cpuTypeARM64

	var (
		headerSize = 28
		encCmd     = uint32(lcEncryptionInfo)
		wantMagic  = uint32(machoMagicLE)
	)

	if is64 {
		headerSize, encCmd, wantMagic = 32, lcEncryptionInfo64, machoMagic64LE
	}

	if base+sliceSize > len(data) || base+headerSize > len(data) {
		return machoInfo{}, errors.New("Mach-O slice exceeds file")
	}

	magic := binary.LittleEndian.Uint32(data[base:])
	cpu := binary.LittleEndian.Uint32(data[base+4:])
	ncmds := int(binary.LittleEndian.Uint32(data[base+16:]))
	sizeofcmds := int(binary.LittleEndian.Uint32(data[base+20:]))

	if magic != wantMagic || cpu != chosen.cpu || ncmds > 1000 {
		return machoInfo{}, errors.New("invalid Mach-O slice header")
	}

	pos := base + headerSize

	commandsEnd := pos + sizeofcmds
	if commandsEnd > base+sliceSize {
		return machoInfo{}, errors.New("load commands exceed Mach-O slice")
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

		if cmd == encCmd {
			if size < 20 {
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

	if pos != commandsEnd {
		return machoInfo{}, errors.New("load command sizes do not match Mach-O header")
	}

	if found == 0 || (found == 1 && cryptid == 0) {
		return machoInfo{}, errNotEncrypted
	}

	if found != 1 {
		return machoInfo{}, fmt.Errorf("expected one encryption command, found %d", found)
	}

	if cryptid != 1 || cryptSize == 0 || cryptSize%pageSize != 0 {
		return machoInfo{}, fmt.Errorf("unsupported cryptid/size: %d, %d", cryptid, cryptSize)
	}

	if cryptOff+cryptSize > sliceSize || cryptidOffset >= base+cryptOff {
		return machoInfo{}, errors.New("invalid encrypted region bounds")
	}

	return machoInfo{
		base: base, size: sliceSize, cpu: chosen.cpu, subtype: chosen.subtype,
		cryptOff: cryptOff, cryptSize: cryptSize, cryptidOffset: cryptidOffset,
	}, nil
}

// errNotEncrypted reports a slice that has no encryption command or whose
// cryptid is already 0.
var errNotEncrypted = errors.New("Mach-O slice is not encrypted")

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

	return clear[24:40], nil
}

// isArcadeSinf reports whether sinf is an Apple Arcade license, which only the
// account's Arcade credential decodes. Mirrors retrieve.py's key[0] == 4 check.
func isArcadeSinf(sinf []byte) bool {
	key, err := sinfField(sinf, "key ")
	return err == nil && len(key) == 4 && key[0] == 4
}

// CredentialDecodes reports whether credential unwraps sinf's priv record, i.e.
// whether it is the credential of that license's account and kind.
func CredentialDecodes(credential, sinf []byte) bool {
	_, err := deriveWork16(credential, sinf)
	return err == nil
}

// pclassPageKeyOffset returns the offset of the 32-byte key for absolutePage
// in a SUPP (.supp v01 / .v4.supp v04): one table indexing every 4 KB page of
// the file from offset 0, so page p sits at base + 32*p. The v01 header
// carries a 20-byte code-signature SHA-1 that v04 omits. Mirrors core.py
// pclass_page_key_offset.
func pclassPageKeyOffset(supp []byte, absolutePage int) (int, error) {
	if len(supp) < 8 || (supp[0] != 1 && supp[0] != 4) {
		return 0, errors.New("unsupported SUPP format")
	}

	pos := 4
	if supp[0] == 1 {
		pos += 20
	}

	if pos+4 > len(supp) {
		return 0, errors.New("truncated SUPP header")
	}

	count := int(binary.BigEndian.Uint32(supp[pos:]))
	if count <= 0 || count > 1<<20 || pos+4+count*32 > len(supp) {
		return 0, errors.New("invalid SUPP page count")
	}

	if absolutePage < 0 || absolutePage >= count {
		return 0, errors.New("SUPP page key missing")
	}

	return pos + 4 + 32*absolutePage, nil
}

// armSupfRecordOffset locates the per-page record block of the slice with the
// given cputype and subtype in a SUPF. Mirrors core.py arm_supf_record_offset,
// but compares subtypes without their capability bits.
func armSupfRecordOffset(supf []byte, requiredPages int, wantedCPU, wantedSubtype uint32) (int, error) {
	if len(supf) < 12 || (supf[0] != 3 && supf[0] != 5) {
		return 0, errors.New("unsupported SUPF format")
	}

	magic := string(supf[1:4])
	if magic != "319" && magic != "322" && magic != "502" && magic != "507" && magic != "510" && magic != "612" {
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
		if cpu == wantedCPU && subtype&cpuSubtypeMask == wantedSubtype&cpuSubtypeMask {
			if pages < requiredPages || length < headerSize+pages*32 {
				return 0, errors.New("SUPF page records are incomplete")
			}

			return pos + 4 + headerSize, nil
		}

		pos += length + 4
	}

	return 0, fmt.Errorf("SUPF record missing for cputype=0x%x cpusubtype=0x%x", wantedCPU, wantedSubtype)
}

func sourceBlocks(wrapped []byte, absoluteIndex uint32) ([16]byte, [16]byte, [16]byte, error) {
	if len(wrapped) != 16 {
		return [16]byte{}, [16]byte{}, [16]byte{}, errors.New("invalid wrapped record")
	}

	var pageOffset [8]byte
	binary.BigEndian.PutUint64(pageOffset[:], uint64(absoluteIndex)<<12)

	var first, second, third [16]byte

	copy(first[:8], wrapped[8:16])
	copy(first[8:], pageOffset[:])

	copy(second[:], wrapped)

	copy(third[:8], pageOffset[:])
	copy(third[8:], wrapped[:8])

	return first, second, third, nil
}

// finish mixes a block as eight big-endian 16-bit words: four rounds over
// word pairs, then one over 32-bit word quartets, XORed back onto the input.
// Mirrors core.py finish.
func finish(state [16]byte) [16]byte {
	var initial [8]uint32
	for i := range 8 {
		initial[i] = uint32(binary.BigEndian.Uint16(state[i*2:]))
	}

	src := initial

	for _, selectors := range roundSelectors {
		var dst [8]uint32

		for i, pair := range selectors {
			mixed := src[pair[0]] + src[pair[1]] // carry bit kept
			x := mixed*mixed ^ mixed>>16 ^ roundConstants[i]
			dst[i*2], dst[i*2+1] = x&0xFFFF, x>>16
		}

		src = dst
	}

	var out [16]byte

	for i, quartet := range finalSelectors {
		mixed := (src[quartet[1]]<<16 | src[quartet[0]]) + (src[quartet[3]]<<16 | src[quartet[2]]) // carry bit dropped
		square := uint64(mixed) * uint64(mixed)
		x := uint32(square) ^ uint32(square>>32) ^ finalConstants[i]
		binary.BigEndian.PutUint16(out[i*4:], uint16(initial[i*2]^x&0xFFFF))
		binary.BigEndian.PutUint16(out[i*4+2:], uint16(initial[i*2+1]^x>>16))
	}

	return out
}

// blockTransform is the per-page key primitive: an AES-128-ECB encryption of
// source under the work key. Mirrors core.py block_transform.
func blockTransform(block cipher.Block, source [16]byte) [16]byte {
	var out [16]byte
	block.Encrypt(out[:], source[:])

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

// decryptBinary decrypts every encrypted page of one slice of a Mach-O and
// clears cryptid. supf holds either a SUPF (.supf/.v5.supf) or a SUPP
// (.supp/.v4.supp). Mirrors core.py decrypt_binary, except that a fat binary
// is thinned to that one slice (see armEncryptionInfo): the others are
// dropped like the on-device helper does. Returns the decrypted thin Mach-O
// and the number of pages processed; errNotEncrypted if the slice is not
// encrypted.
func decryptBinary(source, sinf, supf, credential []byte) ([]byte, int, error) {
	info, err := armEncryptionInfo(source)
	if err != nil {
		return nil, 0, err
	}

	pageCount := info.cryptSize / pageSize
	firstPage := (info.base + info.cryptOff) / pageSize
	pclass := len(supf) > 0 && (supf[0] == 1 || supf[0] == 4)

	recordStart := 0
	if !pclass {
		recordStart, err = armSupfRecordOffset(supf, pageCount, info.cpu, info.subtype)
		if err != nil {
			return nil, 0, err
		}
	}

	work, err := deriveWork16(credential, sinf)
	if err != nil {
		return nil, 0, err
	}

	keyCipher, err := aes.NewCipher(work)
	if err != nil {
		return nil, 0, err
	}

	slice := source[info.base : info.base+info.size]

	result := make([]byte, len(slice))
	copy(result, slice)

	for localPage := range pageCount {
		absoluteIndex := firstPage + localPage
		if pclass {
			recordStart, err = pclassPageKeyOffset(supf, absoluteIndex)
			if err != nil {
				return nil, 0, err
			}
		}

		if recordStart+32 > len(supf) {
			return nil, 0, errors.New("truncated SUPF/SUPP page record")
		}

		record := supf[recordStart : recordStart+32]
		recordStart += 32

		key, err := derivePageKey(keyCipher, record[:16], uint32(absoluteIndex))
		if err != nil {
			return nil, 0, err
		}

		start := info.cryptOff + pageSize*localPage
		ciphertext := slice[start : start+pageSize]

		block, err := aes.NewCipher(key[:])
		if err != nil {
			return nil, 0, err
		}

		cipher.NewCBCDecrypter(block, record[16:32]).CryptBlocks(result[start:start+pageSize], ciphertext)
	}

	binary.LittleEndian.PutUint32(result[info.cryptidOffset-info.base:], 0)

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
