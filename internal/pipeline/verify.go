package pipeline

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"strings"

	"github.com/londek/ipadecrypt/internal/macho"
)

type VerifyMismatch struct {
	Name   string
	Reason string
}

type VerifyResult struct {
	Scanned        int              // Mach-Os parsed in output IPA
	Compared       int              // additionally byte-checked against source
	StillEncrypted []string         // cryptid != 0 (decrypt didn't write through)
	AllZeroCrypt   []string         // cryptid == 0 but crypt region all zeros (decrypt-on-fault never fired)
	Mismatches     []VerifyMismatch // bytes outside crypt region differ from source
	Missing        []string         // output entry has no source counterpart (only when source given)
	Skipped        []string         // output Mach-O failed to parse
}

func (r VerifyResult) OK() bool {
	return len(r.StillEncrypted) == 0 &&
		len(r.AllZeroCrypt) == 0 &&
		len(r.Mismatches) == 0
}

// Verify scans every Mach-O in the decrypted output IPA, asserting
// cryptid==0 and that the FairPlay crypt region isn't a zero-fill (a
// signal that decryption produced no plaintext). When
// sourceIPA is non-empty, each output is also byte-compared against
// its source slice outside the cryptid byte and the encrypted region,
// catching cryptid-zeroed-without-decrypting and any out-of-band byte
// corruption. When skipAppex is true, entries under Payload/<App>.app
// /PlugIns/ are ignored - decryption left them encrypted on purpose.
//
// The offline decryptor rewrites binaries in place, so each output entry is
// byte-identical to its source counterpart except within the encrypted
// arm64 slice.
func Verify(outputIPA, sourceIPA string, skipAppex bool) (VerifyResult, error) {
	var res VerifyResult

	out, err := zip.OpenReader(outputIPA)
	if err != nil {
		return res, fmt.Errorf("open output %s: %w", outputIPA, err)
	}
	defer out.Close()

	var srcByName map[string]*zip.File

	if sourceIPA != "" {
		src, err := zip.OpenReader(sourceIPA)
		if err != nil {
			return res, fmt.Errorf("open source %s: %w", sourceIPA, err)
		}
		defer src.Close()

		srcByName = make(map[string]*zip.File, len(src.File))
		for _, f := range src.File {
			srcByName[f.Name] = f
		}
	}

	for _, of := range out.File {
		if !strings.HasPrefix(of.Name, "Payload/") || of.FileInfo().IsDir() {
			continue
		}

		if skipAppex && isAppExtPath(of.Name) {
			continue
		}

		outData, isMacho, err := readMachO(of)
		if err != nil {
			return res, fmt.Errorf("read %s: %w", of.Name, err)
		}

		if !isMacho {
			continue
		}

		res.Scanned++

		encrypted, err := macho.SliceHasCryptid(outData)
		if err != nil {
			res.Skipped = append(res.Skipped, of.Name)
			continue
		}

		if encrypted {
			res.StillEncrypted = append(res.StillEncrypted, of.Name)
			continue
		}

		// Source-bearing path: precise compare (handles its own all-zero
		// check, gated on srcCrypt.Cryptid to avoid false positives on
		// legitimately-plaintext passthrough slices).
		if sf := srcByName[of.Name]; sf != nil {
			srcData, srcIsMacho, err := readMachO(sf)
			if err != nil {
				return res, fmt.Errorf("read source %s: %w", of.Name, err)
			}

			// Source isn't Mach-O (TBD stubs, .a archives, resolved
			// symlinks) - nothing FairPlay touches, skip.
			if !srcIsMacho {
				continue
			}

			if reason := compareMachOSlice(outData, srcData); reason != "" {
				res.Mismatches = append(res.Mismatches, VerifyMismatch{Name: of.Name, Reason: reason})
				continue
			}

			res.Compared++

			continue
		}

		if srcByName != nil {
			res.Missing = append(res.Missing, of.Name)
		}

		// Source-free fallback: flag thin outputs whose entire crypt
		// region is zeros. False positives are possible if the source
		// shipped LC_ENCRYPTION_INFO with cryptid==0 over a genuinely
		// zero region - rare, and source-aware verify catches it.
		if cryptZeroed(outData) {
			res.AllZeroCrypt = append(res.AllZeroCrypt, of.Name)
		}
	}

	return res, nil
}

// cryptZeroed reports whether any encrypted arm64 slice's crypt region is an
// all-zero fill - the signal that decryption produced no plaintext. Handles
// both thin and fat (in-place) output.
func cryptZeroed(data []byte) bool {
	slices, err := macho.FatSlices(data)
	if err != nil {
		return false
	}

	for _, s := range slices {
		slice := data[s.Offset : s.Offset+s.Size]

		info, err := macho.ReadEncryptionInfo(slice)
		if err != nil || info.CryptSize == 0 {
			continue
		}

		if s.Offset+info.CryptOff+info.CryptSize > uint64(len(data)) {
			continue
		}

		if isAllZero(slice[info.CryptOff : info.CryptOff+info.CryptSize]) {
			return true
		}
	}

	return false
}

// readMachO returns the file's bytes if it begins with a Mach-O / fat magic.
// (nil, false, nil) signals "not a Mach-O, skip".
func readMachO(f *zip.File) ([]byte, bool, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, false, err
	}
	defer rc.Close()

	head := make([]byte, 4)
	if n, _ := io.ReadFull(rc, head); n < 4 || !macho.IsMagic(head) {
		return nil, false, nil
	}

	rest, err := io.ReadAll(rc)
	if err != nil {
		return nil, false, err
	}

	return append(head, rest...), true, nil
}

// compareMachOSlice returns "" when the output is consistent with the
// source. The offline decryptor works in place inside the full (possibly
// fat) file: only the encrypted arm64 slice's cryptid u32 and crypt region
// change, everything else is byte-identical. So output and source must be
// the same length and equal everywhere except, within the source's single
// encrypted slice, the cryptid word (zeroed) and the crypt bytes (plaintext).
func compareMachOSlice(outData, srcData []byte) string {
	if len(outData) != len(srcData) {
		return fmt.Sprintf("size differs: output=%d source=%d", len(outData), len(srcData))
	}

	slices, err := macho.FatSlices(srcData)
	if err != nil {
		return "parse source: " + err.Error()
	}

	var (
		found    bool
		sliceOff uint64
		srcCrypt macho.EncryptionInfo
	)

	for _, s := range slices {
		info, err := macho.ReadEncryptionInfo(srcData[s.Offset : s.Offset+s.Size])
		if err != nil {
			continue
		}

		if found {
			return "source has more than one encrypted slice"
		}

		found = true
		sliceOff = s.Offset
		srcCrypt = info
	}

	// No encrypted slice in source → nothing should have changed.
	if !found {
		if bytes.Equal(outData, srcData) {
			return ""
		}

		return "output differs from unencrypted source"
	}

	cryptidAbs := sliceOff + srcCrypt.CryptidOffset
	cryptStart := sliceOff + srcCrypt.CryptOff
	cryptEnd := cryptStart + srcCrypt.CryptSize

	if cryptEnd > uint64(len(outData)) {
		return "crypt region exceeds file"
	}

	if !bytes.Equal(outData[:cryptidAbs], srcData[:cryptidAbs]) {
		return "bytes before cryptid differ"
	}

	if binary.LittleEndian.Uint32(outData[cryptidAbs:cryptidAbs+4]) != 0 {
		return "cryptid not zeroed"
	}

	if !bytes.Equal(outData[cryptidAbs+4:cryptStart], srcData[cryptidAbs+4:cryptStart]) {
		return "load-commands between cryptid and cryptoff differ"
	}

	if !bytes.Equal(outData[cryptEnd:], srcData[cryptEnd:]) {
		return "bytes after encrypted region differ (LINKEDIT/etc)"
	}

	outCrypt := outData[cryptStart:cryptEnd]

	// Source already plaintext: bytes must match verbatim.
	if srcCrypt.Cryptid == 0 {
		if bytes.Equal(outCrypt, srcData[cryptStart:cryptEnd]) {
			return ""
		}

		return "crypt region differs from already-plaintext source"
	}

	if isAllZero(outCrypt) {
		return "crypt region is all zeros (decrypt produced no plaintext)"
	}

	if bytes.Equal(outCrypt, srcData[cryptStart:cryptEnd]) {
		return "crypt region byte-equal to source ciphertext (cryptid zeroed without decrypting)"
	}

	return ""
}

func isAllZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}

	return true
}
