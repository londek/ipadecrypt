package credmint

import (
	"errors"

	"github.com/londek/ipadecrypt/internal/fairplay"
)

// arcadeInverses[i] is the multiplicative inverse of 2i+1 modulo 256.
var arcadeInverses = func() [16]byte {
	var inverses [16]byte

	for i := range inverses {
		for c := 1; c < 256; c += 2 {
			if byte(2*i+1)*byte(c) == 1 {
				inverses[i] = byte(c)
			}
		}
	}

	return inverses
}()

// arcadeTableMasks finds the 256x16-byte tables in the fairplayd image whose
// rows are all one row XORed with a per-row constant, and returns each table's
// first row XORed with its first byte. Mirrors retrieve.py arcade_table_masks.
func arcadeTableMasks(image []byte) [][16]byte {
	var masks [][16]byte

	for offset := 0; offset+4096 <= len(image); offset++ {
		delta := image[offset] ^ image[offset+16]
		if image[offset+1]^image[offset+17] != delta || image[offset+2]^image[offset+18] != delta {
			continue
		}

		first := image[offset : offset+16]
		if distinctBytes(first) < 8 {
			continue
		}

		table := true

		for i := 3; i < 16 && table; i++ {
			table = image[offset+i]^image[offset+16+i] == delta
		}

		for row := 2; row < 256 && table; row++ {
			at := offset + row*16
			rowDelta := image[at] ^ first[0]

			for i := 1; i < 16 && table; i++ {
				table = image[at+i]^first[i] == rowDelta
			}
		}

		if !table {
			continue
		}

		var mask [16]byte
		for i := range mask {
			mask[i] = first[i] ^ first[0]
		}

		masks = append(masks, mask)
	}

	return masks
}

// arcadeCredential recovers the Arcade credential from the three buffer
// snapshots arcade-capture.ios writes: every table mask, block offset and base
// byte yields a candidate, and the first one that decodes sinf is it. Mirrors
// retrieve.py arcade_credential.
func arcadeCredential(blocks [][]byte, sinf, image []byte) ([]byte, error) {
	if len(blocks) != 3 {
		return nil, errors.New("expected three Arcade block snapshots")
	}

	masks := arcadeTableMasks(image)
	if len(masks) == 0 {
		return nil, errors.New("no Arcade table masks found in fairplayd")
	}

	candidate := make([]byte, credentialSize)

	for _, block := range [][]byte{blocks[1], blocks[0], blocks[2]} {
		for _, relative := range masks {
			for offset := 0; offset+16 <= len(block); offset++ {
				for base := range 256 {
					for i := range candidate {
						v := block[offset+i] ^ relative[(offset+i)&15] ^ byte(base)
						candidate[i] = (v-byte(i))*arcadeInverses[i] ^ 0x30
					}

					if fairplay.CredentialDecodes(candidate, sinf) {
						return candidate, nil
					}
				}
			}
		}
	}

	return nil, errors.New("no Arcade credential found in the captured blocks")
}

func distinctBytes(b []byte) int {
	var seen [256]bool

	n := 0

	for _, c := range b {
		if !seen[c] {
			seen[c] = true
			n++
		}
	}

	return n
}
