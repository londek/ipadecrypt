// Copyright 2013-2017 Sudhi Herle <sudhi.herle-at-gmail-dot-com>
// License: MIT
// Derived from the SRP implementation adapted for Apple by blacktop.

// Package srp implements the SHA-256 SRP variant used by Apple's GrandSlam.
// The Store client uses the fixed RFC 5054 2048-bit group; server-side SRP
// enrollment and the separate IDMSA protocol are outside this package.
package srp

import (
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"

	"golang.org/x/crypto/pbkdf2"
)

type SRP struct {
	h    crypto.Hash
	pf   *primeField
	a, A *big.Int
}

type primeField struct {
	g, N *big.Int
	n    int // modulus width in bytes
}

// PasswordProtocol selects how Apple's SRP variant derives the
// PBKDF2 input from the account password. The server chooses one of the
// protocols the client advertised in the init request and reports it in
// the init response; the client must derive the proof the same way.
type PasswordProtocol string

const (
	// ProtocolS2K feeds the raw SHA-256 digest of the password into PBKDF2.
	ProtocolS2K PasswordProtocol = "s2k"
	// ProtocolS2KFO feeds the lowercase hex encoding of the SHA-256 digest
	// into PBKDF2 (legacy accounts).
	ProtocolS2KFO PasswordProtocol = "s2k_fo"
)

// derivePassword returns the PBKDF2-derived password input for the given
// Apple SRP password protocol.
func derivePassword(protocol PasswordProtocol, password, salt []byte, iter int) ([]byte, error) {
	digest := sha256.Sum256(password)

	var input []byte

	switch protocol {
	case ProtocolS2K:
		input = digest[:]
	case ProtocolS2KFO:
		input = []byte(hex.EncodeToString(digest[:]))
	default:
		return nil, fmt.Errorf("srp: unsupported password protocol %q", protocol)
	}

	return pbkdf2.Key(input, salt, iter, 32, sha256.New), nil
}

// hash byte stream and return as bytes
func (s *SRP) hashbyte(a ...[]byte) []byte {
	h := s.h.New()
	for _, z := range a {
		h.Write(z)
	}

	return h.Sum(nil)
}

// hash a number of byte strings and return the resulting hash as
// bigint
func (s *SRP) hashint(a ...[]byte) *big.Int {
	i := big.NewInt(0)
	b := s.hashbyte(a...)
	i.SetBytes(b)

	return i
}

func xorBytes(a, b []byte) []byte {
	if len(a) != len(b) {
		return nil
	}

	result := make([]byte, len(a))
	for i := range a {
		result[i] = a[i] ^ b[i]
	}

	return result
}

// pad encodes x at the requested width; larger values retain their full bytes.
func pad(x *big.Int, n int) []byte {
	b := x.Bytes()
	if len(b) >= n {
		return b
	}

	padded := make([]byte, n)
	copy(padded[n-len(b):], b)

	return padded
}

// RFC 5054, Appendix A, 2048-bit group (generator 2).
const grandSlamModulus = "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB694B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73"

func findPrimeField(bits int) (*primeField, error) {
	if bits != 2048 {
		return nil, fmt.Errorf("srp: unsupported group size %d", bits)
	}

	modulus, ok := new(big.Int).SetString(grandSlamModulus, 16)
	if !ok {
		return nil, fmt.Errorf("srp: invalid group modulus")
	}

	return &primeField{g: big.NewInt(2), N: modulus, n: 256}, nil
}
