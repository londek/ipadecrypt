package storeauth

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"math/big"

	"golang.org/x/crypto/pbkdf2"
)

// GrandSlam uses the RFC 5054 2048-bit group with Apple's password derivation.
const grandSlamPrime = "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4" +
	"A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF60" +
	"95179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF" +
	"747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B907" +
	"8717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB37861" +
	"60279004E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DB" +
	"FBB694B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73"

type grandSlamSRP struct {
	secret *big.Int
	public *big.Int
}

type grandSlamProof struct {
	client, server, key []byte
}

func newGrandSlamSRP() (*grandSlamSRP, error) {
	modulus, _ := new(big.Int).SetString(grandSlamPrime, 16)
	// Sample uniformly from the nonzero 256-bit secrets.
	limit := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))
	secret, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, err
	}
	secret.Add(secret, big.NewInt(1))

	return &grandSlamSRP{secret: secret, public: new(big.Int).Exp(big.NewInt(2), secret, modulus)}, nil
}

func grandSlamHash(parts ...[]byte) []byte {
	digest := sha256.New()
	for _, part := range parts {
		_, _ = digest.Write(part)
	}

	return digest.Sum(nil)
}

func (s *grandSlamSRP) complete(user, password string, salt, server []byte, iterations uint64, protocol string) (grandSlamProof, error) {
	if len(user) == 0 || len(user) > 4096 || len(password) == 0 || len(password) > 4096 ||
		len(salt) == 0 || len(salt) > 1024 || len(server) == 0 || len(server) > 256 ||
		iterations == 0 || iterations > 1_000_000 || (protocol != "s2k" && protocol != "s2k_fo") {
		return grandSlamProof{}, errors.New("invalid GrandSlam challenge")
	}

	modulus, _ := new(big.Int).SetString(grandSlamPrime, 16)
	generator := big.NewInt(2)
	remote := new(big.Int).SetBytes(server)
	if remote.Sign() == 0 || remote.Cmp(modulus) >= 0 {
		return grandSlamProof{}, errors.New("invalid GrandSlam server public value")
	}

	pad := func(value *big.Int) []byte { return value.FillBytes(make([]byte, 256)) }
	scrambling := new(big.Int).SetBytes(grandSlamHash(pad(s.public), pad(remote)))
	if scrambling.Sign() == 0 {
		return grandSlamProof{}, errors.New("invalid GrandSlam scrambling value")
	}

	material := grandSlamHash([]byte(password))
	if protocol == "s2k_fo" {
		encoded := []byte(hex.EncodeToString(material))
		clear(material)
		material = encoded
	}
	derived := pbkdf2.Key(material, salt, int(iterations), sha256.Size, sha256.New)
	clear(material)
	defer clear(derived)

	inner := new(big.Int).SetBytes(grandSlamHash([]byte(":"), derived))
	exponent := new(big.Int).SetBytes(grandSlamHash(salt, inner.Bytes()))
	verifier := new(big.Int).Exp(generator, exponent, modulus)
	multiplier := new(big.Int).SetBytes(grandSlamHash(pad(modulus), pad(generator)))
	base := new(big.Int).Sub(remote, new(big.Int).Mul(multiplier, verifier))
	base.Mod(base, modulus)
	power := new(big.Int).Add(s.secret, new(big.Int).Mul(scrambling, exponent))
	shared := new(big.Int).Exp(base, power, modulus)
	key := grandSlamHash(shared.Bytes())
	groupHash := grandSlamHash(modulus.Bytes())
	generatorHash := grandSlamHash(pad(generator))
	for index := range groupHash {
		groupHash[index] ^= generatorHash[index]
	}

	proof := grandSlamHash(groupHash, grandSlamHash([]byte(user)), salt, s.public.Bytes(), remote.Bytes(), key)

	return grandSlamProof{client: proof, server: grandSlamHash(s.public.Bytes(), proof, key), key: key}, nil
}

func (p grandSlamProof) decrypt(serverProof, encrypted []byte) ([]byte, error) {
	if len(p.server) != sha256.Size || len(p.key) != sha256.Size ||
		subtle.ConstantTimeCompare(serverProof, p.server) != 1 {
		return nil, errors.New("GrandSlam server proof verification failed")
	}
	if len(encrypted) == 0 || len(encrypted) > 1<<20 || len(encrypted)%aes.BlockSize != 0 {
		return nil, errors.New("invalid GrandSlam encrypted response")
	}

	derive := func(label string) []byte {
		mac := hmac.New(sha256.New, p.key)
		_, _ = mac.Write([]byte(label))

		return mac.Sum(nil)
	}
	key := derive("extra data key:")
	defer clear(key)
	iv := derive("extra data iv:")
	defer clear(iv)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	plain := make([]byte, len(encrypted))
	cipher.NewCBCDecrypter(block, iv[:aes.BlockSize]).CryptBlocks(plain, encrypted)
	padding := int(plain[len(plain)-1])
	if padding < 1 || padding > aes.BlockSize ||
		!bytes.Equal(plain[len(plain)-padding:], bytes.Repeat([]byte{byte(padding)}, padding)) {
		clear(plain)

		return nil, errors.New("invalid GrandSlam response padding")
	}

	return plain[:len(plain)-padding], nil
}
