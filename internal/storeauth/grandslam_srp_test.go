package storeauth

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/crypto/pbkdf2"
	"howett.net/plist"
)

// The server independently computes the SRP verifier and shared secret. No
// client proof or derived key is supplied by a mock to make sign-in succeed.
func TestSignInGrandSlam(t *testing.T) {
	for _, protocol := range []string{"s2k", "s2k_fo"} {
		for _, scenario := range []struct {
			name, password              string
			corruptProof, wrongPassword bool
		}{
			{name: "valid", password: "test-password"},
			{name: "invalid server proof", password: "test-password", corruptProof: true},
			{name: "incorrect password", password: "incorrect-password", wrongPassword: true},
		} {
			t.Run(protocol+"/"+scenario.name, func(t *testing.T) {
				const user, password = "person@example.com", "test-password"
				modulus, _ := new(big.Int).SetString(grandSlamPrime, 16)
				generator := big.NewInt(2)
				pad := func(v *big.Int) []byte { return v.FillBytes(make([]byte, 256)) }
				hash := func(parts ...[]byte) []byte {
					h := sha256.New()
					for _, part := range parts {
						_, _ = h.Write(part)
					}
					return h.Sum(nil)
				}
				salt := []byte("server-supplied-salt")
				material := sha256.Sum256([]byte(password))
				input := material[:]
				if protocol == "s2k_fo" {
					input = []byte(hex.EncodeToString(input))
				}
				derived := pbkdf2.Key(input, salt, 100, 32, sha256.New)
				x := new(big.Int).SetBytes(hash(salt, new(big.Int).SetBytes(hash([]byte(":"), derived)).Bytes()))
				verifier := new(big.Int).Exp(generator, x, modulus)
				serverSecret := big.NewInt(91234567)
				multiplier := new(big.Int).SetBytes(hash(pad(modulus), pad(generator)))
				serverPublic := new(big.Int).Mul(multiplier, verifier)
				serverPublic.Add(serverPublic, new(big.Int).Exp(generator, serverSecret, modulus)).Mod(serverPublic, modulus)
				var public, key []byte
				calls := 0
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					calls++
					data, err := io.ReadAll(r.Body)
					if err != nil {
						t.Error(err)
						w.WriteHeader(500)
						return
					}
					var request struct{ Request map[string]any }
					if _, err := plist.Unmarshal(data, &request); err != nil {
						t.Error(err)
						w.WriteHeader(500)
						return
					}
					fields := request.Request
					if fields["u"] != user {
						t.Error("wrong account")
					}
					response := map[string]any{"Status": map[string]any{"ec": 0}}
					switch fields["o"] {
					case "init":
						public, _ = fields["A2k"].([]byte)
						clientPublic := new(big.Int).SetBytes(public)
						u := new(big.Int).SetBytes(hash(pad(clientPublic), pad(serverPublic)))
						shared := new(big.Int).Exp(verifier, u, modulus)
						shared.Mul(shared, clientPublic).Mod(shared, modulus)
						shared.Exp(shared, serverSecret, modulus)
						key = hash(shared.Bytes())
						response["s"], response["B"], response["i"], response["sp"], response["c"] = salt, serverPublic.Bytes(), 100, protocol, "server-challenge"
					case "complete":
						if fields["c"] != "server-challenge" {
							t.Error("wrong challenge")
						}
						group, gen := hash(modulus.Bytes()), hash(pad(generator))
						for i := range group {
							group[i] ^= gen[i]
						}
						expected := hash(group, hash([]byte(user)), salt, public, serverPublic.Bytes(), key)
						proof, _ := fields["M1"].([]byte)
						if !hmac.Equal(proof, expected) {
							if !scenario.wrongPassword {
								t.Error("client password proof failed")
							}
							w.WriteHeader(403)
							return
						}
						if scenario.wrongPassword {
							t.Error("incorrect password produced a valid proof")
						}
						m2 := hash(public, expected, key)
						if scenario.corruptProof {
							m2[0] ^= 1
						}
						response["M2"] = m2
						plain, err := plist.Marshal(map[string]any{
							"status-code": 200, "adsid": "account-id", "DsPrsId": "12345",
							"t": map[string]any{"com.apple.gs.idms.pet": map[string]any{"token": "verified-token", "expiry": time.Now().Add(time.Hour).UnixMilli()}},
						}, plist.XMLFormat)
						if err != nil {
							t.Error(err)
							w.WriteHeader(500)
							return
						}
						derive := func(label string) []byte {
							h := hmac.New(sha256.New, key)
							_, _ = h.Write([]byte(label))
							return h.Sum(nil)
						}
						padding := aes.BlockSize - len(plain)%aes.BlockSize
						plain = append(plain, bytes.Repeat([]byte{byte(padding)}, padding)...)
						block, err := aes.NewCipher(derive("extra data key:"))
						if err != nil {
							t.Error(err)
							w.WriteHeader(500)
							return
						}
						encrypted := make([]byte, len(plain))
						cipher.NewCBCEncrypter(block, derive("extra data iv:")[:16]).CryptBlocks(encrypted, plain)
						response["spd"] = encrypted
					default:
						t.Error("unexpected operation")
					}
					output, err := plist.Marshal(map[string]any{"Response": response}, plist.XMLFormat)
					if err != nil {
						t.Error(err)
						w.WriteHeader(500)
						return
					}
					_, _ = w.Write(output)
				}))
				defer server.Close()
				headers := make(http.Header)
				for _, name := range []string{"X-Apple-I-MD", "X-Apple-I-MD-M", "X-Apple-I-MD-LU", "X-Apple-I-MD-RINFO", "X-Mme-Device-Id", "X-MMe-Client-Info", "X-Apple-I-Client-Time", "X-Apple-I-TimeZone", "X-Apple-Locale"} {
					headers.Set(name, "machine-value")
				}
				account, err := signInGrandSlam(context.Background(), server.Client(), server.URL, headers, user, scenario.password)
				if scenario.corruptProof || scenario.wrongPassword {
					if err == nil {
						t.Fatal("invalid server proof accepted")
					}
				} else if err != nil || account.PasswordToken != "verified-token" || account.DSID != "12345" {
					t.Fatalf("account exchange failed: %v", err)
				}
				if calls != 2 {
					t.Fatalf("got %d requests, want 2", calls)
				}
			})
		}
	}
}
