// Package maccredential recovers a credential from Mac FairPlay enrollment state.
// It never loads the legacy credential cache or an Apple account password/token.
package maccredential

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/DrWhax/unfairplay/pkg/setup"
	"github.com/londek/ipadecrypt/internal/fairplay"
	"github.com/londek/ipadecrypt/internal/macho"
	"github.com/londek/ipadecrypt/internal/macstore"
	"github.com/londek/ipadecrypt/internal/pipeline"
	"howett.net/plist"
)

const SourceRevision = "c1753f4076fceccbf3e97625ea88c0609869e978"

type Options struct {
	IPA, SIDB, Hardware, Output string
	Progress                    func(string)
	FreshEnrollment             bool
}
type Report struct {
	Source            string    `json:"source"`
	Revision          string    `json:"recoveryRevision"`
	CreatedAt         time.Time `json:"createdAt"`
	IPAHash           string    `json:"ipaSHA256"`
	SIDBHash          string    `json:"sidbSHA256"`
	ModelHash         string    `json:"modelSHA256"`
	CredentialHash    string    `json:"credentialSHA256"`
	PlaintextVerified bool      `json:"plaintextVerified"`
	EncryptedImages   int       `json:"encryptedImages"`
	DecryptedPages    int       `json:"decryptedPages"`
	MachOScanned      int       `json:"machOScanned"`
	MachOCompared     int       `json:"machOCompared"`
	OldCredentialRead bool      `json:"oldCredentialRead"`
}

func directCredential(pack []byte) ([]byte, error) {
	const size = 4184
	if len(pack) != size || string(pack[:8]) != "FPSENR2\x00" || binary.LittleEndian.Uint32(pack[8:12]) != 2 || binary.LittleEndian.Uint32(pack[12:16]) != size {
		return nil, errors.New("only a direct version-2 enrollment model can yield this credential")
	}

	for _, b := range pack[72:88] {
		if b != 0 {
			return nil, errors.New("model has nonzero whitening; refusing key-only conversion")
		}
	}

	for i, b := range pack[88:] {
		if b != byte(i%256) {
			return nil, errors.New("model is not the direct codec")
		}
	}

	credential := make([]byte, 16)
	for i, b := range pack[56:72] {
		credential[i] = b ^ 0x30
	}

	return credential, nil
}
func zipRead(f *zip.File) ([]byte, error) {
	if f.UncompressedSize64 > 16<<20 {
		return nil, errors.New("license/metadata exceeds size limit")
	}

	r, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer r.Close()

	b, err := io.ReadAll(io.LimitReader(r, 16<<20+1))
	if err != nil {
		return nil, err
	}

	if len(b) > 16<<20 {
		return nil, errors.New("license/metadata exceeds size limit")
	}

	return b, nil
}
func readBounded(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	st, err := f.Stat()
	if err != nil {
		return nil, err
	}

	if !st.Mode().IsRegular() || st.Size() > limit {
		return nil, errors.New("recovery input is not a bounded regular file")
	}

	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}

	if int64(len(b)) > limit {
		return nil, errors.New("recovery input exceeds size limit")
	}

	return b, nil
}

func Recover(ctx context.Context, o Options) (Report, error) {
	var report Report
	if o.IPA == "" || o.SIDB == "" || o.Output == "" {
		return report, errors.New("IPA, SIDB and output paths are required")
	}

	for _, p := range []string{o.Output, o.Output + ".json"} {
		if _, err := os.Lstat(p); err == nil {
			return report, errors.New("credential output or report already exists")
		} else if !errors.Is(err, os.ErrNotExist) {
			return report, err
		}
	}

	work, err := os.MkdirTemp(filepath.Dir(o.Output), ".mac-credential-*")
	if err != nil {
		return report, err
	}
	defer os.RemoveAll(work)

	progress := func(s string) {
		if o.Progress != nil {
			o.Progress(s)
		}
	}
	// Snapshot inputs; subsequent recovery cannot accidentally mix changing state.
	sidb, err := readBounded(o.SIDB, 64<<20)
	if err != nil {
		return report, fmt.Errorf("read Mac SIDB: %w", err)
	}
	defer clear(sidb)

	if len(sidb) == 0 || len(sidb) > 64<<20 {
		return report, errors.New("invalid SIDB size")
	}

	sidbPath := filepath.Join(work, "SC Info.sidb")
	if err = macstore.WritePrivate(sidbPath, sidb); err != nil {
		return report, err
	}

	var hardware []byte
	if o.Hardware != "" {
		hardware, err = readBounded(o.Hardware, 6)
	} else {
		hardware, err = localHardwareMAC(ctx, "en0")
	}

	if err != nil {
		return report, err
	}

	defer clear(hardware)

	if len(hardware) != 6 {
		return report, errors.New("IOMACAddress must contain six raw bytes")
	}

	hardwarePath := filepath.Join(work, "iomac.bin")
	if err = macstore.WritePrivate(hardwarePath, hardware); err != nil {
		return report, err
	}

	capture, err := prepareCapture(o.IPA, sidbPath, hardwarePath, filepath.Join(work, "capture"))
	if err != nil {
		return report, err
	}
	// All later checks use the same private IPA snapshot that recovery validated.
	o.IPA = filepath.Join(capture, "reference.ipa")

	recovered, err := setup.Recover(ctx, setup.RecoverOptions{Capture: capture, Output: filepath.Join(work, "recovered"), Progress: progress})
	if err != nil {
		if ctx.Err() != nil {
			return report, ctx.Err()
		}

		return report, errors.New("the Mac enrollment recovery failed for this exact IPA selector; no credential was saved")
	}

	model, err := readBounded(recovered.ModelPath, 4184)
	if err != nil {
		return report, err
	}
	defer clear(model)

	credential, err := directCredential(model)
	if err != nil {
		return report, err
	}
	defer clear(credential)
	// setup.Recover validates the full IPA before exposing the model. Require
	// complete hash coverage, then independently verify our credential output.
	verified, _ := recovered.Summary["plaintext_verified"].(bool)
	images, _ := recovered.Summary["encrypted_images"].(int)

	pages, _ := recovered.Summary["decrypted_pages"].(int)
	if !verified || images == 0 || pages == 0 {
		return report, errors.New("complete plaintext-hash coverage is required before saving a credential")
	}

	if err = ctx.Err(); err != nil {
		return report, err
	}

	progress("Verifying the 16-byte credential with ipadecrypt's offline pipeline")

	ownPath := filepath.Join(work, "ours.ipa")

	out, err := os.OpenFile(ownPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return report, err
	}

	_, decryptErr := fairplay.Decrypt(o.IPA, out, fairplay.Credentials{Standard: credential}, false, false)
	if err = errors.Join(decryptErr, out.Close()); err != nil {
		return report, errors.New("credential failed ipadecrypt offline decryption; not saved")
	}

	verification, err := pipeline.Verify(ownPath, o.IPA, false)
	if err != nil {
		return report, err
	}

	if !verification.OK() || verification.Scanned == 0 || verification.Compared != verification.Scanned || len(verification.Skipped) > 0 || len(verification.Missing) > 0 {
		return report, errors.New("credential failed Mach-O source comparison; not saved")
	}
	// The independently validated plaintext and our plaintext must be identical
	// for every Mach-O; source-only comparison cannot establish encrypted bytes.
	if err = comparePlaintext(ownPath, filepath.Join(work, "recovered", "App.decrypted.ipa")); err != nil {
		return report, err
	}

	ipaHash, err := macstore.FileHash(o.IPA)
	if err != nil {
		return report, err
	}

	report = Report{Source: "native Mac SIDB + IOMACAddress + target IPA", Revision: SourceRevision, CreatedAt: time.Now().UTC(), IPAHash: ipaHash, SIDBHash: fmt.Sprintf("%x", sha256.Sum256(sidb)), ModelHash: fmt.Sprintf("%x", sha256.Sum256(model)), CredentialHash: fmt.Sprintf("%x", sha256.Sum256(credential)), PlaintextVerified: true, EncryptedImages: images, DecryptedPages: pages, MachOScanned: verification.Scanned, MachOCompared: verification.Compared}
	if o.FreshEnrollment {
		report.Source = "fresh emulated Mac enrollment + Store hardware identity + account-personalized IPA"
	}

	candidate := filepath.Join(work, "credential.bin")
	if err = macstore.WritePrivate(candidate, credential); err != nil {
		return report, err
	}

	reportPath := filepath.Join(work, "report.json")
	if err = macstore.WriteJSON(reportPath, report); err != nil {
		return report, err
	}

	if err = ctx.Err(); err != nil {
		return report, err
	}

	if err = os.Link(reportPath, o.Output+".json"); err != nil {
		return report, err
	}

	if err = os.Link(candidate, o.Output); err != nil {
		os.Remove(o.Output + ".json")
		return report, err
	}

	return report, nil
}
func comparePlaintext(ours, other string) error {
	a, err := zip.OpenReader(ours)
	if err != nil {
		return err
	}
	defer a.Close()

	b, err := zip.OpenReader(other)
	if err != nil {
		return err
	}
	defer b.Close()

	entries := map[string]*zip.File{}
	for _, f := range b.File {
		entries[f.Name] = f
	}

	for _, f := range a.File {
		if f.FileInfo().IsDir() {
			continue
		}

		g := entries[f.Name]
		if g == nil {
			return errors.New("plaintext verification output member missing")
		}
		// Resources must match in full; thinned Mach-O files must match their
		// complete architecture slice in the independent output.
		ar, e := f.Open()
		if e != nil {
			return e
		}

		br, e := g.Open()
		if e != nil {
			ar.Close()
			return e
		}

		match, compareErr := plaintextMatches(ar, br)
		if err := errors.Join(compareErr, ar.Close(), br.Close()); err != nil {
			return err
		}

		if !match {
			return errors.New("independent plaintext outputs differ; credential was not saved")
		}
	}

	return nil
}

// plaintextMatches accounts for the offline decryptor thinning fat Mach-O
// files, while still checking every byte of the selected plaintext slice.
func plaintextMatches(ours, reference io.Reader) (bool, error) {
	a, b := bufio.NewReader(ours), bufio.NewReader(reference)
	ahdr, _ := a.Peek(16)
	bhdr, _ := b.Peek(4)

	var expected io.Reader = b

	if macho.IsMagic(ahdr) && !macho.IsFat(ahdr) && macho.IsFat(bhdr) {
		slices, err := macho.FatSlices(ahdr)
		if err != nil {
			return false, err
		}

		data, err := io.ReadAll(b)
		if err != nil {
			return false, err
		}

		selected, err := macho.PickSlice(data, slices[0].Cpu, slices[0].Sub)
		if err != nil {
			return false, err
		}

		expected = bytes.NewReader(selected)
	}

	ah, bh := sha256.New(), sha256.New()
	_, ae := io.Copy(ah, a)

	_, be := io.Copy(bh, expected)
	if err := errors.Join(ae, be); err != nil {
		return false, err
	}

	return bytes.Equal(ah.Sum(nil), bh.Sum(nil)), nil
}

// MatchAccount binds credential recovery to the account of the downloaded IPA. Actual
// credential validity is established separately by SINF and full IPA checks.
func MatchAccount(ipa, email string) error {
	if email == "" {
		return errors.New("account email is missing")
	}

	r, err := zip.OpenReader(ipa)
	if err != nil {
		return err
	}
	defer r.Close()

	count := 0
	matched := false

	for _, f := range r.File {
		if f.Name != "iTunesMetadata.plist" {
			continue
		}

		count++

		b, e := zipRead(f)
		if e != nil {
			return e
		}

		var meta struct {
			AppleID string `plist:"apple-id"`
		}
		if _, e = plist.Unmarshal(b, &meta); e != nil {
			return e
		}

		matched = strings.EqualFold(meta.AppleID, email)
	}

	if count != 1 || !matched {
		return errors.New("IPA account metadata does not match this Mac Store session; choose an IPA owned by the signed-in account")
	}

	return nil
}
