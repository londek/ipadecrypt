package fairplay

import (
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"

	"github.com/londek/ipadecrypt/internal/pipeline"
)

// Credentials are one account's FairPlay credentials: Standard decodes regular
// App Store licenses and Arcade decodes Apple Arcade ones. Arcade may be nil.
type Credentials struct {
	Standard []byte
	Arcade   []byte
}

// ErrNoArcadeCredential reports an Apple Arcade app decrypted without the
// account's Arcade credential.
var ErrNoArcadeCredential = errors.New("this Apple Arcade app needs the account's Arcade credential")

// Summary reports what a Decrypt run processed.
type Summary struct {
	Binaries int
	Pages    int
}

// Decrypt reads the encrypted IPA at srcIPA, decrypts every FairPlay-protected
// binary it can (main app, frameworks, extensions) using the account
// credential matching each license, and writes a decrypted IPA to dst. Fat
// binaries come out thinned to one slice (see armEncryptionInfo). SC_Info
// and iTunesMetadata are stripped from the output, and Watch apps too unless
// keepWatch is set (see pipeline.Assemble); stripped Watch binaries are not
// decrypted. With skipAppex, .appex binaries are left out of the decrypt plan.
func Decrypt(srcIPA string, dst io.Writer, credentials Credentials, skipAppex, keepWatch bool) (Summary, error) {
	if len(credentials.Standard) != CredentialSize || (credentials.Arcade != nil && len(credentials.Arcade) != CredentialSize) {
		return Summary{}, errors.New("credential must contain exactly 16 bytes")
	}

	zr, err := zip.OpenReader(srcIPA)
	if err != nil {
		return Summary{}, fmt.Errorf("open ipa %s: %w", srcIPA, err)
	}

	defer zr.Close()

	members := make(map[string]*zip.File, len(zr.File))
	nameSet := make(map[string]bool, len(zr.File))

	for _, f := range zr.File {
		if _, dup := members[f.Name]; dup {
			return Summary{}, fmt.Errorf("input zip has duplicate member %q", f.Name)
		}

		members[f.Name] = f
		nameSet[f.Name] = true
	}

	entries, err := planEntries(nameSet)
	if err != nil {
		return Summary{}, err
	}

	replacements := make(map[string][]byte)
	totalPages := 0

	for _, e := range entries {
		if skipAppex && strings.Contains(e.binaryPath, ".appex/") {
			continue
		}

		// pipeline.Assemble drops Watch apps from the output unless keepWatch.
		if !keepWatch && strings.Contains(e.binaryPath, "/Watch/") {
			continue
		}

		source, err := readMember(members[e.binaryPath])
		if err != nil {
			return Summary{}, err
		}

		if _, err := armEncryptionInfo(source); err != nil {
			if errors.Is(err, errNotEncrypted) {
				continue
			}

			return Summary{}, fmt.Errorf("%s: %w", e.binaryPath, err)
		}

		sinfPath := e.sinfPath
		if !nameSet[sinfPath] {
			fallback := enclosingAppSinf(nameSet, e.bundle)
			if fallback == "" {
				return Summary{}, fmt.Errorf("SUPF/SUPP lacks binary/SINF: %s", e.supfPath)
			}

			sinfPath = fallback
		}

		sinf, err := readMember(members[sinfPath])
		if err != nil {
			return Summary{}, err
		}

		supf, err := readMember(members[e.supfPath])
		if err != nil {
			return Summary{}, err
		}

		credential := credentials.Standard
		if isArcadeSinf(sinf) {
			if credentials.Arcade == nil {
				return Summary{}, ErrNoArcadeCredential
			}

			credential = credentials.Arcade
		}

		result, pages, err := decryptBinary(source, sinf, supf, credential)
		if err != nil {
			if errors.Is(err, errNotEncrypted) {
				continue
			}

			return Summary{}, fmt.Errorf("%s: %w", e.binaryPath, err)
		}

		replacements[e.binaryPath] = result
		totalPages += pages
	}

	if len(replacements) == 0 {
		return Summary{}, errors.New("no encrypted binaries with supported SINF/SUPF/SUPP")
	}

	err = pipeline.Assemble(srcIPA, dst, keepWatch, func(write pipeline.SubstituteWriter) error {
		for name, data := range replacements {
			if err := write(name, bytes.NewReader(data)); err != nil {
				return err
			}
		}

		return nil
	})
	if err != nil {
		return Summary{}, err
	}

	return Summary{Binaries: len(replacements), Pages: totalPages}, nil
}

type planEntry struct {
	binaryPath string
	supfPath   string
	sinfPath   string
	bundle     string
}

// pageKeySuffixes lists the page-key file suffixes, best first: SUPF
// (f-class: .supf/.v5.supf) and SUPP (p-class: .supp/.v4.supp). Newer
// generations (.v5.supf, .v4.supp) rank ahead of legacy ones (.supf, .supp),
// and SUPF ahead of SUPP within each.
var pageKeySuffixes = []string{".v5.supf", ".v4.supp", ".supf", ".supp"}

// pageKeySuffix returns name's rank and suffix in pageKeySuffixes, or -1.
func pageKeySuffix(name string) (int, string) {
	for i, s := range pageKeySuffixes {
		if strings.HasSuffix(name, s) {
			return i, s
		}
	}

	return -1, ""
}

// planEntries maps every SUPF/SUPP in the IPA to its binary and SINF. Mirrors
// decrypt.py's supf_paths + plan builder.
func planEntries(names map[string]bool) ([]planEntry, error) {
	var entries []planEntry

	for _, supfPath := range supfPaths(names) {
		idx := strings.LastIndex(supfPath, "/SC_Info/")
		if idx < 0 {
			return nil, fmt.Errorf("SUPF/SUPP outside SC_Info: %s", supfPath)
		}

		bundle := supfPath[:idx]
		filename := supfPath[idx+len("/SC_Info/"):]

		_, suffix := pageKeySuffix(filename)
		stem := strings.TrimSuffix(filename, suffix)
		binaryPath := bundle + "/" + stem

		sinfPath := bundle + "/SC_Info/" + stem + ".sinf"
		if suffix == ".v5.supf" || suffix == ".v4.supp" {
			if v4 := bundle + "/SC_Info/" + stem + ".v4.sinf"; names[v4] {
				sinfPath = v4
			}
		}

		if !names[binaryPath] {
			return nil, fmt.Errorf("SUPF/SUPP lacks binary/SINF: %s", supfPath)
		}

		entries = append(entries, planEntry{binaryPath: binaryPath, supfPath: supfPath, sinfPath: sinfPath, bundle: bundle})
	}

	return entries, nil
}

// supfPaths keeps, per binary stem, the SUPF/SUPP whose suffix ranks best in
// pageKeySuffixes.
func supfPaths(names map[string]bool) []string {
	best := make(map[string]string)

	for name := range names {
		rank, suffix := pageKeySuffix(name)
		if rank < 0 {
			continue
		}

		stem := strings.TrimSuffix(name, suffix)

		cur, ok := best[stem]
		if curRank, _ := pageKeySuffix(cur); !ok || rank < curRank {
			best[stem] = name
		}
	}

	out := make([]string, 0, len(best))
	for _, name := range best {
		out = append(out, name)
	}

	sort.Strings(out)

	return out
}

// enclosingAppSinf finds a usable SINF in the nearest enclosing .app bundle,
// used when an extension or framework has no SINF of its own. Mirrors
// decrypt.py enclosing_app_sinf.
func enclosingAppSinf(names map[string]bool, bundle string) string {
	parts := strings.Split(bundle, "/")

	for i := len(parts); i > 0; i-- {
		prefix := strings.Join(parts[:i], "/")
		if !strings.HasSuffix(prefix, ".app") {
			continue
		}

		scInfo := prefix + "/SC_Info/"

		var sinfs []string

		for name := range names {
			if strings.HasPrefix(name, scInfo) && strings.HasSuffix(name, ".sinf") &&
				strings.Count(name, "/") == strings.Count(scInfo, "/") {
				sinfs = append(sinfs, name)
			}
		}

		if len(sinfs) == 0 {
			continue
		}

		sort.Strings(sinfs)

		base := path.Base(prefix)
		stem := strings.TrimSuffix(base, path.Ext(base))

		for _, suffix := range []string{".sinf", ".v4.sinf"} {
			preferred := scInfo + stem + suffix
			if containsString(sinfs, preferred) {
				return preferred
			}
		}

		for _, name := range sinfs {
			if !strings.HasSuffix(name, ".v4.sinf") {
				return name
			}
		}

		return sinfs[0]
	}

	return ""
}

func containsString(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}

	return false
}

func readMember(f *zip.File) ([]byte, error) {
	if f == nil {
		return nil, errors.New("missing zip member")
	}

	rc, err := f.Open()
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", f.Name, err)
	}

	defer rc.Close()

	data, err := io.ReadAll(rc)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", f.Name, err)
	}

	return data, nil
}
