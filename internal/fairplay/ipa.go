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

// Summary reports what a Decrypt run processed.
type Summary struct {
	Binaries int
	Pages    int
}

// Decrypt reads the encrypted IPA at srcIPA, decrypts every FairPlay-protected
// arm64 binary it can (main app, frameworks, extensions) using the 16-byte
// account credential, and writes a decrypted IPA to dst. SC_Info, Watch apps
// and iTunesMetadata are stripped from the output (see pipeline.Assemble).
// With skipAppex, .appex binaries are left out of the decrypt plan.
func Decrypt(srcIPA string, dst io.Writer, credential []byte, skipAppex bool) (Summary, error) {
	if len(credential) != 16 {
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

		source, err := readMember(members[e.binaryPath])
		if err != nil {
			return Summary{}, err
		}

		if _, err := arm64EncryptionInfo(source); err != nil {
			if errors.Is(err, errCryptidZero) {
				continue
			}

			return Summary{}, fmt.Errorf("%s: %w", e.binaryPath, err)
		}

		sinfPath := e.sinfPath
		if !nameSet[sinfPath] {
			fallback := enclosingAppSinf(nameSet, e.bundle)
			if fallback == "" {
				return Summary{}, fmt.Errorf("SUPF lacks binary/SINF: %s", e.supfPath)
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

		result, pages, err := decryptBinary(source, sinf, supf, credential)
		if err != nil {
			if errors.Is(err, errCryptidZero) {
				continue
			}

			return Summary{}, fmt.Errorf("%s: %w", e.binaryPath, err)
		}

		replacements[e.binaryPath] = result
		totalPages += pages
	}

	if len(replacements) == 0 {
		return Summary{}, errors.New("no encrypted arm64 binaries with supported SINF/SUPF")
	}

	err = pipeline.Assemble(srcIPA, dst, func(write pipeline.SubstituteWriter) error {
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

// planEntries maps every SUPF record in the IPA to its binary and SINF,
// preferring v5 records. Mirrors decrypt.py's supf_paths + plan builder.
func planEntries(names map[string]bool) ([]planEntry, error) {
	var entries []planEntry

	for _, supfPath := range supfPaths(names) {
		idx := strings.LastIndex(supfPath, "/SC_Info/")
		if idx < 0 {
			return nil, fmt.Errorf("SUPF outside SC_Info: %s", supfPath)
		}

		bundle := supfPath[:idx]
		filename := supfPath[idx+len("/SC_Info/"):]

		isV5 := strings.HasSuffix(filename, ".v5.supf")

		var stem string
		if isV5 {
			stem = strings.TrimSuffix(filename, ".v5.supf")
		} else {
			stem = strings.TrimSuffix(filename, ".supf")
		}

		binaryPath := bundle + "/" + stem

		sinfName := stem + ".sinf"
		if isV5 {
			sinfName = stem + ".v4.sinf"
		}

		sinfPath := bundle + "/SC_Info/" + sinfName
		if !names[sinfPath] && isV5 {
			sinfPath = bundle + "/SC_Info/" + stem + ".sinf"
		}

		if !names[binaryPath] {
			return nil, fmt.Errorf("SUPF lacks binary/SINF: %s", supfPath)
		}

		entries = append(entries, planEntry{binaryPath: binaryPath, supfPath: supfPath, sinfPath: sinfPath, bundle: bundle})
	}

	return entries, nil
}

func supfPaths(names map[string]bool) []string {
	sorted := make([]string, 0, len(names))
	for n := range names {
		sorted = append(sorted, n)
	}

	sort.Strings(sorted)

	byBinary := make(map[string]string)

	for _, name := range sorted {
		switch {
		case strings.HasSuffix(name, ".v5.supf"):
			byBinary[strings.TrimSuffix(name, ".v5.supf")] = name
		case strings.HasSuffix(name, ".supf"):
			key := strings.TrimSuffix(name, ".supf")
			if _, ok := byBinary[key]; !ok {
				byBinary[key] = name
			}
		}
	}

	out := make([]string, 0, len(byBinary))
	for _, v := range byBinary {
		out = append(out, v)
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
