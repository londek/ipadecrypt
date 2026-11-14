package maccredential

import (
	"archive/zip"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	upstream "github.com/DrWhax/unfairplay/pkg/fairplay"
	"github.com/londek/ipadecrypt/internal/macstore"
	"howett.net/plist"
)

// prepareCapture adapts our explicit inputs to upstream's public capture format.
// The executable and licenses come from the reference IPA, not an installed app.
// No daemon binary, invented OS identity, or additional system state is needed.
func prepareCapture(ipa, sidb, hardware, directory string) (string, error) {
	if err := os.Mkdir(directory, 0700); err != nil {
		return "", err
	}

	m := upstream.EnrollmentCaptureManifest{Schema: upstream.EnrollmentCaptureSchema, CreatedAt: time.Now().UTC().Format(time.RFC3339)}
	add := func(name string, reader io.Reader) (upstream.EnrollmentCaptureFile, error) {
		var file upstream.EnrollmentCaptureFile

		path := filepath.Join(directory, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			return file, err
		}

		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return file, err
		}

		n, copyErr := io.Copy(f, reader)
		if err = errors.Join(copyErr, f.Close()); err != nil {
			return file, err
		}

		hash, err := macstore.FileHash(path)
		if err != nil {
			return file, err
		}

		file = upstream.EnrollmentCaptureFile{Path: name, Bytes: n, SHA256: hash, Mode: "0600"}
		m.Files = append(m.Files, file)

		return file, nil
	}
	copyFile := func(name, source string) (upstream.EnrollmentCaptureFile, error) {
		f, err := os.Open(source)
		if err != nil {
			return upstream.EnrollmentCaptureFile{}, err
		}
		defer f.Close()

		return add(name, f)
	}

	ref, err := copyFile("reference.ipa", ipa)
	if err != nil {
		return "", err
	}

	m.IPA = &ref

	r, err := zip.OpenReader(filepath.Join(directory, ref.Path))
	if err != nil {
		return "", err
	}
	defer r.Close()

	files := map[string]*zip.File{}

	var root string

	for _, f := range r.File {
		if files[f.Name] != nil {
			return "", errors.New("duplicate IPA member")
		}

		files[f.Name] = f

		parts := strings.Split(f.Name, "/")
		if len(parts) != 3 || parts[0] != "Payload" || !strings.HasSuffix(parts[1], ".app") || parts[2] != "Info.plist" {
			continue
		}

		if root != "" {
			return "", errors.New("IPA has multiple root apps")
		}

		b, err := zipRead(f)
		if err != nil {
			return "", err
		}

		var info struct {
			Executable string `plist:"CFBundleExecutable"`
			Bundle     string `plist:"CFBundleIdentifier"`
		}
		if _, err = plist.Unmarshal(b, &info); err != nil {
			return "", err
		}

		root = strings.Join(parts[:2], "/")
		m.App = upstream.EnrollmentCaptureApp{Executable: info.Executable, BundleIdentifier: info.Bundle, IPAMemberRoot: root}
	}

	exe := m.App.Executable
	if root == "" || exe == "" || exe == "." || exe == ".." || strings.ContainsAny(exe, "/\\") {
		return "", errors.New("invalid root app executable")
	}

	copyMember := func(name, member string, limit uint64) error {
		f := files[member]
		if f == nil || f.UncompressedSize64 > limit {
			return errors.New("missing or oversized recovery IPA member")
		}

		stream, err := f.Open()
		if err != nil {
			return err
		}
		defer stream.Close()

		file, err := add(name, io.LimitReader(stream, int64(limit)+1))
		if err == nil && file.Bytes > int64(limit) {
			return errors.New("recovery IPA member exceeds size limit")
		}

		return err
	}
	if err = copyMember("app/executable", root+"/"+exe, 512<<20); err != nil {
		return "", err
	}

	m.App.ExecutablePath = root + "/" + exe

	m.App.SINFPath = "app/SC_Info/" + exe + ".sinf"
	if err = copyMember(m.App.SINFPath, root+"/SC_Info/"+exe+".sinf", 16<<20); err != nil {
		return "", err
	}

	sinf, err := os.ReadFile(filepath.Join(directory, m.App.SINFPath))
	if err != nil {
		return "", err
	}

	m.App.Selector, err = upstream.ParseSINFSelector(sinf)
	clear(sinf)

	if err != nil {
		return "", err
	}

	m.App.SelectorID = m.App.Selector.Identifier()
	aux := 0

	for _, suffix := range []string{".supf", ".v5.supf", ".supp", ".v4.supp"} {
		member := root + "/SC_Info/" + exe + suffix
		if files[member] == nil {
			continue
		}

		if err = copyMember("app/SC_Info/"+exe+suffix, member, 16<<20); err != nil {
			return "", err
		}

		aux++
	}

	if aux == 0 {
		return "", errors.New("root app SUPF/SUPP is required")
	}

	if _, err = copyFile("state/fpsd-sc-info/SC Info.sidb", sidb); err != nil {
		return "", err
	}

	m.HardwareMAC, err = copyFile("hardware/iomac.bin", hardware)
	if err != nil {
		return "", err
	}

	if err = macstore.WriteJSON(filepath.Join(directory, "manifest.json"), m); err != nil {
		return "", err
	}

	return directory, nil
}
