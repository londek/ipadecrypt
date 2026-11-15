package anisettecapture

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/ulikunitz/xz"
)

const (
	fridaVersion  = "17.26.2"
	fridaDEBURL   = "https://build.frida.re/pool/main/r/re.frida.server/re.frida.server_17.26.2_iphoneos-arm64.deb"
	fridaDEBSHA   = "9ba9a7454b1b51250b1f2d24d4071108e413c4cf7bc18badd54bf10e0c8095cc"
	fridaDEBLimit = 32 << 20
)

type fridaFile struct {
	member   string
	name     string
	sha256   string
	maxBytes int64
}

var fridaFiles = []fridaFile{
	{"./var/jb/usr/sbin/frida-server", "frida-server", "76c2cf03aa7d6b86986c9801cc9f60bd564e97f9e9f538a2a93ea296b947c044", 24 << 20},
	{"./var/jb/usr/lib/frida-1.0/frida-agent.dylib", "frida-agent.dylib", "1076efd67ad097240de30dc762113169fd8684fb1eb6df36043a848cef1ac32d", 80 << 20},
}

type fridaArtifacts struct {
	server string
	agent  string
}

func ensureFridaArtifacts(ctx context.Context) (fridaArtifacts, error) {
	cache, err := os.UserCacheDir()
	if err != nil {
		return fridaArtifacts{}, fmt.Errorf("locate Frida cache: %w", err)
	}

	directory := filepath.Join(cache, "ipadecrypt", "frida-"+fridaVersion)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fridaArtifacts{}, fmt.Errorf("create Frida cache: %w", err)
	}

	result := fridaArtifacts{
		server: filepath.Join(directory, "frida-server"),
		agent:  filepath.Join(directory, "frida-agent.dylib"),
	}
	allValid := true

	for _, item := range fridaFiles {
		valid, err := fileSHA256(filepath.Join(directory, item.name), item.sha256)
		if err != nil {
			return fridaArtifacts{}, err
		}

		allValid = allValid && valid
	}

	if allValid {
		return result, nil
	}

	archive := filepath.Join(directory, "frida.deb")

	valid, err := fileSHA256(archive, fridaDEBSHA)
	if err != nil {
		return fridaArtifacts{}, err
	}

	if !valid {
		if err := downloadFridaFile(ctx, fridaDEBURL, archive, fridaDEBSHA, fridaDEBLimit); err != nil {
			return fridaArtifacts{}, err
		}
	}

	if err := extractFrida(archive, directory); err != nil {
		return fridaArtifacts{}, err
	}

	return result, nil
}

func fileSHA256(path, expected string) (bool, error) {
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}

	if err != nil {
		return false, fmt.Errorf("open cached artifact %s: %w", path, err)
	}

	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return false, fmt.Errorf("hash cached artifact %s: %w", path, err)
	}

	return hex.EncodeToString(hash.Sum(nil)) == expected, nil
}

func downloadFridaFile(ctx context.Context, url, destination, expected string, limit int64) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("create Frida download request: %w", err)
	}

	request.Header.Set("User-Agent", "ipadecrypt Frida runtime downloader")

	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return fmt.Errorf("download Frida %s: %w", fridaVersion, err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("download Frida %s: unexpected HTTP status %s", fridaVersion, response.Status)
	}

	file, err := os.CreateTemp(filepath.Dir(destination), ".frida-download-*")
	if err != nil {
		return fmt.Errorf("create Frida download: %w", err)
	}

	temporary := file.Name()
	defer os.Remove(temporary)

	hash := sha256.New()

	written, copyErr := io.Copy(io.MultiWriter(file, hash), io.LimitReader(response.Body, limit+1))
	if closeErr := file.Close(); copyErr == nil {
		copyErr = closeErr
	}

	if copyErr != nil {
		return fmt.Errorf("save Frida download: %w", copyErr)
	}

	if written > limit {
		return fmt.Errorf("download Frida %s: package is too large", fridaVersion)
	}

	if actual := hex.EncodeToString(hash.Sum(nil)); actual != expected {
		return fmt.Errorf("download Frida %s: archive SHA-256 is %s, want %s", fridaVersion, actual, expected)
	}

	if err := os.Rename(temporary, destination); err != nil {
		return fmt.Errorf("cache Frida download: %w", err)
	}

	return nil
}

func extractFrida(archivePath, directory string) error {
	data, err := debMember(archivePath, "data.tar.xz")
	if err != nil {
		return err
	}

	reader, err := xz.NewReader(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("open Frida package: %w", err)
	}

	tarReader := tar.NewReader(reader)

	remaining := make(map[string]fridaFile, len(fridaFiles))
	for _, item := range fridaFiles {
		remaining[item.member] = item
	}

	for len(remaining) > 0 {
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}

		if err != nil {
			return fmt.Errorf("read Frida package: %w", err)
		}

		selected, wanted := remaining[header.Name]
		if !wanted {
			continue
		}

		if header.Typeflag != tar.TypeReg || header.Size > selected.maxBytes {
			return fmt.Errorf("invalid Frida package member %q", header.Name)
		}

		if err := writeArtifact(tarReader, filepath.Join(directory, selected.name), header.Size, selected); err != nil {
			return err
		}

		delete(remaining, header.Name)
	}

	if len(remaining) > 0 {
		return errors.New("the Frida package is missing its server or agent")
	}

	return nil
}

func writeArtifact(reader io.Reader, destination string, size int64, selected fridaFile) error {
	file, err := os.CreateTemp(filepath.Dir(destination), ".frida-artifact-*")
	if err != nil {
		return fmt.Errorf("create Frida artifact: %w", err)
	}

	temporary := file.Name()
	defer os.Remove(temporary)

	hash := sha256.New()

	written, copyErr := io.Copy(io.MultiWriter(file, hash), io.LimitReader(reader, selected.maxBytes+1))
	if closeErr := file.Close(); copyErr == nil {
		copyErr = closeErr
	}

	if copyErr != nil {
		return fmt.Errorf("extract Frida artifact: %w", copyErr)
	}

	if (size >= 0 && written != size) || hex.EncodeToString(hash.Sum(nil)) != selected.sha256 {
		return fmt.Errorf("the Frida artifact %s failed its integrity check", selected.name)
	}

	if err := os.Chmod(temporary, 0o700); err != nil {
		return fmt.Errorf("secure Frida artifact: %w", err)
	}

	if err := os.Rename(temporary, destination); err != nil {
		return fmt.Errorf("cache Frida artifact: %w", err)
	}

	return nil
}

func debMember(path, wanted string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open Frida package: %w", err)
	}
	defer file.Close()

	magic := make([]byte, 8)
	if _, err := io.ReadFull(file, magic); err != nil || string(magic) != "!<arch>\n" {
		return nil, errors.New("invalid Frida Debian package")
	}

	for {
		header := make([]byte, 60)
		if _, err := io.ReadFull(file, header); err != nil {
			return nil, errors.New("the Frida package has no data archive")
		}

		size, err := strconv.ParseInt(strings.TrimSpace(string(header[48:58])), 10, 64)
		if err != nil || size < 0 || size > fridaDEBLimit {
			return nil, errors.New("invalid Frida Debian package member")
		}

		name := strings.TrimSpace(string(header[0:16]))
		if name == wanted {
			data, err := io.ReadAll(io.LimitReader(file, size))
			if err != nil || int64(len(data)) != size {
				return nil, errors.New("truncated Frida package data archive")
			}

			return data, nil
		}

		if _, err := file.Seek(size+size%2, io.SeekCurrent); err != nil {
			return nil, fmt.Errorf("skip Frida package member: %w", err)
		}
	}
}
