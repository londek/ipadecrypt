package pipeline

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"howett.net/plist"
)

func PatchMinOS(src, dst, target string) (bool, string, error) {
	r, err := zip.OpenReader(src)
	if err != nil {
		return false, "", fmt.Errorf("open %s: %w", src, err)
	}
	defer r.Close()

	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return false, "", fmt.Errorf("mkdir %s: %w", filepath.Dir(dst), err)
	}

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return false, "", fmt.Errorf("open dst %s: %w", dst, err)
	}

	defer out.Close()

	w := zip.NewWriter(out)

	defer w.Close()

	patched := false
	previous := ""
	for _, f := range r.File {
		if isMainAppInfoPlist(f.Name) {
			changed, prev, err := rewriteInfoPlist(f, target, w)
			if err != nil {
				return patched, previous, fmt.Errorf("rewrite %s: %w", f.Name, err)
			}

			if changed {
				patched = true
				previous = prev
			}

			continue
		}

		if err := copyEntry(f, w); err != nil {
			return patched, previous, fmt.Errorf("copy %s: %w", f.Name, err)
		}
	}

	return patched, previous, nil
}

func isMainAppInfoPlist(name string) bool {
	parts := strings.Split(name, "/")
	return len(parts) == 3 &&
		parts[0] == "Payload" &&
		strings.HasSuffix(parts[1], ".app") &&
		parts[2] == "Info.plist"
}

func copyEntry(f *zip.File, w *zip.Writer) error {
	rc, err := f.Open()
	if err != nil {
		return err
	}
	defer rc.Close()

	hdr := f.FileHeader

	dst, err := w.CreateHeader(&hdr)
	if err != nil {
		return err
	}

	_, err = io.Copy(dst, rc)

	return err
}

func rewriteInfoPlist(f *zip.File, target string, w *zip.Writer) (bool, string, error) {
	rc, err := f.Open()
	if err != nil {
		return false, "", err
	}

	data, err := io.ReadAll(rc)
	rc.Close()
	if err != nil {
		return false, "", err
	}

	var m map[string]interface{}
	format, err := plist.Unmarshal(data, &m)
	if err != nil {
		// Not a parseable plist at this path; pass through unchanged.
		return false, "", writeBytes(f, w, data)
	}

	current, _ := m["MinimumOSVersion"].(string)
	if current == "" || cmpVer(current, target) <= 0 {
		return false, "", writeBytes(f, w, data)
	}

	m["MinimumOSVersion"] = target
	newData, err := plist.Marshal(m, format)
	if err != nil {
		return false, "", fmt.Errorf("marshal plist: %w", err)
	}

	return true, current, writeBytes(f, w, newData)
}

func writeBytes(f *zip.File, w *zip.Writer, data []byte) error {
	hdr := f.FileHeader

	dst, err := w.CreateHeader(&hdr)
	if err != nil {
		return err
	}

	_, err = io.Copy(dst, bytes.NewReader(data))

	return err
}

// MainExecSHA256 reads the main executable out of the IPA (resolved via
// CFBundleExecutable in the top-level Info.plist) and returns its name and
// lowercase-hex SHA-256. Used to verify that an already-installed bundle on
// the device still matches the IPA we'd otherwise upload.
func MainExecSHA256(ipaPath string) (execName, hexSum string, err error) {
	r, err := zip.OpenReader(ipaPath)
	if err != nil {
		return "", "", fmt.Errorf("open %s: %w", ipaPath, err)
	}
	defer r.Close()

	var appDir string

	for _, f := range r.File {
		if !isMainAppInfoPlist(f.Name) {
			continue
		}

		rc, err := f.Open()
		if err != nil {
			return "", "", err
		}

		data, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			return "", "", err
		}

		var m map[string]any
		if _, err := plist.Unmarshal(data, &m); err != nil {
			return "", "", fmt.Errorf("parse Info.plist: %w", err)
		}

		execName, _ = m["CFBundleExecutable"].(string)
		parts := strings.SplitN(f.Name, "/", 3)
		appDir = parts[0] + "/" + parts[1]

		break
	}

	if execName == "" {
		return "", "", fmt.Errorf("CFBundleExecutable not found in %s", ipaPath)
	}

	execPath := appDir + "/" + execName

	for _, f := range r.File {
		if f.Name != execPath {
			continue
		}

		rc, err := f.Open()
		if err != nil {
			return "", "", err
		}

		h := sha256.New()
		if _, err := io.Copy(h, rc); err != nil {
			rc.Close()
			return "", "", err
		}

		rc.Close()

		return execName, hex.EncodeToString(h.Sum(nil)), nil
	}

	return "", "", fmt.Errorf("main exec %s not found in IPA", execPath)
}

// AppInfo reads BundleID + version from Payload/<Name>.app/Info.plist.
func AppInfo(ipaPath string) (bundleID, version string, err error) {
	r, err := zip.OpenReader(ipaPath)
	if err != nil {
		return "", "", fmt.Errorf("open %s: %w", ipaPath, err)
	}

	defer r.Close()

	for _, f := range r.File {
		if !isMainAppInfoPlist(f.Name) {
			continue
		}

		rc, err := f.Open()
		if err != nil {
			return "", "", err
		}

		data, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			return "", "", err
		}

		var m map[string]any
		if _, err := plist.Unmarshal(data, &m); err != nil {
			return "", "", fmt.Errorf("parse Info.plist: %w", err)
		}

		version, _ = m["CFBundleShortVersionString"].(string)
		if version == "" {
			version, _ = m["CFBundleVersion"].(string)
		}

		bundleID, _ = m["CFBundleIdentifier"].(string)
		if bundleID == "" {
			return "", "", fmt.Errorf("Info.plist missing CFBundleIdentifier")
		}

		return bundleID, version, nil
	}

	return "", "", fmt.Errorf("no Payload/*.app/Info.plist in %s", ipaPath)
}

func AppDirName(ipaPath string) (string, error) {
	r, err := zip.OpenReader(ipaPath)
	if err != nil {
		return "", fmt.Errorf("open %s: %w", ipaPath, err)
	}
	defer r.Close()
	for _, f := range r.File {
		parts := strings.Split(f.Name, "/")
		if len(parts) >= 2 && parts[0] == "Payload" && strings.HasSuffix(parts[1], ".app") {
			return parts[1], nil
		}
	}
	return "", fmt.Errorf("no Payload/*.app/ directory in %s", ipaPath)
}

// rewriteIPA rebuilds ipaPath in place, dropping entries for which skip returns
// true. It returns the number of entries dropped; when zero, the source file
// is left untouched and no rename happens.
func rewriteIPA(ipaPath string, skip func(name string) bool) (int, error) {
	r, err := zip.OpenReader(ipaPath)
	if err != nil {
		return 0, fmt.Errorf("open %s: %w", ipaPath, err)
	}
	defer r.Close()

	tmp := ipaPath + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return 0, fmt.Errorf("open %s: %w", tmp, err)
	}
	w := zip.NewWriter(out)

	cleanup := func() { _ = os.Remove(tmp) }

	removed := 0
	for _, f := range r.File {
		if skip(f.Name) {
			removed++
			continue
		}

		if err := copyEntry(f, w); err != nil {
			w.Close()
			out.Close()
			cleanup()
			return 0, fmt.Errorf("copy %s: %w", f.Name, err)
		}
	}

	if err := w.Close(); err != nil {
		out.Close()
		cleanup()
		return 0, fmt.Errorf("close zip: %w", err)
	}

	if err := out.Close(); err != nil {
		cleanup()
		return 0, fmt.Errorf("close file: %w", err)
	}

	if removed == 0 {
		cleanup()
		return 0, nil
	}

	if err := os.Rename(tmp, ipaPath); err != nil {
		return 0, fmt.Errorf("rename: %w", err)
	}

	return removed, nil
}

func StripMetadata(ipaPath string) (bool, error) {
	n, err := rewriteIPA(ipaPath, func(name string) bool {
		return strings.EqualFold(filepath.Base(name), "iTunesMetadata.plist")
	})
	return n > 0, err
}

func StripWatch(ipaPath string) (int, error) {
	return rewriteIPA(ipaPath, isWatchPath)
}

func isWatchPath(name string) bool {
	parts := strings.Split(name, "/")
	if len(parts) < 3 {
		return false
	}

	if parts[0] != "Payload" {
		return false
	}

	if !strings.HasSuffix(parts[1], ".app") {
		return false
	}

	return parts[2] == "Watch"
}

func cmpVer(a, b string) int {
	aParts := strings.Split(a, ".")
	bParts := strings.Split(b, ".")

	n := len(aParts)
	if len(bParts) > n {
		n = len(bParts)
	}

	for i := 0; i < n; i++ {
		var x, y int

		if i < len(aParts) {
			x, _ = strconv.Atoi(aParts[i])
		}

		if i < len(bParts) {
			y, _ = strconv.Atoi(bParts[i])
		}

		if x != y {
			return x - y
		}
	}

	return 0
}
