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

type PatchResult struct {
	MinOSChanged         bool
	PreviousMinOS        string
	WatchRemoved         int
	DeviceFamilyExpanded bool
	PreviousDeviceFamily []int
	NewDeviceFamily      []int
}

// ErrDeviceFamilyMismatch is returned when an IPA's UIDeviceFamily list does
// not include the target device's family and the caller has not opted into
// patching. The caller can format a user-friendly message from the fields.
type ErrDeviceFamilyMismatch struct {
	Supported []int
	Device    int
}

func (e *ErrDeviceFamilyMismatch) Error() string {
	return fmt.Sprintf("app supports device family %v, device is %d (%s)",
		e.Supported, e.Device, DeviceFamilyName(e.Device))
}

func DeviceFamilyName(f int) string {
	switch f {
	case 1:
		return "iPhone"
	case 2:
		return "iPad"
	case 3:
		return "Apple TV"
	case 4:
		return "Apple Watch"
	default:
		return "unknown"
	}
}

// PatchForInstall rewrites the main Info.plist (MinimumOSVersion plus, when
// patchDeviceType is true, UIDeviceFamily) and drops Watch/ entries. The
// Info.plist is pre-scanned so a device-family mismatch fails early, without
// writing a partial output IPA.
func PatchForInstall(src, dst, target string, deviceFamily int, patchDeviceType bool) (PatchResult, error) {
	var res PatchResult

	edit := func(m map[string]any, format int) ([]byte, error) {
		dirty := false

		current, _ := m["MinimumOSVersion"].(string)
		if current != "" && cmpVer(current, target) > 0 {
			m["MinimumOSVersion"] = target
			res.MinOSChanged = true
			res.PreviousMinOS = current
			dirty = true
		}

		supported := readDeviceFamily(m["UIDeviceFamily"])
		if deviceFamily > 0 && len(supported) > 0 && !containsInt(supported, deviceFamily) {
			if !patchDeviceType {
				return nil, &ErrDeviceFamilyMismatch{Supported: supported, Device: deviceFamily}
			}

			expanded := append(append([]int(nil), supported...), deviceFamily)
			m["UIDeviceFamily"] = toAnySlice(expanded)
			res.DeviceFamilyExpanded = true
			res.PreviousDeviceFamily = supported
			res.NewDeviceFamily = expanded
			dirty = true
		}

		if !dirty {
			return nil, nil
		}

		return plist.Marshal(m, format)
	}

	_, removed, err := rewriteIPA(src, dst, edit, true)
	if err != nil {
		return res, err
	}

	res.WatchRemoved = removed

	return res, nil
}

func isMainAppInfoPlist(name string) bool {
	parts := strings.Split(name, "/")

	return len(parts) == 3 &&
		parts[0] == "Payload" &&
		strings.HasSuffix(parts[1], ".app") &&
		parts[2] == "Info.plist"
}

// copyEntry forwards an entry verbatim — no decompress + recompress.
// CreateRaw + OpenRaw stream the original deflate bytes byte-for-byte,
// which is the only thing that makes a multi-GB IPA repack survivable.
func copyEntry(f *zip.File, w *zip.Writer) error {
	rc, err := f.OpenRaw()
	if err != nil {
		return err
	}

	hdr := f.FileHeader

	dst, err := w.CreateRaw(&hdr)
	if err != nil {
		return err
	}

	_, err = io.Copy(dst, rc)

	return err
}

// rewriteIPA streams src → dst, copying every entry verbatim except for the
// main Info.plist, which is offered to edit. When edit returns non-nil bytes
// the new contents replace the original; nil bytes leave the entry untouched.
// When dropWatch is true, Payload/<App>.app/Watch/* entries are dropped.
//
// If edit returns an error, dst is not opened — callers get the same
// "fail before writing a partial output" guarantee the old pre-scan offered.
// If neither Info.plist nor any Watch entry needs changing, dst is not
// created at all and (false, 0, nil) is returned, so callers can no-op
// without paying for a multi-GB copy.
func rewriteIPA(src, dst string, edit func(map[string]any, int) ([]byte, error), dropWatch bool) (wrote bool, watchRemoved int, err error) {
	r, err := zip.OpenReader(src)
	if err != nil {
		return false, 0, fmt.Errorf("open %s: %w", src, err)
	}
	defer r.Close()

	var infoFile *zip.File

	hasWatch := false

	for _, f := range r.File {
		if infoFile == nil && isMainAppInfoPlist(f.Name) {
			infoFile = f
		}

		if dropWatch && isWatchPath(f.Name) {
			hasWatch = true
		}
	}

	var newInfo []byte

	if infoFile != nil && edit != nil {
		rc, err := infoFile.Open()
		if err != nil {
			return false, 0, err
		}

		data, err := io.ReadAll(rc)
		rc.Close()

		if err != nil {
			return false, 0, err
		}

		var m map[string]any

		// Unparseable plists are silently passed through (legacy policy).
		format, perr := plist.Unmarshal(data, &m)
		if perr == nil {
			newInfo, err = edit(m, format)
			if err != nil {
				return false, 0, err
			}
		}
	}

	if newInfo == nil && !hasWatch {
		return false, 0, nil
	}

	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return false, 0, fmt.Errorf("mkdir %s: %w", filepath.Dir(dst), err)
	}

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return false, 0, fmt.Errorf("open dst %s: %w", dst, err)
	}

	committed := false
	defer func() {
		if !committed {
			out.Close()
			os.Remove(dst)
		}
	}()

	w := zip.NewWriter(out)

	for _, f := range r.File {
		if dropWatch && isWatchPath(f.Name) {
			watchRemoved++
			continue
		}

		if f == infoFile && newInfo != nil {
			if err := writeBytes(f, w, newInfo); err != nil {
				return false, watchRemoved, fmt.Errorf("rewrite %s: %w", f.Name, err)
			}

			continue
		}

		if err := copyEntry(f, w); err != nil {
			return false, watchRemoved, fmt.Errorf("copy %s: %w", f.Name, err)
		}
	}

	if err := w.Close(); err != nil {
		return false, watchRemoved, fmt.Errorf("close zip: %w", err)
	}

	if err := out.Close(); err != nil {
		return false, watchRemoved, err
	}

	committed = true

	return true, watchRemoved, nil
}

func intSliceEqual(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}

	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}

	return true
}

func readDeviceFamily(v any) []int {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}

	out := make([]int, 0, len(arr))
	for _, e := range arr {
		switch n := e.(type) {
		case uint64:
			out = append(out, int(n))
		case int64:
			out = append(out, int(n))
		case int:
			out = append(out, n)
		}
	}

	return out
}

func toAnySlice(in []int) []any {
	out := make([]any, len(in))
	for i, v := range in {
		out[i] = uint64(v)
	}

	return out
}

func containsInt(haystack []int, needle int) bool {
	for _, v := range haystack {
		if v == needle {
			return true
		}
	}

	return false
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
			return "", "", fmt.Errorf("missing CFBundleIdentifier in Info.plist")
		}

		return bundleID, version, nil
	}

	return "", "", fmt.Errorf("no Payload/*.app/Info.plist in %s", ipaPath)
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

// RestoreOriginalPlistValues rewrites the main Info.plist of an already-built
// IPA, putting MinimumOSVersion and UIDeviceFamily back to the values
// captured before PatchForInstall mutated them. The rewrite is atomic
// (write-to-tmp + rename) and is a no-op when the IPA already matches the
// originals, so the multi-GB copy is skipped in the common "nothing to do"
// case.
func RestoreOriginalPlistValues(ipaPath, originalMinOS string, originalDeviceFamily []int) error {
	if originalMinOS == "" && len(originalDeviceFamily) == 0 {
		return nil
	}

	tmpPath := ipaPath + ".tmp"

	wrote, _, err := rewriteIPA(ipaPath, tmpPath, func(m map[string]any, format int) ([]byte, error) {
		dirty := false

		if originalMinOS != "" {
			if cur, _ := m["MinimumOSVersion"].(string); cur != originalMinOS {
				m["MinimumOSVersion"] = originalMinOS
				dirty = true
			}
		}

		if len(originalDeviceFamily) > 0 {
			cur := readDeviceFamily(m["UIDeviceFamily"])
			if !intSliceEqual(cur, originalDeviceFamily) {
				m["UIDeviceFamily"] = toAnySlice(originalDeviceFamily)
				dirty = true
			}
		}

		if !dirty {
			return nil, nil
		}

		return plist.Marshal(m, format)
	}, false)
	if err != nil {
		return err
	}

	if !wrote {
		return nil
	}

	return os.Rename(tmpPath, ipaPath)
}
