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

type plistPlan struct {
	data                 []byte // rewritten bytes, or nil if unchanged
	minOSChanged         bool
	previousMinOS        string
	deviceFamilyExpanded bool
	previousFamily       []int
	newFamily            []int
}

// PatchForInstall rewrites the main Info.plist (MinimumOSVersion plus, when
// patchDeviceType is true, UIDeviceFamily) and drops Watch/ entries. The
// Info.plist is pre-scanned so a device-family mismatch fails early, without
// writing a partial output IPA.
func PatchForInstall(src, dst, target string, deviceFamily int, patchDeviceType bool) (PatchResult, error) {
	var res PatchResult

	r, err := zip.OpenReader(src)
	if err != nil {
		return res, fmt.Errorf("open %s: %w", src, err)
	}
	defer r.Close()

	var infoFile *zip.File

	for _, f := range r.File {
		if isMainAppInfoPlist(f.Name) {
			infoFile = f
			break
		}
	}

	var plan plistPlan
	if infoFile != nil {
		plan, err = planInfoPlist(infoFile, target, deviceFamily, patchDeviceType)
		if err != nil {
			return res, err
		}
	}

	res.MinOSChanged = plan.minOSChanged
	res.PreviousMinOS = plan.previousMinOS
	res.DeviceFamilyExpanded = plan.deviceFamilyExpanded
	res.PreviousDeviceFamily = plan.previousFamily
	res.NewDeviceFamily = plan.newFamily

	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return res, fmt.Errorf("mkdir %s: %w", filepath.Dir(dst), err)
	}

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return res, fmt.Errorf("open dst %s: %w", dst, err)
	}
	defer out.Close()

	w := zip.NewWriter(out)

	for _, f := range r.File {
		if isWatchPath(f.Name) {
			res.WatchRemoved++
			continue
		}

		if f == infoFile && plan.data != nil {
			if err := writeBytes(f, w, plan.data); err != nil {
				return res, fmt.Errorf("rewrite %s: %w", f.Name, err)
			}

			continue
		}

		if err := copyEntry(f, w); err != nil {
			return res, fmt.Errorf("copy %s: %w", f.Name, err)
		}
	}

	if err := w.Close(); err != nil {
		return res, fmt.Errorf("close zip: %w", err)
	}

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

func planInfoPlist(f *zip.File, target string, deviceFamily int, patchDeviceType bool) (plistPlan, error) {
	var plan plistPlan

	rc, err := f.Open()
	if err != nil {
		return plan, err
	}

	data, err := io.ReadAll(rc)
	rc.Close()

	if err != nil {
		return plan, err
	}

	var m map[string]any

	format, err := plist.Unmarshal(data, &m)
	if err != nil {
		// Not a parseable plist; pass through unchanged.
		return plan, nil
	}

	dirty := false

	current, _ := m["MinimumOSVersion"].(string)
	if current != "" && cmpVer(current, target) > 0 {
		m["MinimumOSVersion"] = target
		plan.minOSChanged = true
		plan.previousMinOS = current
		dirty = true
	}

	supported := readDeviceFamily(m["UIDeviceFamily"])
	if deviceFamily > 0 && len(supported) > 0 && !containsInt(supported, deviceFamily) {
		if !patchDeviceType {
			return plan, &ErrDeviceFamilyMismatch{Supported: supported, Device: deviceFamily}
		}

		expanded := append(append([]int(nil), supported...), deviceFamily)
		m["UIDeviceFamily"] = toAnySlice(expanded)
		plan.deviceFamilyExpanded = true
		plan.previousFamily = supported
		plan.newFamily = expanded
		dirty = true
	}

	if !dirty {
		return plan, nil
	}

	newData, err := plist.Marshal(m, format)
	if err != nil {
		return plan, fmt.Errorf("marshal plist: %w", err)
	}

	plan.data = newData

	return plan, nil
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

// RestoreMinimumOSVersion rewrites the main Info.plist (MinimumOSVersion) to the original value in the given IPA file.
func RestoreMinimumOSVersion(ipaPath, originalMinOS string) error {
	tmpPath := ipaPath + ".tmp"

	r, err := zip.OpenReader(ipaPath)
	if err != nil {
		return fmt.Errorf("open %s: %w", ipaPath, err)
	}
	defer r.Close()

	var infoFile *zip.File
	for _, f := range r.File {
		if isMainAppInfoPlist(f.Name) {
			infoFile = f
			break
		}
	}

	var data []byte
	if infoFile != nil {
		rc, err := infoFile.Open()
		if err != nil {
			return err
		}
		originalData, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			return err
		}

		var m map[string]any
		format, err := plist.Unmarshal(originalData, &m)
		if err == nil {
			m["MinimumOSVersion"] = originalMinOS
			data, err = plist.Marshal(m, format)
			if err != nil {
				return err
			}
		}
	}

	out, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("open dst %s: %w", tmpPath, err)
	}

	w := zip.NewWriter(out)

	for _, f := range r.File {
		if f == infoFile && data != nil {
			if err := writeBytes(f, w, data); err != nil {
				out.Close()
				os.Remove(tmpPath)
				return fmt.Errorf("rewrite %s: %w", f.Name, err)
			}
			continue
		}

		if err := copyEntry(f, w); err != nil {
			out.Close()
			os.Remove(tmpPath)
			return fmt.Errorf("copy %s: %w", f.Name, err)
		}
	}

	if err := w.Close(); err != nil {
		out.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("close zip: %w", err)
	}

	if err := out.Close(); err != nil {
		os.Remove(tmpPath)
		return err
	}

	return os.Rename(tmpPath, ipaPath)
}
