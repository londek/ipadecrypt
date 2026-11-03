package pipeline

import (
	"archive/zip"
	"fmt"
	"io"
	"strings"

	"howett.net/plist"
)

func isMainAppInfoPlist(name string) bool {
	parts := strings.Split(name, "/")

	return len(parts) == 3 &&
		parts[0] == "Payload" &&
		strings.HasSuffix(parts[1], ".app") &&
		parts[2] == "Info.plist"
}

// copyEntry forwards an entry verbatim  no decompress + recompress.
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

// isAppExtPath matches Payload/<App>.app/PlugIns/<*>.appex/...
func isAppExtPath(name string) bool {
	parts := strings.Split(name, "/")

	return len(parts) >= 4 &&
		parts[0] == "Payload" &&
		strings.HasSuffix(parts[1], ".app") &&
		parts[2] == "PlugIns"
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
