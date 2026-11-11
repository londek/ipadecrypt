package pipeline

import (
	"archive/zip"
	"fmt"
	"io"
	"strings"
)

// SubstituteWriter writes one substituted entry into the output IPA.
// Excluded entries (SC_Info, dSYM, etc., and Watch unless keepWatch) are
// silently dropped so the caller doesn't have to mirror the exclude set.
type SubstituteWriter func(name string, r io.Reader) error

// Assemble writes a decrypted IPA into dst by combining caller-supplied
// substitute entries (typically decrypted Mach-Os streamed from the
// device) with verbatim entries from srcIPA.
//
// fillSubstitutes receives a write function; each invocation creates one
// entry in the output and records it so the srcIPA traversal skips the
// original. After fillSubstitutes returns, every srcIPA entry that
// wasn't substituted and doesn't match the on-device exclude set is
// copied byte-for-byte (deflate-preserving) into dst. With keepWatch, Watch
// and WatchKitSupport2 entries are kept instead of excluded.
func Assemble(srcIPA string, dst io.Writer, keepWatch bool,
	fillSubstitutes func(write SubstituteWriter) error) error {
	src, err := zip.OpenReader(srcIPA)
	if err != nil {
		return fmt.Errorf("open src %s: %w", srcIPA, err)
	}

	defer src.Close()

	zw := zip.NewWriter(dst)

	written := make(map[string]struct{})

	write := func(name string, r io.Reader) error {
		if isExcludedIPAEntry(name, keepWatch) {
			// Drop and drain so the framed stream stays aligned.
			_, err := io.Copy(io.Discard, r)
			return err
		}

		w, err := zw.Create(name)
		if err != nil {
			return err
		}

		if _, err := io.Copy(w, r); err != nil {
			return err
		}

		written[name] = struct{}{}

		return nil
	}

	if err := fillSubstitutes(write); err != nil {
		zw.Close()
		return err
	}

	for _, f := range src.File {
		if _, ok := written[f.Name]; ok {
			continue
		}

		if isExcludedIPAEntry(f.Name, keepWatch) {
			continue
		}

		if err := copyEntry(f, zw); err != nil {
			zw.Close()
			return fmt.Errorf("copy %s: %w", f.Name, err)
		}
	}

	return zw.Close()
}

// isExcludedIPAEntry mirrors the -x patterns the on-device run_zip
// applies: SC_Info (FairPlay sinfs), Watch/WatchKitSupport2, dSYM,
// BCSymbolMaps, Symbols, META-INF, iTunesMetadata.plist, iTunesArtwork.
// keepWatch lets Watch/WatchKitSupport2 through.
func isExcludedIPAEntry(name string, keepWatch bool) bool {
	s := strings.TrimSuffix(name, "/")

	if s == "iTunesMetadata.plist" || s == "Payload/iTunesMetadata.plist" || s == "Payload/iTunesArtwork" {
		return true
	}

	if s == "Payload/META-INF" || strings.HasPrefix(s, "Payload/META-INF/") {
		return true
	}

	parts := strings.Split(s, "/")

	// Walk segments inside Payload/<app>.app/ (skip "Payload" and "<app>.app").
	for i := 2; i < len(parts); i++ {
		seg := parts[i]
		switch seg {
		case "Watch", "WatchKitSupport2":
			if !keepWatch {
				return true
			}
		case "SC_Info", "BCSymbolMaps", "Symbols":
			return true
		}

		if strings.HasSuffix(seg, ".dSYM") {
			return true
		}
	}

	return false
}
