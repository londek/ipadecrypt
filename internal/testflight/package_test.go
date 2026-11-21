package testflight

import (
	"archive/zip"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/londek/ipadecrypt/internal/appstore"
	"howett.net/plist"
)

func packageArchive(t *testing.T, version, marker string) []byte {
	t.Helper()

	var archive bytes.Buffer

	w := zip.NewWriter(&archive)

	info, err := plist.Marshal(map[string]string{"CFBundleIdentifier": "com.example.beta", "CFBundleShortVersionString": version}, plist.XMLFormat)
	if err != nil {
		t.Fatal(err)
	}

	for _, entry := range []struct {
		name string
		data []byte
	}{{"Payload/Example.app/Info.plist", info}, {"Payload/Example.app/Example", []byte(marker)}} {
		file, err := w.Create(entry.name)
		if err != nil {
			t.Fatal(err)
		}

		if _, err = file.Write(entry.data); err != nil {
			t.Fatal(err)
		}
	}

	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	return archive.Bytes()
}

func packageTicket() DownloadTicket {
	return DownloadTicket{DownloadTicket: appstore.DownloadTicket{Metadata: map[string]any{"bundleIdentifier": "com.example.beta", "bundleShortVersionString": "1.0.0"}}}
}

func TestPublishPackagePreservesExistingIPAOnFailure(t *testing.T) {
	for _, test := range []struct {
		name     string
		validZIP bool
		version  string
	}{{"version mismatch", true, "2.0.0"}, {"invalid ZIP", false, ""}} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			source, output := filepath.Join(dir, "prepared.ipa"), filepath.Join(dir, "output.ipa")
			old := packageArchive(t, "1.0.0", "existing")

			candidate := []byte("invalid ZIP")
			if test.validZIP {
				candidate = packageArchive(t, test.version, "candidate")
			}

			if err := os.WriteFile(source, candidate, 0o600); err != nil {
				t.Fatal(err)
			}

			if err := os.WriteFile(output, old, 0o600); err != nil {
				t.Fatal(err)
			}

			if err := publishPackage(source, output, packageTicket()); err == nil {
				t.Fatal("published invalid package")
			}

			got, err := os.ReadFile(output)
			if err != nil || !bytes.Equal(got, old) {
				t.Fatal("existing IPA was changed")
			}
		})
	}
}

func TestPublishPackageReplacesDestinationSymlink(t *testing.T) {
	dir := t.TempDir()
	source, output, victim := filepath.Join(dir, "prepared.ipa"), filepath.Join(dir, "output.ipa"), filepath.Join(dir, "victim")

	archive := packageArchive(t, "1.0.0", "candidate")
	if err := os.WriteFile(source, archive, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(victim, []byte("untouched"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := os.Symlink(victim, output); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	if err := publishPackage(source, output, packageTicket()); err != nil {
		t.Fatal(err)
	}

	got, err := os.ReadFile(victim)
	if err != nil || string(got) != "untouched" {
		t.Fatal("followed destination symlink")
	}

	got, err = os.ReadFile(output)
	if err != nil || !bytes.Equal(got, archive) {
		t.Fatal("validated package not published")
	}

	stat, err := os.Lstat(output)
	if err != nil || !stat.Mode().IsRegular() {
		t.Fatal("destination is not a regular IPA")
	}
}

func TestConcurrentPackagePublicationDoesNotMixFiles(t *testing.T) {
	dir := t.TempDir()
	output := filepath.Join(dir, "output.ipa")

	var (
		sources  []string
		archives [][]byte
	)

	for i := 0; i < 6; i++ {
		private, err := os.MkdirTemp(dir, "stage-")
		if err != nil {
			t.Fatal(err)
		}

		source := filepath.Join(private, "prepared.ipa")

		archive := packageArchive(t, "1.0.0", fmt.Sprintf("package-%d", i))
		if err := os.WriteFile(source, archive, 0o600); err != nil {
			t.Fatal(err)
		}

		sources = append(sources, source)
		archives = append(archives, archive)
	}

	var workers sync.WaitGroup

	failures := make(chan error, len(sources))
	for _, source := range sources {
		workers.Add(1)
		go func() { defer workers.Done(); failures <- publishPackage(source, output, packageTicket()) }()
	}

	workers.Wait()
	close(failures)

	for err := range failures {
		if err != nil {
			t.Fatal(err)
		}
	}

	got, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}

	for _, archive := range archives {
		if bytes.Equal(got, archive) {
			return
		}
	}

	t.Fatal("published IPA was mixed or incomplete")
}
