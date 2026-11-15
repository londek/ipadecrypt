package macstore

import (
	"archive/zip"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	store "github.com/majd/ipatool/v2/pkg/appstore"
	"howett.net/plist"
)

type downloadAPI struct {
	store.AppStore
	download  func(store.DownloadInput) (store.DownloadOutput, error)
	replicate func(store.ReplicateSinfInput) error
}

func (a downloadAPI) Download(in store.DownloadInput) (store.DownloadOutput, error) {
	return a.download(in)
}
func (a downloadAPI) ReplicateSinf(in store.ReplicateSinfInput) error { return a.replicate(in) }

func downloadFixture(t *testing.T, path string, mutations map[string]any, duplicate bool) {
	t.Helper()

	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}

	z := zip.NewWriter(f)

	metadata := map[string]any{"apple-id": "owner@example.test", "itemId": 123, "softwareVersionBundleId": "test.app", "softwareVersionExternalIdentifier": 456}
	for k, v := range mutations {
		metadata[k] = v
	}

	info := map[string]any{"CFBundleIdentifier": "test.app", "CFBundleSupportedPlatforms": []string{"iPhoneOS"}, "CFBundleExecutable": "App"}
	write := func(name string, data []byte) {
		w, err := z.Create(name)
		if err != nil {
			t.Fatal(err)
		}

		if _, err = w.Write(data); err != nil {
			t.Fatal(err)
		}
	}

	meta, err := plist.Marshal(metadata, plist.XMLFormat)
	if err != nil {
		t.Fatal(err)
	}

	bundle, err := plist.Marshal(info, plist.XMLFormat)
	if err != nil {
		t.Fatal(err)
	}

	write("iTunesMetadata.plist", meta)

	if duplicate {
		write("iTunesMetadata.plist", meta)
	}

	write("Payload/App.app/Info.plist", bundle)
	write("Payload/App.app/App", []byte("executable"))
	write("Payload/App.app/SC_Info/App.sinf", []byte("license"))

	if err = errors.Join(z.Close(), f.Close()); err != nil {
		t.Fatal(err)
	}
}

func TestPublicDownloadCacheRefreshAndProgress(t *testing.T) {
	account := store.Account{Email: "owner@example.test", DirectoryServicesID: "12345"}
	catalog := CatalogApp{App: store.App{ID: 123, BundleID: "test.app"}, ExternalVersionID: "456"}
	calls, replications := 0, 0
	api := downloadAPI{
		download: func(in store.DownloadInput) (store.DownloadOutput, error) {
			calls++

			if in.Platform != store.PlatformIPhone || in.ExternalVersionID != "456" || in.Account != account {
				t.Fatal("incorrect public download inputs")
			}

			downloadFixture(t, in.OutputPath, nil, false)
			in.Progress.ChangeMax64(100)

			if err := in.Progress.Set64(100); err != nil {
				t.Fatal(err)
			}

			return store.DownloadOutput{DestinationPath: in.OutputPath, Sinfs: []store.Sinf{{Data: []byte("license")}}}, nil
		},
		replicate: func(in store.ReplicateSinfInput) error {
			replications++

			if filepath.Base(in.PackagePath) != "personalized.ipa" {
				t.Fatal("replication can overwrite resumable download")
			}

			return nil
		},
	}
	s := &Session{Root: t.TempDir(), API: api}

	var current, total int64

	path, err := Download(context.Background(), s, account, catalog, false, nil, func(c, n int64) { current, total = c, n })
	if err != nil {
		t.Fatal(err)
	}

	if current != 100 || total != 100 {
		t.Fatalf("progress %d/%d", current, total)
	}

	if _, err = Download(context.Background(), s, account, catalog, false, nil, nil); err != nil || calls != 1 {
		t.Fatal("cache not reused", err, calls)
	}

	if _, err = Download(context.Background(), s, account, catalog, true, nil, nil); err != nil || calls != 2 {
		t.Fatal("refresh not delegated", err, calls)
	}

	if err = os.WriteFile(path, []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}

	if _, err = Download(context.Background(), s, account, catalog, false, nil, nil); err != nil || calls != 3 || replications != 3 {
		t.Fatal("corrupt cache reused", err, calls, replications)
	}
}

func TestDownloadRejectsWrongBindingBeforePublication(t *testing.T) {
	for _, tc := range []struct {
		name      string
		changes   map[string]any
		duplicate bool
	}{
		{"account", map[string]any{"apple-id": "other@example.test"}, false},
		{"app", map[string]any{"itemId": 999}, false},
		{"bundle", map[string]any{"softwareVersionBundleId": "other.app"}, false},
		{"version", map[string]any{"softwareVersionExternalIdentifier": 999}, false},
		{"duplicate", nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			s := &Session{Root: root, API: downloadAPI{download: func(in store.DownloadInput) (store.DownloadOutput, error) {
				downloadFixture(t, in.OutputPath, tc.changes, tc.duplicate)
				return store.DownloadOutput{DestinationPath: in.OutputPath, Sinfs: []store.Sinf{{Data: []byte("license")}}}, nil
			}, replicate: func(store.ReplicateSinfInput) error { return nil }}}
			a := store.Account{Email: "owner@example.test", DirectoryServicesID: "12345"}

			c := CatalogApp{App: store.App{ID: 123, BundleID: "test.app"}, ExternalVersionID: "456"}
			if _, err := Download(context.Background(), s, a, c, false, nil, nil); err == nil {
				t.Fatal("bad binding accepted")
			}

			for _, name := range []string{"ready.json", "encrypted.ipa"} {
				if _, err := os.Stat(filepath.Join(root, "downloads", AccountHash(a), "123-456", name)); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("invalid download published", err)
				}
			}
		})
	}
}

func TestPublicDownloadRetainsPartialAndLicenseError(t *testing.T) {
	a := store.Account{Email: "owner@example.test", DirectoryServicesID: "12345"}
	c := CatalogApp{App: store.App{ID: 123, BundleID: "test.app"}, ExternalVersionID: "456"}

	var previous string

	s := &Session{Root: t.TempDir(), API: downloadAPI{download: func(in store.DownloadInput) (store.DownloadOutput, error) {
		if previous != "" {
			if previous != in.OutputPath {
				t.Fatal("resume path changed")
			}

			if b, err := os.ReadFile(in.OutputPath + ".tmp"); err != nil || string(b) != "prefix" {
				t.Fatal("partial lost", err)
			}
		}

		previous = in.OutputPath
		if err := os.WriteFile(in.OutputPath+".tmp", []byte("prefix"), 0600); err != nil {
			t.Fatal(err)
		}

		return store.DownloadOutput{}, store.ErrLicenseRequired
	}}}
	for range 2 {
		if _, err := Download(context.Background(), s, a, c, false, nil, nil); !errors.Is(err, store.ErrLicenseRequired) {
			t.Fatal("lost license sentinel", err)
		}
	}
}
