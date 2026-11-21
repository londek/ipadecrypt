package appstore

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"howett.net/plist"
)

func TestPatchPackagePreservesOrdinaryIPAs(t *testing.T) {
	for _, method := range []uint16{zip.Store, zip.Deflate} {
		for _, licensing := range []string{"none", "fallback", "manifest"} {
			t.Run(fmt.Sprintf("method-%d/%s", method, licensing), func(t *testing.T) {
				dir := t.TempDir()
				source, output := filepath.Join(dir, "source.ipa"), filepath.Join(dir, "output.ipa")

				info, err := plist.Marshal(map[string]string{
					"CFBundleIdentifier": "com.example.app", "CFBundleShortVersionString": "1.0.0", "CFBundleExecutable": "Example",
				}, plist.XMLFormat)
				if err != nil {
					t.Fatal(err)
				}

				entries := []struct {
					name string
					data []byte
				}{
					{"Payload/Example.app/Info.plist", info},
					{"Payload/Example.app/Example", bytes.Repeat([]byte{0xcf, 0xfa, 0xed, 0xfe, 0x12, 0x34}, 1024)},
					{"Payload/Example.app/Assets.car", bytes.Repeat([]byte("original assets"), 128)},
				}
				ticket := DownloadTicket{Metadata: map[string]any{"bundleIdentifier": "com.example.app", "bundleShortVersionString": "1.0.0"}}

				sinfPaths := []string{"SC_Info/Example.sinf"}
				if licensing == "manifest" {
					sinfPaths = append(sinfPaths, "PlugIns/Extension.appex/SC_Info/Extension.sinf")

					manifest, err := plist.Marshal(map[string]any{"SinfPaths": sinfPaths}, plist.XMLFormat)
					if err != nil {
						t.Fatal(err)
					}

					entries = append(entries, struct {
						name string
						data []byte
					}{"Payload/Example.app/SC_Info/Manifest.plist", manifest})
				}

				if licensing != "none" {
					for i := range sinfPaths {
						ticket.Sinfs = append(ticket.Sinfs, Sinf{ID: int64(i + 1), Data: []byte{byte(i), 1, 2, 3}})
					}
				}

				var archive bytes.Buffer

				writer := zip.NewWriter(&archive)

				for _, entry := range entries {
					header := &zip.FileHeader{Name: entry.name, Method: method, Comment: "original comment", Extra: []byte{0xca, 0xfe, 3, 0, 1, 2, 3}}
					header.SetMode(0o755)

					w, err := writer.CreateHeader(header)
					if err != nil {
						t.Fatal(err)
					}

					if _, err = w.Write(entry.data); err != nil {
						t.Fatal(err)
					}
				}

				if err := writer.Close(); err != nil {
					t.Fatal(err)
				}

				if err := os.WriteFile(source, archive.Bytes(), 0o600); err != nil {
					t.Fatal(err)
				}

				if err := PatchPackage(source, output, ticket, &Account{Email: "person@example.com"}); err != nil {
					t.Fatal(err)
				}

				original, err := zip.OpenReader(source)
				if err != nil {
					t.Fatal(err)
				}
				defer original.Close()

				patched, err := zip.OpenReader(output)
				if err != nil {
					t.Fatal(err)
				}
				defer patched.Close()

				files := make(map[string]*zip.File)
				for _, file := range patched.File {
					files[file.Name] = file
				}

				for _, file := range original.File {
					got := files[file.Name]
					if got == nil {
						t.Fatalf("missing %s", file.Name)
					}

					if got.Method != file.Method || got.Mode() != file.Mode() || got.Comment != file.Comment || !bytes.Equal(got.Extra, file.Extra) {
						t.Fatalf("changed ZIP attributes for %s", file.Name)
					}

					raw, err := file.OpenRaw()
					if err != nil {
						t.Fatal(err)
					}

					want, err := io.ReadAll(raw)
					if err != nil {
						t.Fatal(err)
					}

					raw, err = got.OpenRaw()
					if err != nil {
						t.Fatal(err)
					}

					actual, err := io.ReadAll(raw)
					if err != nil {
						t.Fatal(err)
					}

					if !bytes.Equal(actual, want) {
						t.Fatalf("compressed bytes changed for %s", file.Name)
					}
				}

				metadata, err := readZipFile(files["iTunesMetadata.plist"])
				if err != nil {
					t.Fatal(err)
				}

				var values map[string]any
				if _, err = plist.Unmarshal(metadata, &values); err != nil {
					t.Fatal(err)
				}

				if values["apple-id"] != "person@example.com" || values["bundleIdentifier"] != "com.example.app" {
					t.Fatal("incorrect account metadata")
				}

				for i, sinf := range ticket.Sinfs {
					file := files["Payload/Example.app/"+sinfPaths[i]]
					if file == nil {
						t.Fatal("missing SINF")
					}

					data, err := readZipFile(file)
					if err != nil || !bytes.Equal(data, sinf.Data) {
						t.Fatal("incorrect SINF")
					}
				}
			})
		}
	}
}
