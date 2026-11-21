package appstore

import (
	"archive/zip"
	"bytes"
	"hash/crc32"
	"io"
	"os"
	"testing"

	"github.com/go-compressions/lzfse"
)

func TestReplicateZipNormalizesAppleLZFSE(t *testing.T) {
	payload := bytes.Repeat([]byte("TestFlight package data\n"), 1024)

	compressed, err := lzfse.Compress(payload)
	if err != nil {
		t.Fatal(err)
	}

	sourcePath := t.TempDir() + "/apple.zip"

	source, err := os.Create(sourcePath)
	if err != nil {
		t.Fatal(err)
	}

	zw := zip.NewWriter(source)
	header := &zip.FileHeader{
		Name:               "Payload/Test.app/Test",
		Method:             appleLZFSEMethod,
		CRC32:              crc32.ChecksumIEEE(payload),
		CompressedSize64:   uint64(len(compressed)),
		UncompressedSize64: uint64(len(payload)),
	}

	w, err := zw.CreateRaw(header)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := w.Write(compressed); err != nil {
		t.Fatal(err)
	}

	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	if err := source.Close(); err != nil {
		t.Fatal(err)
	}

	zr, err := zip.OpenReader(sourcePath)
	if err != nil {
		t.Fatal(err)
	}

	registerAppleZIPDecompressor(&zr.Reader)

	destinationPath := t.TempDir() + "/normalized.zip"

	destination, err := os.Create(destinationPath)
	if err != nil {
		t.Fatal(err)
	}

	output := zip.NewWriter(destination)
	if err := replicateZip(zr, output, sourcePath); err != nil {
		t.Fatal(err)
	}

	if err := output.Close(); err != nil {
		t.Fatal(err)
	}

	if err := destination.Close(); err != nil {
		t.Fatal(err)
	}

	if err := zr.Close(); err != nil {
		t.Fatal(err)
	}

	normalized, err := zip.OpenReader(destinationPath)
	if err != nil {
		t.Fatal(err)
	}
	defer normalized.Close()

	if len(normalized.File) != 1 || normalized.File[0].Method != zip.Deflate {
		t.Fatalf("normalized files = %#v", normalized.File)
	}

	r, err := normalized.File[0].Open()
	if err != nil {
		t.Fatal(err)
	}

	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}

	if err := r.Close(); err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(got, payload) {
		t.Fatal("normalized member differs from its Apple LZFSE source")
	}
}
