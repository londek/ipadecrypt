package appstore

import (
	"archive/zip"
	"bytes"
	"io"

	"github.com/go-compressions/lzfse"
)

const appleLZFSEMethod = 99

func registerAppleZIPDecompressor(reader *zip.Reader) {
	reader.RegisterDecompressor(appleLZFSEMethod, func(source io.Reader) io.ReadCloser {
		return &appleLZFSEReader{source: source}
	})
}

type appleLZFSEReader struct {
	source io.Reader
	reader *bytes.Reader
	err    error
}

func (r *appleLZFSEReader) Read(p []byte) (int, error) {
	if r.reader == nil && r.err == nil {
		var compressed []byte

		compressed, r.err = io.ReadAll(r.source)
		if r.err == nil {
			var uncompressed []byte

			uncompressed, r.err = lzfse.Decompress(compressed)
			r.reader = bytes.NewReader(uncompressed)
		}
	}

	if r.err != nil {
		return 0, r.err
	}

	return r.reader.Read(p)
}

func (r *appleLZFSEReader) Close() error {
	return nil
}
