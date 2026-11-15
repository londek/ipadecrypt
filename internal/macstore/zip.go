package macstore

import (
	"archive/zip"
	"errors"
	"fmt"
	"io"
)

func CheckZIP(path string) error {
	r, err := zip.OpenReader(path)
	if err != nil {
		return err
	}
	defer r.Close()

	for _, entry := range r.File {
		if entry.FileInfo().IsDir() {
			continue
		}

		f, err := entry.Open()
		if err != nil {
			return err
		}

		_, copyErr := io.Copy(io.Discard, f)

		err = errors.Join(copyErr, f.Close())
		if err != nil {
			return fmt.Errorf("invalid ZIP entry: %w", err)
		}
	}

	return nil
}
