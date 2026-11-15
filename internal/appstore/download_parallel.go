package appstore

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	apphttp "github.com/londek/ipadecrypt/internal/apphttp"
)

const (
	parallelDownloadThreshold = 128 << 20
	parallelDownloadCount     = 4
)

type parallelDownloadError struct {
	err       error
	validator string
}

func (e *parallelDownloadError) Error() string {
	return fmt.Sprintf("parallel download: %s", e.err)
}

func (e *parallelDownloadError) Unwrap() error {
	return e.err
}

func downloadPartsPath(dst string) string {
	return dst + ".ipadecrypt-parts"
}

// downloadValidator returns the response's strong ETag; combining ranges is
// only safe when they all come from the same representation.
func downloadValidator(res *http.Response) string {
	etag := res.Header.Get("ETag")
	if strings.HasPrefix(etag, `"`) && strings.HasSuffix(etag, `"`) {
		return etag
	}

	return ""
}

// downloadFileParallel completes a download whose first response covers the
// whole remainder [offset, total). It keeps the first quarter from that
// response and fetches the other three as separate ranges. Out-of-order bytes
// are staged in a side directory so the main file always holds a contiguous,
// resumable prefix.
func downloadFileParallel(ctx context.Context, cancel context.CancelFunc, client apphttp.Client[any], src, dst string, f *os.File, w io.Writer, res *http.Response, offset, total int64, progress io.Writer) (err error) {
	directory := downloadPartsPath(dst)
	if err := os.Mkdir(directory, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", directory, err)
	}

	defer func() {
		if cleanupErr := os.RemoveAll(directory); cleanupErr != nil {
			err = joinCleanupError(err, "remove "+directory, cleanupErr)
		}
	}()

	chunkSize := (total - offset) / parallelDownloadCount
	validator := downloadValidator(res)

	var (
		workers  sync.WaitGroup
		failures [parallelDownloadCount - 1]error
	)

	for index := range parallelDownloadCount - 1 {
		workers.Add(1)

		go func() {
			defer workers.Done()

			start := offset + chunkSize*int64(index+1)
			end := start + chunkSize - 1

			if index == parallelDownloadCount-2 {
				end = total - 1
			}

			path := filepath.Join(directory, fmt.Sprintf("%d", index))
			failures[index] = downloadFileRange(ctx, client, src, path, start, end, total, validator, progress)

			if failures[index] != nil {
				cancel()
			}
		}()
	}

	_, copyErr := io.CopyN(w, res.Body, chunkSize)
	// The initial request covers the entire remainder. Stop reading it once its
	// first quarter is written; the other requests supply the remaining ranges.
	_ = res.Body.Close()

	if copyErr != nil {
		cancel()
	}

	workers.Wait()

	for _, failure := range failures {
		if failure != nil {
			return failure
		}
	}

	if copyErr != nil {
		return fmt.Errorf("fetch first range: %w", copyErr)
	}

	for index := range parallelDownloadCount - 1 {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("download canceled: %w", err)
		}

		path := filepath.Join(directory, fmt.Sprintf("%d", index))
		if err := appendDownloadPart(f, path); err != nil {
			return err
		}
	}

	return nil
}

func downloadFileRange(ctx context.Context, client apphttp.Client[any], src, dst string, start, end, total int64, validator string, progress io.Writer) (err error) {
	req, err := client.NewRequest(http.MethodGet, src, nil)
	if err != nil {
		return err
	}

	req = req.WithContext(ctx)
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", start, end))

	if validator != "" {
		req.Header.Set("If-Range", validator)
	}

	res, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("fetch range: %w", err)
	}

	defer res.Body.Close()

	_, length, size, _, err := downloadResponseRange(res, start)
	if err != nil {
		return err
	}

	if res.StatusCode != http.StatusPartialContent || length != end-start+1 || size != total {
		return fmt.Errorf("fetch: unexpected range %q", res.Header.Get("Content-Range"))
	}

	if encoding := res.Header.Get("Content-Encoding"); encoding != "" && !strings.EqualFold(encoding, "identity") {
		return fmt.Errorf("fetch: unexpected content encoding %q", encoding)
	}

	if etag := res.Header.Get("ETag"); validator != "" && etag != "" && etag != validator {
		return fmt.Errorf("fetch: validator changed from %q to %q", validator, etag)
	}

	f, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("open %s: %w", dst, err)
	}

	defer func() {
		if closeErr := f.Close(); closeErr != nil {
			err = joinCleanupError(err, "close "+dst, closeErr)
		}
	}()

	var w io.Writer = f
	if progress != nil {
		w = io.MultiWriter(f, progress)
	}

	written, err := io.Copy(w, io.LimitReader(res.Body, length+1))
	if err != nil {
		return fmt.Errorf("write %s: %w", dst, err)
	}

	if written != length {
		return fmt.Errorf("write %s: %w", dst, io.ErrUnexpectedEOF)
	}

	return nil
}

func appendDownloadPart(dst io.Writer, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}

	_, copyErr := io.Copy(dst, f)
	closeErr := f.Close()

	if copyErr != nil {
		return fmt.Errorf("append %s: %w", path, copyErr)
	}

	if closeErr != nil {
		return fmt.Errorf("close %s: %w", path, closeErr)
	}

	if err := os.Remove(path); err != nil {
		return fmt.Errorf("remove %s: %w", path, err)
	}

	return nil
}
