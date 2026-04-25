package main

import (
	"io"
	"time"
)

const progressTick = 100 * time.Millisecond

type progressReader struct {
	r          io.Reader
	total      int64
	read       int64
	last       time.Time
	onProgress func(cur, total int64)
}

func newProgressReader(r io.Reader, total int64, onProgress func(cur, total int64)) *progressReader {
	return &progressReader{r: r, total: total, onProgress: onProgress}
}

func (p *progressReader) Read(b []byte) (int, error) {
	n, err := p.r.Read(b)
	if n > 0 {
		p.read += int64(n)
		if now := time.Now(); now.Sub(p.last) >= progressTick {
			p.last = now
			p.onProgress(p.read, p.total)
		}
	}
	if err == io.EOF {
		p.onProgress(p.read, p.total)
	}

	return n, err
}

type progressWriter struct {
	w          io.Writer
	total      int64
	written    int64
	last       time.Time
	onProgress func(cur, total int64)
}

func newProgressWriter(w io.Writer, total int64, onProgress func(cur, total int64)) *progressWriter {
	return &progressWriter{w: w, total: total, onProgress: onProgress}
}

func (p *progressWriter) Write(b []byte) (int, error) {
	n, err := p.w.Write(b)
	if n > 0 {
		p.written += int64(n)
		if now := time.Now(); now.Sub(p.last) >= progressTick {
			p.last = now
			p.onProgress(p.written, p.total)
		}
	}

	return n, err
}

// Flush emits a final progress callback with the current byte count. Callers
// invoke after Download returns to ensure the UI shows 100%.
func (p *progressWriter) Flush() {
	p.onProgress(p.written, p.total)
}
