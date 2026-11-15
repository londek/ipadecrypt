package machine

import (
	"testing"

	"github.com/londek/ipadecrypt/internal/sap/unicorn"
)

func TestContentStreams(t *testing.T) {
	m := newServiceTestMachine(t)
	v := &contentFS{files: map[string][]byte{}}
	if err := v.installStreams(m.services); err != nil {
		t.Fatal(err)
	}
	call := func(name string, args ...uint64) uint64 {
		t.Helper()
		result, err := m.invoke(m.services.symbols[name], args...)
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	path := []byte("/private/var/db/fpsd/SC Info/SC Info.sidb")
	p := scratchBase + 0x1000
	buffer := scratchBase + 0x2000
	if err := m.engine.MemWrite(p, path); err != nil {
		t.Fatal(err)
	}
	u := call("_CFURLCreateFromFileSystemRepresentation", 0, p, uint64(len(path)), 0)
	r := call("_CFReadStreamCreateWithFile", 0, u)
	if call("_CFReadStreamOpen", r) != 0 || len(v.files) != 0 {
		t.Fatal("missing virtual file must not open/create/read host")
	}
	if call("_CFReadStreamGetError", r) != 1 {
		t.Fatal("missing file error domain")
	}
	e, _ := m.engine.RegRead(unicorn.RegX1)
	if e != 2 {
		t.Fatal("missing ENOENT")
	}
	w := call("_CFWriteStreamCreateWithFile", 0, u)
	if call("_CFWriteStreamOpen", w) != 1 {
		t.Fatal("write open failed")
	}
	if err := m.engine.MemWrite(buffer, []byte("hello")); err != nil {
		t.Fatal(err)
	}
	if call("_CFWriteStreamWrite", w, buffer, 5) != 5 {
		t.Fatal("write failed")
	}
	call("_CFWriteStreamClose", w)
	r = call("_CFReadStreamCreateWithFile", 0, u)
	if call("_CFReadStreamOpen", r) != 1 {
		t.Fatal("read open failed")
	}
	if call("_CFReadStreamRead", r, buffer, 3) != 3 || call("_CFReadStreamRead", r, buffer+3, 8) != 2 || call("_CFReadStreamRead", r, buffer+5, 8) != 0 {
		t.Fatal("partial read/EOF failed")
	}
	b, _ := m.engine.MemRead(buffer, 5)
	if string(b) != "hello" {
		t.Fatalf("bad stream data %q", b)
	}
	// A reader whose offset is beyond a newly truncated file must report EOF,
	// not convert a negative Go length into a huge guest transfer count.
	r = call("_CFReadStreamCreateWithFile", 0, u)
	call("_CFReadStreamOpen", r)
	call("_CFReadStreamRead", r, buffer, 3)
	w = call("_CFWriteStreamCreateWithFile", 0, u)
	call("_CFWriteStreamOpen", w)
	if call("_CFReadStreamRead", r, buffer, 3) != 0 {
		t.Fatal("read after truncation did not return EOF")
	}
	if _, err := m.invoke(m.services.symbols["_CFWriteStreamWrite"], r, buffer, 1); err == nil {
		t.Fatal("wrote through a read-only stream")
	}
}
