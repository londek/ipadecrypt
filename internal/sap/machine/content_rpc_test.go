package machine

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestContentReceiveOOL(t *testing.T) {
	src, dst := newServiceTestMachine(t), newServiceTestMachine(t)
	payload := []byte("synthetic Mach OOL fixture")
	p, err := src.scratch(payload, uint64(len(payload)))
	if err != nil {
		t.Fatal(err)
	}
	sent := make([]byte, 44)
	put := binary.LittleEndian.PutUint32
	put(sent[0:4], 0x80001513)
	put(sent[4:8], uint32(len(sent)))
	put(sent[8:12], 2)
	put(sent[12:16], 37)
	put(sent[20:24], 1200)
	put(sent[24:28], 1)
	binary.LittleEndian.PutUint64(sent[28:36], p)
	sent[39] = 1
	put(sent[40:44], uint32(len(payload)))
	received, err := contentReceive(src, dst, sent, 1)
	if err != nil {
		t.Fatal(err)
	}
	if binary.LittleEndian.Uint32(received[:4]) != 0x80001112 || binary.LittleEndian.Uint32(received[8:12]) != 37 || binary.LittleEndian.Uint32(received[12:16]) != 1 {
		t.Fatal("wrong received header rights or port roles")
	}
	target := binary.LittleEndian.Uint64(received[28:36])
	if target == p {
		t.Fatal("sender address reused without translation")
	}
	got, err := dst.engine.MemRead(target, uint64(len(payload)))
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatal("OOL data missing from recipient address space")
	}
	if err := dst.engine.MemWrite(target, make([]byte, len(payload))); err != nil {
		t.Fatal(err)
	}
	got, err = src.engine.MemRead(p, uint64(len(payload)))
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatal("recipient write changed sender memory")
	}
	if binary.LittleEndian.Uint64(sent[28:36]) != p || binary.LittleEndian.Uint32(sent[:4]) != 0x80001513 {
		t.Fatal("translation mutated original header")
	}
}

func TestContentReceiveMalformed(t *testing.T) {
	for _, tc := range []struct {
		name    string
		size    int
		count   uint32
		kind    byte
		oolSize uint32
	}{
		{"short header", 23, 0, 0, 0},
		{"missing count", 24, 0, 0, 0},
		{"missing descriptor", 28, 1, 0, 0},
		{"unsupported descriptor", 44, 1, 2, 0},
		{"truncated OOL", 40, 1, 1, 0},
		{"oversized OOL", 44, 1, 1, 16<<20 + 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := make([]byte, tc.size)
			binary.LittleEndian.PutUint32(b[:4], 0x80001513)
			binary.LittleEndian.PutUint32(b[4:8], uint32(len(b)))
			if len(b) >= 28 {
				binary.LittleEndian.PutUint32(b[24:28], tc.count)
			}
			if len(b) >= 40 {
				b[39] = tc.kind
			}
			if len(b) >= 44 {
				binary.LittleEndian.PutUint32(b[40:44], tc.oolSize)
			}
			if _, err := contentReceive(nil, nil, b, 1); err == nil {
				t.Fatal("malformed or unsupported message accepted")
			}
		})
	}
}
