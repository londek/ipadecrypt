package tui

import (
	"bytes"
	"testing"
)

func TestPrimaryListRendering(t *testing.T) {
	previous := Out
	defer func() { Out = previous }()

	var output bytes.Buffer

	Out = &output

	Heading("Example Developer")
	Item("Example App (123)")

	want := "  Example Developer\n    • Example App (123)\n"
	if output.String() != want {
		t.Fatalf("output = %q, want %q", output.String(), want)
	}
}
