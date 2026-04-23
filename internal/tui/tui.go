// Package tui is the single-stop terminal UI for ipadecrypt. Everything - status
// lines, prompts, spinners, progress bars, result blocks - writes to Out
// (stderr by default) so that stdout is reserved for data (e.g. the final
// decrypted IPA path).
package tui

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"golang.org/x/term"
)

var Out io.Writer = os.Stderr

const (
	ansiReset = "\x1b[0m"
	ansiDim   = "\x1b[2m"
	ansiBold  = "\x1b[1m"
	ansiGreen = "\x1b[32m"
	ansiRed   = "\x1b[31m"
	ansiAmber = "\x1b[33m"
	ansiCyan  = "\x1b[36m"
)

func IsTTY() bool {
	f, ok := Out.(*os.File)
	if !ok {
		return false
	}
	return term.IsTerminal(int(f.Fd()))
}

func useColor() bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	return IsTTY()
}

func paint(code, s string) string {
	if useColor() {
		return code + s + ansiReset
	}
	return s
}

// ---- status lines ------------------------------------------------------

func Spacer() { fmt.Fprintln(Out) }

// Step prints a wizard-style step header with a leading blank line.
func Step(n, total int, title string) {
	head := fmt.Sprintf("Step %d/%d · %s", n, total, title)
	fmt.Fprintln(Out)
	if useColor() {
		fmt.Fprintln(Out, paint(ansiCyan+ansiBold, "▎")+" "+paint(ansiBold, head))
	} else {
		fmt.Fprintln(Out, "== "+head+" ==")
	}
}

// Info prints dim indented prose. Multi-line strings render as multiple lines.
func Info(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	for _, line := range strings.Split(msg, "\n") {
		fmt.Fprintln(Out, "  "+paint(ansiDim, line))
	}
}

// Bullet prints a further-indented "•" line under an Info paragraph.
func Bullet(format string, args ...any) {
	fmt.Fprintln(Out, "    "+paint(ansiDim, "• "+fmt.Sprintf(format, args...)))
}

// Fields renders aligned "key: value" pairs. Call as Fields(k1, v1, k2, v2, …).
// Pairs where the value is empty are skipped so callers can include optional
// fields without branching.
func Fields(kv ...string) {
	if len(kv)%2 != 0 {
		return
	}
	var rows [][2]string
	for i := 0; i < len(kv); i += 2 {
		if kv[i+1] == "" {
			continue
		}
		rows = append(rows, [2]string{kv[i], kv[i+1]})
	}
	if len(rows) == 0 {
		return
	}
	maxKey := 0
	for _, r := range rows {
		if len(r[0]) > maxKey {
			maxKey = len(r[0])
		}
	}
	for _, r := range rows {
		pad := strings.Repeat(" ", maxKey-len(r[0]))
		fmt.Fprintln(Out, "    "+paint(ansiDim, r[0]+":")+pad+"  "+r[1])
	}
}

func OK(format string, args ...any)   { status(ansiGreen, "✓", "[ok]", format, args...) }
func Warn(format string, args ...any) { status(ansiAmber, "!", "[warn]", format, args...) }
func Err(format string, args ...any)  { status(ansiRed, "✗", "[err]", format, args...) }

func status(color, glyph, plain, format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	var line string
	if useColor() {
		line = "  " + paint(color+ansiBold, glyph) + " " + msg
	} else {
		line = "  " + plain + " " + msg
	}
	fmt.Fprintln(Out, truncate(line, width()))
}

// Erase moves the cursor up n lines and clears from there to the end of the
// screen, so the next render replaces the previous one in place. No-op on
// non-TTY. Every status/prompt line counted must not wrap (status auto-
// truncates; PressEnter is short enough in practice).
func Erase(n int) {
	if !IsTTY() || n <= 0 {
		return
	}
	fmt.Fprintf(Out, "\x1b[%dA\x1b[0J", n)
}

// ---- prompts -----------------------------------------------------------

// Prompt asks for free-form input. Label is displayed without a trailing colon;
// Prompt adds ": " itself.
func Prompt(label string) (string, error) {
	writePrompt(label)
	s, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && err != io.EOF {
		return "", err
	}
	return strings.TrimRight(strings.TrimRight(s, "\n"), "\r"), nil
}

// PromptDefault is Prompt but offers a fallback if the user hits Enter.
func PromptDefault(label, def string) (string, error) {
	shown := label
	if def != "" {
		shown = fmt.Sprintf("%s [%s]", label, def)
	}
	s, err := Prompt(shown)
	if err != nil {
		return "", err
	}
	if s == "" {
		return def, nil
	}
	return s, nil
}

// PromptPassword reads a line without echoing. Falls back to visible input
// when stdin isn't a TTY (e.g. piped).
func PromptPassword(label string) (string, error) {
	writePrompt(label)
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		s, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && err != io.EOF {
			return "", err
		}
		return strings.TrimRight(strings.TrimRight(s, "\n"), "\r"), nil
	}
	pw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(Out)
	if err != nil {
		return "", err
	}
	return string(pw), nil
}

// Select renders an arrow-key-navigable list and returns the chosen index.
// Enter confirms, Ctrl-C aborts. Falls back to the first option when stdin
// isn't a TTY.
func Select(label string, options []string) (int, error) {
	if len(options) == 0 {
		return -1, fmt.Errorf("select: no options")
	}
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return 0, nil
	}

	old, err := term.MakeRaw(fd)
	if err != nil {
		return -1, err
	}
	defer term.Restore(fd, old)

	cursor := 0
	draw := func(first bool) {
		if !first {
			fmt.Fprintf(Out, "\x1b[%dA", len(options)+1)
		}
		fmt.Fprint(Out, "\r\x1b[K  "+paint(ansiCyan, "▸")+" "+label+"\r\n")
		for i, opt := range options {
			fmt.Fprint(Out, "\r\x1b[K")
			if i == cursor {
				fmt.Fprint(Out, "    "+paint(ansiCyan, "›")+" "+paint(ansiBold, opt))
			} else {
				fmt.Fprint(Out, "      "+paint(ansiDim, opt))
			}
			fmt.Fprint(Out, "\r\n")
		}
	}

	draw(true)

	buf := make([]byte, 3)
	for {
		n, err := os.Stdin.Read(buf)
		if err != nil {
			return -1, err
		}
		if n == 0 {
			continue
		}
		switch {
		case buf[0] == '\r' || buf[0] == '\n':
			return cursor, nil
		case buf[0] == 0x03: // Ctrl-C
			return -1, fmt.Errorf("aborted")
		case buf[0] == 0x04: // Ctrl-D
			return -1, io.EOF
		case n == 3 && buf[0] == 0x1b && buf[1] == '[':
			switch buf[2] {
			case 'A': // up
				if cursor > 0 {
					cursor--
				}
			case 'B': // down
				if cursor < len(options)-1 {
					cursor++
				}
			}
			draw(false)
		case buf[0] == 'k':
			if cursor > 0 {
				cursor--
				draw(false)
			}
		case buf[0] == 'j':
			if cursor < len(options)-1 {
				cursor++
				draw(false)
			}
		}
	}
}

// PressEnter prints a dim message and waits for the user to hit Enter.
func PressEnter(msg string) error {
	fmt.Fprint(Out, "  "+paint(ansiCyan, "▸")+" "+paint(ansiDim, msg+" (press Enter)")+" ")
	_, err := bufio.NewReader(os.Stdin).ReadString('\n')
	return err
}

func writePrompt(label string) {
	fmt.Fprint(Out, "  "+paint(ansiCyan, "▸")+" "+label+": ")
}

// ---- Live (spinner / progress bar) -------------------------------------

// Live is a single in-place progress line. Exactly one Live should be visible
// at a time; call OK, Fail, or Stop to close it.
type Live struct {
	mu     sync.Mutex
	stop   chan struct{}
	done   chan struct{}
	state  liveState
	tty    bool
	active bool
}

type liveState struct {
	msg      string
	cur, max int64
	hasBar   bool
	detail   string
}

func NewLive() *Live {
	l := &Live{
		stop: make(chan struct{}),
		done: make(chan struct{}),
		tty:  IsTTY(),
	}
	if l.tty {
		l.active = true
		go l.loop()
	} else {
		close(l.done)
	}
	return l
}

func (l *Live) Spin(format string, args ...any) {
	l.setMessage(fmt.Sprintf(format, args...), true)
}

// Message updates the current live-line text without changing whether the
// progress bar is visible.
func (l *Live) Message(format string, args ...any) {
	l.setMessage(fmt.Sprintf(format, args...), false)
}

func (l *Live) Progress(cur, max int64, detail ...string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.state.cur = cur
	l.state.max = max
	l.state.hasBar = true

	if len(detail) > 0 {
		l.state.detail = detail[0]
	} else {
		l.state.detail = ""
	}
}

func (l *Live) setMessage(msg string, clearBar bool) {
	l.mu.Lock()

	prev := l.state
	l.state.msg = msg
	if clearBar {
		l.state.cur = 0
		l.state.max = 0
		l.state.hasBar = false
		l.state.detail = ""
	}

	st := l.state
	tty := l.tty

	l.mu.Unlock()

	if tty || st.msg == prev.msg {
		return
	}

	if !clearBar && prev.hasBar {
		return
	}

	fmt.Fprintln(Out, "  "+st.msg)
}

// Note prints a dim "·" line above the current live line without stopping it.
func (l *Live) Note(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)

	l.mu.Lock()
	defer l.mu.Unlock()

	if l.tty {
		fmt.Fprint(Out, "\r\033[2K")
	}

	fmt.Fprintln(Out, "    "+paint(ansiDim, "· "+msg))
}

func (l *Live) OK(format string, args ...any) {
	l.finish(ansiGreen, "✓", "[ok]", fmt.Sprintf(format, args...))
}

func (l *Live) Fail(format string, args ...any) {
	l.finish(ansiRed, "✗", "[err]", fmt.Sprintf(format, args...))
}

// Stop aborts the live line without printing anything. Idempotent.
func (l *Live) Stop() {
	l.mu.Lock()
	if !l.tty || !l.active {
		l.mu.Unlock()
		return
	}

	l.active = false
	l.mu.Unlock()

	close(l.stop)
	<-l.done

	l.mu.Lock()
	fmt.Fprint(Out, "\r\033[2K")
	l.mu.Unlock()
}

func (l *Live) finish(color, glyph, plain, msg string) {
	l.Stop()

	if useColor() {
		fmt.Fprintln(Out, "  "+paint(color+ansiBold, glyph)+" "+msg)
	} else {
		fmt.Fprintln(Out, "  "+plain+" "+msg)
	}
}

var spinFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

func (l *Live) loop() {
	defer close(l.done)
	t := time.NewTicker(80 * time.Millisecond)
	defer t.Stop()
	i := 0
	for {
		select {
		case <-l.stop:
			return
		case <-t.C:
			i++
			l.render(i)
		}
	}
}

func (l *Live) render(tick int) {
	l.mu.Lock()
	defer l.mu.Unlock()

	fmt.Fprint(Out, "\r\033[2K")
	st := l.state
	frame := spinFrames[tick%len(spinFrames)]
	line := "  " + paint(ansiCyan+ansiBold, frame)

	if st.msg != "" {
		line += " " + st.msg
	}

	if st.hasBar {
		line += " "
		line += renderBar(st.cur, st.max)
		if st.detail != "" {
			line += " " + paint(ansiDim, st.detail)
		}
	}
	fmt.Fprint(Out, truncate(line, width()))
}

func width() int {
	f, ok := Out.(*os.File)
	if !ok {
		return 100
	}

	w, _, err := term.GetSize(int(f.Fd()))
	if err != nil || w <= 0 {
		return 100
	}

	return w
}

func renderBar(cur, max int64) string {
	const W = 20

	if max <= 0 {
		return paint(ansiDim, strings.Repeat("░", W)+" …")
	}

	if cur > max {
		cur = max
	}

	filled := int((cur * int64(W)) / max)
	pct := int((cur * 100) / max)

	return paint(ansiGreen, strings.Repeat("█", filled)) +
		paint(ansiDim, strings.Repeat("░", W-filled)) +
		" " + paint(ansiGreen+ansiBold, fmt.Sprintf("%3d%%", pct))
}

func truncate(s string, max int) string {
	if visibleWidth(s) <= max {
		return s
	}

	var b strings.Builder
	inEsc := false
	visible := 0
	for _, r := range s {
		if r == '\x1b' {
			inEsc = true
			b.WriteRune(r)
			continue
		}

		if inEsc {
			b.WriteRune(r)
			if r == 'm' {
				inEsc = false
			}
			continue
		}

		if visible >= max-1 {
			break
		}

		b.WriteRune(r)
		visible++
	}

	b.WriteString("…" + ansiReset)

	return b.String()
}

func visibleWidth(s string) int {
	n := 0
	inEsc := false
	for _, r := range s {
		if r == '\x1b' {
			inEsc = true
			continue
		}

		if inEsc {
			if r == 'm' {
				inEsc = false
			}
			continue
		}

		n += utf8.RuneLen(r)
	}

	return n
}
