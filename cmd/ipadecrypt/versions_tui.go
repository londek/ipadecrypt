package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/londek/ipadecrypt/internal/appstore"
	"github.com/londek/ipadecrypt/internal/config"
	"github.com/londek/ipadecrypt/internal/tui"
	"golang.org/x/term"
)

const (
	versionsFetchWorkers = 2
	versionsEagerFetch   = 3
)

type rowState int

const (
	rowUnfetched rowState = iota
	rowPending            // in queue or being fetched
	rowFetched
	rowError
)

type versionsRow struct {
	extVerID string
	state    rowState
	meta     cachedVersion
	errMsg   string

	// predicted holds bracket-matched guesses for rows where state is
	// rowUnfetched: when the nearest fetched row above (newer) and the
	// nearest fetched row below (older) agree on a field, we copy that
	// value in. Rendered with a trailing "?".
	predicted cachedVersion
}

type fetchResult struct {
	extVerID string
	meta     appstore.VersionMetadata
	err      error
}

type versionsUI struct {
	cfg       *config.Config
	as        *appstore.Client
	app       appstore.App
	cachePath string
	logPath   string

	cache   *versionsCache
	cacheMu sync.Mutex

	rows           []versionsRow
	cursor         int
	offset         int
	latestExtVerID string
	totalVersions  int

	queued map[string]struct{}

	tick int
}

func runVersionsTUI(cfg *config.Config, as *appstore.Client, app appstore.App, list appstore.ListVersionsOutput, cache *versionsCache, cachePath, logPath string) error {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return fmt.Errorf("versions: stdin is not a terminal")
	}

	// Apple returns oldest -> newest. Show newest on top.
	ids := list.ExternalVersionIDs
	reversed := make([]string, len(ids))
	for i, id := range ids {
		reversed[len(ids)-1-i] = id
	}

	rows := make([]versionsRow, len(reversed))
	for i, id := range reversed {
		r := versionsRow{extVerID: id, state: rowUnfetched}
		if cv, ok := cache.Versions[id]; ok {
			r.state = rowFetched
			r.meta = cv
		}
		rows[i] = r
	}

	ui := &versionsUI{
		cfg:            cfg,
		as:             as,
		app:            app,
		cachePath:      cachePath,
		logPath:        logPath,
		cache:          cache,
		rows:           rows,
		latestExtVerID: list.LatestExternalVersionID,
		totalVersions:  len(rows),
		queued:         map[string]struct{}{},
	}

	ui.rebuildPredictions()

	old, err := term.MakeRaw(fd)
	if err != nil {
		return err
	}
	defer term.Restore(fd, old)

	w := tui.Out
	// Enter alt screen, hide cursor.
	fmt.Fprint(w, "\x1b[?1049h\x1b[?25l")
	defer fmt.Fprint(w, "\x1b[?25h\x1b[?1049l")

	queue := make(chan string, 256)
	results := make(chan fetchResult, versionsFetchWorkers)
	done := make(chan struct{})

	var wg sync.WaitGroup
	for i := 0; i < versionsFetchWorkers; i++ {
		wg.Add(1)
		go ui.fetchWorker(queue, results, &wg)
	}

	inputCh := make(chan []byte, 8)
	go ui.readInput(inputCh, done)

	// Eager-fetch only the top N rows (the N latest versions).
	// Already-cached rows among those stay cached; we do not scan past
	// them looking for older unfetched rows.
	for i := 0; i < len(ui.rows) && i < versionsEagerFetch; i++ {
		if ui.rows[i].state == rowUnfetched {
			ui.enqueue(ui.rows[i].extVerID, queue)
		}
	}

	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	ui.render()

loop:
	for {
		select {
		case buf := <-inputCh:
			if ui.handleInput(buf, queue) {
				break loop
			}
			// Drain any other input bytes that already queued up (e.g.
			// autorepeat on a held arrow key) before we spend time
			// rendering - one redraw covers them all.
		drain:
			for {
				select {
				case buf = <-inputCh:
					if ui.handleInput(buf, queue) {
						break loop
					}
				default:
					break drain
				}
			}
			ui.render()

		case res := <-results:
			ui.applyResult(res)
			ui.render()

		case <-ticker.C:
			ui.tick++
			// Only redraw if a row is pending (spinner animation).
			if ui.hasPending() {
				ui.render()
			}
		}
	}

	close(done)
	close(queue)
	// Drain results from in-flight fetches so workers can exit.
	drain := make(chan struct{})
	go func() {
		wg.Wait()
		close(drain)
	}()
	for {
		select {
		case res := <-results:
			ui.applyResult(res)
		case <-drain:
			return nil
		}
	}
}

func (ui *versionsUI) enqueue(extVerID string, queue chan<- string) {
	if _, ok := ui.queued[extVerID]; ok {
		return
	}
	ui.queued[extVerID] = struct{}{}
	for i := range ui.rows {
		if ui.rows[i].extVerID == extVerID {
			ui.rows[i].state = rowPending
			ui.rows[i].errMsg = ""
			break
		}
	}
	queue <- extVerID
}

func (ui *versionsUI) applyResult(res fetchResult) {
	delete(ui.queued, res.extVerID)

	for i := range ui.rows {
		if ui.rows[i].extVerID != res.extVerID {
			continue
		}
		if res.err != nil {
			ui.rows[i].state = rowError
			ui.rows[i].errMsg = res.err.Error()
			return
		}
		cv := cachedVersion{
			FetchedAt:        time.Now().UTC(),
			DisplayVersion:   res.meta.DisplayVersion,
			BundleVersion:    res.meta.BundleVersion,
			SupportedDevices: res.meta.SupportedDevices,
			ReleaseDate:      res.meta.ReleaseDate,
			Raw:              res.meta.Raw,
		}
		ui.rows[i].state = rowFetched
		ui.rows[i].meta = cv
		ui.rebuildPredictions()

		// Update in-memory cache and persist. We own the file, so no
		// need to re-read it from disk to merge.
		ui.cacheMu.Lock()
		ui.cache.Versions[res.meta.ExternalVersionID] = cv
		_ = ui.cache.save(ui.cachePath)
		ui.cacheMu.Unlock()
		return
	}
}

func (ui *versionsUI) hasPending() bool {
	return len(ui.queued) > 0
}

// rebuildPredictions fills each unfetched row's `predicted.DisplayVersion`
// with a best-effort guess based on nearby fetched rows. Predictions are
// approximate - they exist to give the reader a rough sense of what
// version to expect at a given row, not to be relied on.
//
// Three kinds of fill happen:
//   - between pairs of fetched rows -> monotonicVersionFill
//   - above the first fetched row -> extrapolate upward with +1 minor/row
//   - below the last fetched row  -> extrapolate downward with -1 minor/row
func (ui *versionsUI) rebuildPredictions() {
	for i := range ui.rows {
		ui.rows[i].predicted = cachedVersion{}
	}

	n := len(ui.rows)

	// Collect indices of fetched rows in display order (newest first).
	var fetched []int
	for i := 0; i < n; i++ {
		if ui.rows[i].state == rowFetched {
			fetched = append(fetched, i)
		}
	}
	if len(fetched) == 0 {
		return
	}

	// Head: extrapolate upward from the first fetched row.
	firstIdx := fetched[0]
	if firstIdx > 0 {
		if nm, ok := parseSemver3(ui.rows[firstIdx].meta.DisplayVersion); ok {
			for i := firstIdx - 1; i >= 0; i-- {
				offset := firstIdx - i
				minor := nm[1] + offset
				ui.rows[i].predicted.DisplayVersion = fmt.Sprintf("%d.%d.0", nm[0], minor)
			}
		}
	}

	// Between pairs.
	for k := 0; k < len(fetched)-1; k++ {
		a, b := fetched[k], fetched[k+1]
		gap := b - a - 1
		if gap == 0 {
			continue
		}
		guesses := monotonicVersionFill(ui.rows[a].meta.DisplayVersion, ui.rows[b].meta.DisplayVersion, gap)
		for i, g := range guesses {
			if g != "" {
				ui.rows[a+1+i].predicted.DisplayVersion = g
			}
		}
	}

	// Tail: extrapolate downward from the last fetched row.
	lastIdx := fetched[len(fetched)-1]
	if lastIdx < n-1 {
		if om, ok := parseSemver3(ui.rows[lastIdx].meta.DisplayVersion); ok {
			for i := lastIdx + 1; i < n; i++ {
				offset := i - lastIdx
				minor := om[1] - offset
				if minor < 0 {
					break
				}
				ui.rows[i].predicted.DisplayVersion = fmt.Sprintf("%d.%d.0", om[0], minor)
			}
		}
	}
}

// monotonicVersionFill fills a gap of `slots` unfetched rows between
// `newer` (above) and `older` (below) with plausible version strings,
// strictly monotonically decreasing.
//
// The algorithm builds an ordered "descent path" of version tuples
// strictly between the two bounds (patch-descent within newer's minor,
// then each intermediate minor at patch 0) and then samples it:
//
//   - slots <= len(path): even-spaced pick. Each slot gets the candidate
//     at its proportional position in the descent, so the guesses spread
//     across the whole range rather than piling up near newer.
//   - slots > len(path): copy the whole path, then fill remaining bottom
//     slots with ascending hotfix patches of the older bound (cross-minor
//     only - same-minor has no more tuples to invent).
//
// Predictions are approximate by design - the `?` suffix on the rendered
// cell signals that. Safe on parse failures and cross-major bounds
// (returns blanks, never crashes).
func monotonicVersionFill(newer, older string, slots int) []string {
	out := make([]string, slots)
	if slots <= 0 {
		return out
	}
	nm, ok1 := parseSemver3(newer)
	om, ok2 := parseSemver3(older)
	if !ok1 || !ok2 {
		return out
	}
	if newer == older {
		for i := range out {
			out[i] = newer
		}
		return out
	}
	if nm[0] != om[0] {
		return out
	}
	if nm[1] < om[1] || (nm[1] == om[1] && nm[2] <= om[2]) {
		return out
	}

	// Descent path, highest-first, strictly between newer and older.
	path := make([]string, 0, 16)
	if nm[1] == om[1] {
		for p := nm[2] - 1; p > om[2]; p-- {
			path = append(path, fmt.Sprintf("%d.%d.%d", nm[0], nm[1], p))
		}
	} else {
		if nm[2] > 0 {
			for p := nm[2] - 1; p >= 0; p-- {
				path = append(path, fmt.Sprintf("%d.%d.%d", nm[0], nm[1], p))
			}
		}
		for m := nm[1] - 1; m > om[1]; m-- {
			path = append(path, fmt.Sprintf("%d.%d.0", nm[0], m))
		}
	}

	n := len(path)
	switch {
	case n == 0:
		// No strict intermediate tuples. Fill as hotfixes of older.
		if nm[1] > om[1] {
			for i := 0; i < slots; i++ {
				hotfixPatch := om[2] + (slots - i)
				out[i] = fmt.Sprintf("%d.%d.%d", om[0], om[1], hotfixPatch)
			}
		}

	case slots <= n:
		// Even-spaced sample: slot i (0-indexed) picks path index
		// floor(n * (2i+1) / (2*slots)). Centers each slot in its share
		// of the path; produces strictly monotonic output for any n.
		lastIdx := -1
		for i := 0; i < slots; i++ {
			idx := (n * (2*i + 1)) / (2 * slots)
			if idx <= lastIdx {
				idx = lastIdx + 1
			}
			if idx >= n {
				idx = n - 1
			}
			out[i] = path[idx]
			lastIdx = idx
		}

	default:
		// slots > n. Copy path into top slots, fill the rest with
		// hotfixes of older at the bottom.
		for i, c := range path {
			out[i] = c
		}
		if nm[1] > om[1] {
			remaining := slots - n
			for i := 0; i < remaining; i++ {
				hotfixPatch := om[2] + (remaining - i)
				out[n+i] = fmt.Sprintf("%d.%d.%d", om[0], om[1], hotfixPatch)
			}
		}
	}

	return out
}

// parseSemver3 returns (major, minor, patch) for strings like
// "5.96.2" / "5.96" / "5" / "107.4.51.3" (takes the first three
// numeric components). Non-numeric suffix or missing components yield
// ok=false, so callers gracefully skip the row.
func parseSemver3(s string) ([3]int, bool) {
	if s == "" {
		return [3]int{}, false
	}
	parts := strings.Split(s, ".")
	if len(parts) < 1 {
		return [3]int{}, false
	}
	var out [3]int
	for i := 0; i < 3; i++ {
		if i >= len(parts) {
			// Missing component treated as 0 (e.g. "5" -> 5.0.0).
			out[i] = 0
			continue
		}
		n, err := strconv.Atoi(parts[i])
		if err != nil || n < 0 {
			return [3]int{}, false
		}
		out[i] = n
	}
	return out, true
}

func (ui *versionsUI) fetchWorker(queue <-chan string, results chan<- fetchResult, wg *sync.WaitGroup) {
	defer wg.Done()
	for extVerID := range queue {
		meta, err := getVersionMetadataWithAuth(ui.cfg, ui.as, ui.app, extVerID)
		if err == nil {
			logVersionsResponse(ui.logPath, "get_version_metadata", ui.app.BundleID, extVerID, meta.Raw)
		}
		results <- fetchResult{extVerID: extVerID, meta: meta, err: err}
	}
}

func (ui *versionsUI) readInput(out chan<- []byte, done <-chan struct{}) {
	for {
		buf := make([]byte, 8)
		// Stdin is in raw mode; Read returns on any byte(s). When `done`
		// is closed we stop sending, but Read itself can't be cancelled
		// portably - if that happens the final byte is dropped.
		n, err := os.Stdin.Read(buf)
		if err != nil || n == 0 {
			return
		}
		select {
		case out <- buf[:n]:
		case <-done:
			return
		}
	}
}

// handleInput returns true when the caller should exit the loop.
func (ui *versionsUI) handleInput(buf []byte, queue chan<- string) bool {
	if len(buf) == 0 {
		return false
	}

	// Escape sequences: ESC [ A/B/C/D, ESC [ 5~ / 6~.
	if buf[0] == 0x1b {
		if len(buf) == 1 {
			// Plain Esc = quit.
			return true
		}
		if len(buf) >= 3 && buf[1] == '[' {
			switch buf[2] {
			case 'A': // up
				ui.moveCursor(-1)
			case 'B': // down
				ui.moveCursor(1)
			case '5': // PgUp: ESC [ 5 ~
				ui.moveCursor(-ui.pageSize())
			case '6': // PgDown: ESC [ 6 ~
				ui.moveCursor(ui.pageSize())
			}
		}
		return false
	}

	switch buf[0] {
	case 'q', 0x03, 0x04: // q, Ctrl-C, Ctrl-D
		return true
	case '\r', '\n':
		if ui.cursor >= 0 && ui.cursor < len(ui.rows) {
			r := ui.rows[ui.cursor]
			if r.state == rowUnfetched || r.state == rowError {
				ui.enqueue(r.extVerID, queue)
			}
		}
	case 'k':
		ui.moveCursor(-1)
	case 'j':
		ui.moveCursor(1)
	case 'g':
		ui.cursor = 0
		ui.offset = 0
	case 'G':
		ui.cursor = len(ui.rows) - 1
	}
	return false
}

func (ui *versionsUI) moveCursor(delta int) {
	if len(ui.rows) == 0 {
		return
	}
	ui.cursor += delta
	if ui.cursor < 0 {
		ui.cursor = 0
	}
	if ui.cursor >= len(ui.rows) {
		ui.cursor = len(ui.rows) - 1
	}
}

func (ui *versionsUI) pageSize() int {
	_, h := ui.termSize()
	// Leave room for header (3 lines) + column header (1) + footer (2).
	n := h - 6
	if n < 1 {
		n = 1
	}
	return n
}

func (ui *versionsUI) termSize() (int, int) {
	f, ok := tui.Out.(*os.File)
	if !ok {
		return 100, 30
	}
	w, h, err := term.GetSize(int(f.Fd()))
	if err != nil || w <= 0 || h <= 0 {
		return 100, 30
	}
	return w, h
}

// ---- rendering ----------------------------------------------------------

var spinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

func (ui *versionsUI) render() {
	w, h := ui.termSize()

	// Adjust viewport so cursor is visible.
	rowsHeight := h - 6
	if rowsHeight < 1 {
		rowsHeight = 1
	}
	if ui.cursor < ui.offset {
		ui.offset = ui.cursor
	}
	if ui.cursor >= ui.offset+rowsHeight {
		ui.offset = ui.cursor - rowsHeight + 1
	}
	if ui.offset < 0 {
		ui.offset = 0
	}

	// Single pre-sized builder, home cursor, no screen wipe - each line
	// is terminated with CSI K (clear-to-EOL) so stale content under the
	// new bytes is erased in-place. After the last line we emit CSI J
	// to erase anything below. This avoids the full-screen flash that
	// CSI 2J causes on slow terminals / SSH links.
	b := strings.Builder{}
	b.Grow(4096)
	b.WriteString("\x1b[H")

	// Header: app name (bold), then bundleId / latest / counts (dim).
	b.WriteString("  \x1b[1m")
	b.WriteString(truncateVisible(ui.app.Name, w-4))
	b.WriteString("\x1b[0m\x1b[K\r\n")

	pending := len(ui.queued)
	cached := 0
	for _, r := range ui.rows {
		if r.state == rowFetched {
			cached++
		}
	}
	summary := fmt.Sprintf("%s  ·  latest %s  ·  %d versions (%d cached, %d pending)",
		ui.app.BundleID, ui.latestExtVerID, ui.totalVersions, cached, pending)
	b.WriteString("  \x1b[2m")
	b.WriteString(truncateVisible(summary, w-4))
	b.WriteString("\x1b[0m\x1b[K\r\n\x1b[K\r\n")

	// Column header.
	colIDW := 13
	colVerW := 14
	colBuildW := 14
	colDevW := 14

	b.WriteString("  \x1b[2m")
	fmt.Fprintf(&b, "    %-*s  %-*s  %-*s  %-*s",
		colIDW, "externalId",
		colVerW, "version",
		colBuildW, "build",
		colDevW, "devices")
	b.WriteString("\x1b[0m\x1b[K\r\n")

	end := ui.offset + rowsHeight
	if end > len(ui.rows) {
		end = len(ui.rows)
	}
	for i := ui.offset; i < end; i++ {
		r := ui.rows[i]
		selected := i == ui.cursor
		ui.writeRow(&b, r, selected, colIDW, colVerW, colBuildW, colDevW)
	}

	// Footer (no padding lines - the CSI J below erases anything left).
	b.WriteString("\x1b[K\r\n  \x1b[2m")
	footer := "↑/↓ navigate  ·  PgUp/PgDn jump  ·  Enter fetch metadata  ·  q quit"
	b.WriteString(truncateVisible(footer, w-4))
	b.WriteString("\x1b[0m\x1b[K")

	// Clear anything below the footer left over from a previous, taller render.
	b.WriteString("\x1b[J")

	fmt.Fprint(tui.Out, b.String())
}

func (ui *versionsUI) writeRow(b *strings.Builder, r versionsRow, selected bool, colIDW, colVerW, colBuildW, colDevW int) {
	var icon, version, build, devices, note string
	versionDim := false

	switch r.state {
	case rowFetched:
		icon = "\x1b[32m✓\x1b[0m"
		version = r.meta.DisplayVersion
		build = r.meta.BundleVersion
		devices = formatDeviceIDs(r.meta.SupportedDevices)
	case rowPending:
		icon = "\x1b[36m" + spinnerFrames[ui.tick%len(spinnerFrames)] + "\x1b[0m"
		version = "…"
		build = "…"
		devices = "…"
	case rowError:
		icon = "\x1b[31m✗\x1b[0m"
		version = "err"
		note = r.errMsg
	default:
		icon = "\x1b[2m·\x1b[0m"
		if r.predicted.DisplayVersion != "" {
			version = r.predicted.DisplayVersion + "?"
			versionDim = true
		} else {
			version = "—"
		}
		build = "—"
		devices = "—"
	}

	cursor := " "
	if selected {
		cursor = "\x1b[36;1m▸\x1b[0m"
	}

	idCol := padOrTrim(r.extVerID, colIDW)
	version = padOrTrim(version, colVerW)
	build = padOrTrim(build, colBuildW)
	devices = padOrTrim(devices, colDevW)

	if versionDim {
		version = "\x1b[90m" + version + "\x1b[0m"
	}

	line := fmt.Sprintf("  %s %s %s  %s  %s  %s  %s",
		cursor,
		icon,
		idCol,
		version,
		build,
		devices,
		note)

	if selected {
		b.WriteString("\x1b[1m")
	}
	b.WriteString(line)
	if selected {
		b.WriteString("\x1b[0m")
	}
	b.WriteString("\x1b[K\r\n")
}

func formatDeviceIDs(ids []int) string {
	if len(ids) == 0 {
		return ""
	}
	parts := make([]string, len(ids))
	for i, n := range ids {
		parts[i] = fmt.Sprintf("%d", n)
	}
	return strings.Join(parts, ",")
}

// padOrTrim returns s padded or truncated to exactly width runes (ignoring
// ANSI escapes in s - callers should pass plain text).
func padOrTrim(s string, width int) string {
	n := 0
	for range s {
		n++
	}
	if n == width {
		return s
	}
	if n < width {
		return s + strings.Repeat(" ", width-n)
	}
	// Trim.
	out := make([]rune, 0, width)
	i := 0
	for _, r := range s {
		if i >= width-1 {
			break
		}
		out = append(out, r)
		i++
	}
	out = append(out, '…')
	return string(out)
}

func truncateVisible(s string, max int) string {
	if max <= 0 {
		return ""
	}
	n := 0
	for range s {
		n++
	}
	if n <= max {
		return s
	}
	out := make([]rune, 0, max)
	i := 0
	for _, r := range s {
		if i >= max-1 {
			break
		}
		out = append(out, r)
		i++
	}
	out = append(out, '…')
	return string(out)
}
