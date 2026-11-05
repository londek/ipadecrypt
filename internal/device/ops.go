package device

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"

	"howett.net/plist"
)

//go:embed ipadecrypt-helper-arm64
var helperArm64 []byte

type ProbeResult struct {
	IOSVersion string
	Arch       string // "arm64" or "arm64e"
	Model      string // "iPhone10,2", "iPad7,3", …
	// DeviceFamily mirrors UIDeviceFamily values from Info.plist:
	// 1 = iPhone/iPod, 2 = iPad. 0 if unknown.
	DeviceFamily int
	// Jailbreak is the detected jailbreak: "Dopamine", "palera1n",
	// "checkra1n", "rootless?" (rootless but brand unknown) or "unknown".
	Jailbreak string
}

// classifyJailbreak identifies the ACTIVE jailbreak from the live /var/jb
// symlink target - the hard tell. /var/jb is the rootless prefix every
// modern jb mounts at boot, and its target is the bootstrap that actually
// booted this session, so it reflects what is RUNNING, not what is merely
// installed: a leftover Dopamine.app on a palera1n boot cannot change where
// /var/jb points. We deliberately ignore installed apps/dpkg packages -
// they are stale-prone and not authoritative.
//
// Verified on iPhone10,5 / A11 / Dopamine: target is
// /private/preboot/<hash>/dopamine-<rand>/procursus. roothide Dopamine also
// uses a /var/.jbroot-<hex> scheme. palera1n's rootless bootstrap sits under
// a jb-<rand> dir; checkra1n is rootful (no /var/jb -> preboot link). The
// "dopamine" token is empirically confirmed; the palera1n/checkra1n schemes
// are from their known layouts (no such hardware here to confirm).
func classifyJailbreak(sig string) string {
	f := map[string]string{}

	for _, tok := range strings.Fields(sig) {
		if k, v, ok := strings.Cut(tok, "="); ok {
			f[k] = v
		}
	}

	link := strings.ToLower(f["link"])
	switch {
	case strings.Contains(link, "dopamine") || strings.Contains(link, ".jbroot"):
		return "Dopamine"
	case strings.Contains(link, "palera1n") || strings.Contains(link, "/jb-"):
		return "palera1n"
	case f["vjb"] == "1":
		return "rootless?"
	default:
		return "unknown"
	}
}

func deviceFamilyFromModel(model string) int {
	switch {
	case strings.HasPrefix(model, "iPhone"), strings.HasPrefix(model, "iPod"):
		return 1
	case strings.HasPrefix(model, "iPad"):
		return 2
	default:
		return 0
	}
}

func (c *Client) Probe() (ProbeResult, error) {
	// SSH non-interactive shells on iOS often have a trimmed PATH that omits
	// the sysctl / rootless locations, so try a few absolute paths before
	// giving up. The 2>/dev/null suppresses expected "not found" from the
	// unmatched ones.
	// `uname -m` on iOS always returns "arm64"  Apple doesn't expose
	// the arm64e subtype through the standard syscall. Read cpusubtype
	// directly from the mach header of `/sbin/launchd` (always present,
	// always thin to the device's actual arch). Offset 8 in the
	// mach_header_64 is the cpusubtype low byte: 0x02 = arm64e (PAC),
	// 0x00 or 0x01 = arm64.
	// Line 0: iOS version. Line 1: model. Line 2: launchd cpusubtype byte.
	// Then a "JB ..." line carrying the live /var/jb symlink target - the
	// hard tell for the ACTIVE jailbreak (see classifyJailbreak). An absent
	// or unrecognized jailbreak just yields "unknown"; the probe never fails.
	const script = `sw_vers -productVersion 2>/dev/null || /usr/libexec/PlistBuddy -c 'Print :ProductVersion' /System/Library/CoreServices/SystemVersion.plist 2>/dev/null
(sysctl -n hw.machine 2>/dev/null || /usr/sbin/sysctl -n hw.machine 2>/dev/null || /var/jb/usr/sbin/sysctl -n hw.machine 2>/dev/null || sysctl hw.machine 2>/dev/null | sed 's/^hw.machine: *//' || true)
od -An -tx1 -j8 -N1 /sbin/launchd 2>/dev/null | tr -d ' \n'; echo
VJB=0; [ -e /var/jb ] && VJB=1
LINK=$(readlink /var/jb 2>/dev/null)
printf 'JB link=%s vjb=%s\n' "$LINK" "$VJB"`

	out, _, code, err := c.Run(script)
	if err != nil || code != 0 {
		return ProbeResult{}, fmt.Errorf("probe (exit %d): %w", code, err)
	}

	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")

	var r ProbeResult
	if len(lines) > 0 {
		r.IOSVersion = strings.TrimSpace(lines[0])
	}

	if len(lines) > 1 {
		r.Model = strings.TrimSpace(lines[1])
	}

	if len(lines) > 2 {
		switch strings.TrimSpace(lines[2]) {
		case "02":
			r.Arch = "arm64e"
		default:
			r.Arch = "arm64"
		}
	} else {
		r.Arch = "arm64"
	}

	r.DeviceFamily = deviceFamilyFromModel(r.Model)

	r.Jailbreak = "unknown"

	for _, ln := range lines {
		if s := strings.TrimSpace(ln); strings.HasPrefix(s, "JB ") {
			r.Jailbreak = classifyJailbreak(strings.TrimPrefix(s, "JB "))
			break
		}
	}

	return r, nil
}

func (c *Client) LocateAppinst() (string, error) {
	out, _, _, err := c.Run("command -v appinst 2>/dev/null || true")
	if err != nil {
		return "", fmt.Errorf("locate appinst: %w", err)
	}

	if p := strings.TrimSpace(out); p != "" {
		return p, nil
	}

	for _, candidate := range []string{
		"/usr/local/bin/appinst",
		"/var/jb/usr/bin/appinst",
		"/var/jb/usr/local/bin/appinst",
	} {
		if c.Exists(candidate) {
			return candidate, nil
		}
	}

	return "", nil
}

func (c *Client) LocateAppSync() (string, error) {
	candidates := []string{
		"/var/jb/Library/MobileSubstrate/DynamicLibraries/AppSyncUnified-installd.dylib",
		"/Library/MobileSubstrate/DynamicLibraries/AppSyncUnified-installd.dylib",
		"/var/jb/Library/MobileSubstrate/DynamicLibraries/AppSyncUnified.dylib",
		"/Library/MobileSubstrate/DynamicLibraries/AppSyncUnified.dylib",
	}

	for _, p := range candidates {
		if c.Exists(p) {
			return p, nil
		}
	}

	out, _, _, err := c.Run(
		"ls /Library/MobileSubstrate/DynamicLibraries/AppSyncUnified*.dylib " +
			"/var/jb/Library/MobileSubstrate/DynamicLibraries/AppSyncUnified*.dylib " +
			"2>/dev/null | head -1")
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(out), nil
}

func (c *Client) Install(appinstPath, ipaRemote string) error {
	out, errOut, code, err := c.RunSudo(fmt.Sprintf("%s %q", appinstPath, ipaRemote))
	if err != nil {
		return fmt.Errorf("appinst: %w", err)
	}

	if code != 0 {
		return fmt.Errorf("appinst exit %d:\nstdout: %s\nstderr: %s", code, out, errOut)
	}

	return nil
}

// Uninstall removes an installed app. Two steps wrapped in a single
// `sudo sh -c '…'` so both commands run as root (sudo only elevates the
// first command in a `cmd1; cmd2` chain, otherwise rm runs as mobile and
// hits the _installd-owned files with EACCES). Order matters:
//
//  1. uicache -u <bundlePath>  - unregister from LSApplicationWorkspace
//     so SpringBoard drops the icon and the LS registry forgets the
//     bundle.
//  2. rm -rf <UUID-dir>        - remove the bundle dir under
//     /var/containers/Bundle/Application/.
//
// The data container at /var/mobile/Containers/Data/Application/<other-UUID>/
// is left behind  finding it would require scanning every container's
// metadata plist for the bundle id, and the next install spins a fresh
// one regardless.
func (c *Client) Uninstall(bundlePath string) error {
	const bundleRoot = "/var/containers/Bundle/Application/"
	if !strings.HasPrefix(bundlePath, bundleRoot) {
		return fmt.Errorf("refuse to uninstall: suspicious bundle path %q", bundlePath)
	}

	uuidDir := path.Dir(bundlePath)

	cmd := fmt.Sprintf("sh -c %s",
		shellQuote(fmt.Sprintf("uicache -u %s && rm -rf %s",
			shellQuote(bundlePath), shellQuote(uuidDir))))

	out, errOut, code, err := c.RunSudo(cmd)
	if err != nil {
		return fmt.Errorf("uninstall: %w", err)
	}

	if code != 0 {
		return fmt.Errorf("uninstall exit %d:\nstdout: %s\nstderr: %s", code, out, errOut)
	}

	return nil
}

func (c *Client) EnsureHelper() (string, error) {
	sum := sha256.Sum256(helperArm64)
	remote := path.Join(RemoteRoot, "helpers",
		fmt.Sprintf("ipadecrypt-helper-arm64-%s.bin", hex.EncodeToString(sum[:])[:12]))

	if !c.Exists(remote) {
		if err := c.Upload(bytes.NewReader(helperArm64), remote, 0o755); err != nil {
			return "", fmt.Errorf("upload helper: %w", err)
		}
	}

	if err := c.prepareFreyaHelper(remote); err != nil {
		return "", err
	}

	return remote, nil
}

// HashFile computes the sha256 of a path on-device. Installed bundles under
// /var/containers are readable only by root + _installd, hence sudo. Relies
// on a `shasum` binary being on PATH (procursus/dopamine/palera1n all ship
// it at /var/jb/usr/bin/shasum).
func (c *Client) HashFile(target string) (string, error) {
	// procursus (Dopamine + palera1n) ships sha256sum (from coreutils) and
	// shasum (perl). Try both. Output is `<hex>  <path>`; cut first field.
	cmd := fmt.Sprintf(
		"sh -c '"+
			"for p in sha256sum /var/jb/usr/bin/sha256sum /usr/bin/sha256sum "+
			"shasum /var/jb/usr/bin/shasum /usr/bin/shasum; do "+
			"  if command -v \"$p\" >/dev/null 2>&1; then "+
			"    case \"$p\" in "+
			"      *shasum) \"$p\" -a 256 %[1]q | cut -d\" \" -f1; exit 0;; "+
			"      *) \"$p\" %[1]q | cut -d\" \" -f1; exit 0;; "+
			"    esac; "+
			"  fi; "+
			"done; exit 127"+
			"'",
		target)

	out, errOut, code, err := c.RunSudo(cmd)
	if err != nil {
		return "", fmt.Errorf("shasum: %w", err)
	}

	if code != 0 {
		return "", fmt.Errorf("shasum exit %d: %s", code, strings.TrimSpace(errOut))
	}

	return strings.TrimSpace(out), nil
}

// InstalledVersion reads CFBundleShortVersionString (falling back to
// CFBundleVersion) from an installed app bundle's Info.plist.
func (c *Client) InstalledVersion(bundlePath string) (string, error) {
	infoPath := path.Join(bundlePath, "Info.plist")

	out, errOut, code, err := c.RunSudo(fmt.Sprintf("cat %q", infoPath))
	if err != nil {
		return "", fmt.Errorf("read installed version: %w", err)
	}

	if code != 0 {
		return "", fmt.Errorf("read installed version exit %d: %s", code, strings.TrimSpace(errOut))
	}

	var info map[string]any
	if _, err := plist.Unmarshal([]byte(out), &info); err != nil {
		return "", fmt.Errorf("parse installed Info.plist: %w", err)
	}

	if version, _ := info["CFBundleShortVersionString"].(string); version != "" {
		return version, nil
	}

	if version, _ := info["CFBundleVersion"].(string); version != "" {
		return version, nil
	}

	return "", errors.New("installed version not found")
}

// FindInstalledByBundleID returns the .app path and canonical CFBundleIdentifier
// matching bundleID case-insensitively. grep is a prefilter; each hit is parsed
// to confirm (binary plists embed bundle ids as URL-scheme substrings).
func (c *Client) FindInstalledByBundleID(bundleID string) (string, string, error) {
	cmd := "grep -laFi " + shellQuote(bundleID) +
		" /var/containers/Bundle/Application/*/*.app/Info.plist 2>/dev/null"

	out, errOut, code, err := c.RunSudo(cmd)
	if err != nil {
		return "", "", err
	}

	if code != 0 && code != 1 {
		return "", "", fmt.Errorf("find-by-bundle-id exit %d: %s", code, strings.TrimSpace(errOut))
	}

	for line := range strings.SplitSeq(strings.TrimSpace(out), "\n") {
		infoPath := strings.TrimSpace(line)
		if infoPath == "" {
			continue
		}

		bundlePath := strings.TrimSuffix(infoPath, "/Info.plist")

		got, err := c.bundleIdentifierAt(infoPath)
		if err != nil {
			continue
		}

		if strings.EqualFold(got, bundleID) {
			return bundlePath, got, nil
		}
	}

	return "", "", nil
}

func (c *Client) bundleIdentifierAt(infoPlistPath string) (string, error) {
	out, errOut, code, err := c.RunSudo(fmt.Sprintf("cat %q", infoPlistPath))
	if err != nil {
		return "", fmt.Errorf("read Info.plist: %w", err)
	}

	if code != 0 {
		return "", fmt.Errorf("read Info.plist exit %d: %s", code, strings.TrimSpace(errOut))
	}

	var info map[string]any
	if _, err := plist.Unmarshal([]byte(out), &info); err != nil {
		return "", fmt.Errorf("parse Info.plist: %w", err)
	}

	id, _ := info["CFBundleIdentifier"].(string)

	return id, nil
}

// VerifyHelper is a best-effort sanity: invoke the helper with no args; it
// should exit 2 with a usage string we can recognize. Catches common issues
// (binary not executable, sudo denied, missing codesign).
func (c *Client) VerifyHelper(helperPath string) error {
	cmd := fmt.Sprintf("%s 2>&1 | head -1", helperPath)

	out, _, _, err := c.RunSudo(cmd)
	if err != nil {
		return fmt.Errorf("verify helper: %w", err)
	}

	if !strings.Contains(out, "usage:") {
		return fmt.Errorf("helper didn't respond with usage (got %q)", strings.TrimSpace(out))
	}

	return nil
}

type EventHandler func(Event)

// FrameHandler is invoked once per Mach-O record the helper streams in
// --execs-only mode. path is the IPA-relative bundle path
// ("Payload/AppName.app/Frameworks/X.framework/X"). r yields exactly size
// bytes; the handler must read them fully before returning, or the next
// frame will deserialize garbage.
type FrameHandler func(path string, size int64, r io.Reader) error

// RunHelper spawns the on-device helper for a bundle and streams the
// decrypted IPA bytes into ipaW. bundleID goes to the SpringBoard SBS SPI
// (only accepted for the main app; empty string skips the main-app pass
// and just decrypts PlugIns/*.appex + Extensions/*.appex). When skipAppex
// is true the helper passes --skip-appex, leaving extensions encrypted.
//
// In this mode the helper writes IPA bytes to stdout and event lines to
// stderr; we tee stderr through the event splitter while ipaW receives
// the binary stream - no on-device output file, no sftp pull.
func (c *Client) RunHelper(helperPath, bundleID, bundlePath string,
	verbose, skipAppex bool, onEvent EventHandler, ipaW io.Writer) (int, error) {
	gflag := ""
	if verbose {
		gflag = "-v "
	}

	subflag := ""
	if skipAppex {
		subflag = "--skip-appex "
	}

	cmd := fmt.Sprintf("%s %sdecrypt %s%q %q -",
		helperPath, gflag, subflag, bundleID, bundlePath)

	splitter := newEventSplitter(onEvent, io.Discard)
	defer splitter.Close()

	_, _, code, err := c.RunSudoStream(cmd, ipaW, splitter)

	return code, err
}

// RunHelperExecs runs the helper in --execs-only mode: the helper streams
// framed Mach-O records on stdout, events on stderr. onFrame is called
// once per record. Use this when the host has the source IPA and will
// assemble the output by substituting the helper-provided execs.
func (c *Client) RunHelperExecs(helperPath, bundleID, bundlePath string,
	verbose, skipAppex bool, onEvent EventHandler, onFrame FrameHandler) (int, error) {
	gflag := ""
	if verbose {
		gflag = "-v "
	}

	subflag := "--execs-only "
	if skipAppex {
		subflag += "--skip-appex "
	}

	cmd := fmt.Sprintf("%s %sdecrypt %s%q %q",
		helperPath, gflag, subflag, bundleID, bundlePath)

	splitter := newEventSplitter(onEvent, io.Discard)
	defer splitter.Close()

	// Tee helper stdout into a pipe we read frames from. The SSH session
	// blocks in a goroutine; we read frames from the main goroutine and
	// signal completion via done.
	pr, pw := io.Pipe()

	var (
		code   int
		runErr error
		done   = make(chan struct{})
	)

	go func() {
		_, _, code, runErr = c.RunSudoStream(cmd, pw, splitter)
		pw.Close()
		close(done)
	}()

	parseErr := parseFrames(pr, onFrame)

	// Drain any remaining stdout so the SSH session can complete.
	io.Copy(io.Discard, pr)
	<-done

	if runErr != nil {
		return code, runErr
	}

	if parseErr != nil {
		return code, parseErr
	}

	return code, nil
}

// parseFrames reads [u32be plen][plen-byte path][u64be size][size bytes]
// records until EOF, invoking onFrame for each.
func parseFrames(r io.Reader, onFrame FrameHandler) error {
	br := bufio.NewReaderSize(r, 64*1024)

	for {
		var hdr [4]byte
		if _, err := io.ReadFull(br, hdr[:]); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}

			return fmt.Errorf("read frame plen: %w", err)
		}

		plen := binary.BigEndian.Uint32(hdr[:])
		if plen == 0 || plen > 4096 {
			return fmt.Errorf("invalid frame path length: %d", plen)
		}

		pathBuf := make([]byte, plen)
		if _, err := io.ReadFull(br, pathBuf); err != nil {
			return fmt.Errorf("read frame path: %w", err)
		}

		var szHdr [8]byte
		if _, err := io.ReadFull(br, szHdr[:]); err != nil {
			return fmt.Errorf("read frame size: %w", err)
		}

		size := int64(binary.BigEndian.Uint64(szHdr[:]))
		if size < 0 {
			return fmt.Errorf("negative frame size: %d", size)
		}

		lr := io.LimitReader(br, size)
		if err := onFrame(string(pathBuf), size, lr); err != nil {
			return err
		}

		// Drain leftovers in case the handler didn't read everything.
		if _, err := io.Copy(io.Discard, lr); err != nil {
			return fmt.Errorf("drain frame body: %w", err)
		}
	}
}

type eventSplitter struct {
	pw *io.PipeWriter
}

func (s *eventSplitter) Write(p []byte) (int, error) { return s.pw.Write(p) }
func (s *eventSplitter) Close() error                { return s.pw.Close() }

func newEventSplitter(onEvent EventHandler, humanFallback io.Writer) *eventSplitter {
	pr, pw := io.Pipe()

	go func() {
		defer pr.Close()

		sc := bufio.NewScanner(pr)
		sc.Buffer(make([]byte, 1<<16), 1<<20)

		for sc.Scan() {
			line := sc.Text()
			if ev, ok := ParseEvent(line); ok {
				if onEvent != nil {
					onEvent(ev)
				}

				continue
			}

			if humanFallback != nil {
				fmt.Fprintln(humanFallback, line)
			}
		}
	}()

	return &eventSplitter{pw: pw}
}
