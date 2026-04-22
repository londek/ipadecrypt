package device

import (
	"bufio"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"

	"howett.net/plist"
)

//go:embed helper.arm64
var helperArm64 []byte

type ProbeResult struct {
	IOSVersion string
	Arch       string // "arm64" or "arm64e"
	Model      string // "iPhone10,2", "iPad7,3", …
}

func (c *Client) Probe() (ProbeResult, error) {
	// SSH non-interactive shells on iOS often have a trimmed PATH that omits
	// the sysctl / rootless locations, so try a few absolute paths before
	// giving up. The 2>/dev/null suppresses expected "not found" from the
	// unmatched ones.
	const script = "" +
		"sw_vers -productVersion 2>/dev/null || " +
		"/usr/libexec/PlistBuddy -c 'Print :ProductVersion' " +
		"/System/Library/CoreServices/SystemVersion.plist 2>/dev/null; " +
		"uname -m; " +
		"(sysctl -n hw.machine 2>/dev/null || " +
		"/usr/sbin/sysctl -n hw.machine 2>/dev/null || " +
		"/var/jb/usr/sbin/sysctl -n hw.machine 2>/dev/null || " +
		"sysctl hw.machine 2>/dev/null | sed 's/^hw.machine: *//' || true)"
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
		arch := strings.TrimSpace(lines[1])
		switch arch {
		case "arm64", "arm64e":
			r.Arch = arch
		default:
			r.Arch = "arm64"
		}
	}

	if len(lines) > 2 {
		r.Model = strings.TrimSpace(lines[2])
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

func (c *Client) LocateBinary(name string) (string, error) {
	out, _, _, err := c.Run(fmt.Sprintf("command -v %s 2>/dev/null || true", name))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(out), nil
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

func (c *Client) EnsureHelper() (string, error) {
	sum := sha256.Sum256(helperArm64)
	remote := path.Join(RemoteRoot, "helpers",
		fmt.Sprintf("helper-arm64-%s.bin", hex.EncodeToString(sum[:])[:12]))

	if c.Exists(remote) {
		return remote, nil
	}

	if err := c.UploadBytes(helperArm64, remote, 0o755); err != nil {
		return "", fmt.Errorf("upload helper: %w", err)
	}

	return remote, nil
}

// HashFile runs `<helperPath> sha256 <path>` under sudo (installed bundles
// under /var/containers are readable only by root + _installd). Returns the
// lowercase-hex digest or an error.
func (c *Client) HashFile(helperPath, path string) (string, error) {
	cmd := fmt.Sprintf("%s sha256 %q", helperPath, path)

	out, errOut, code, err := c.RunSudo(cmd)
	if err != nil {
		return "", fmt.Errorf("helper sha256: %w", err)
	}

	if code != 0 {
		return "", fmt.Errorf("helper sha256 exit %d: %s", code, strings.TrimSpace(errOut))
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

	if version, ok := info["CFBundleShortVersionString"]; ok {
		return strings.TrimSpace(fmt.Sprintf("%v", version)), nil
	}

	if version, ok := info["CFBundleVersion"]; ok {
		return strings.TrimSpace(fmt.Sprintf("%v", version)), nil
	}

	if out == "" {
		return "", errors.New("installed version not found")
	}

	return "", errors.New("installed version not found")
}

func (c *Client) FindInstalled(helperPath, appDirName string) (string, error) {
	cmd := fmt.Sprintf("%s find %q", helperPath, appDirName)
	out, errOut, code, err := c.RunSudo(cmd)
	if err != nil {
		return "", err
	}

	switch code {
	case 0:
		return strings.TrimSpace(out), nil
	case 1:
		if strings.Contains(errOut, "[helper] find: scanned") {
			return "", nil
		}

		if s := strings.TrimSpace(errOut); s != "" {
			return "", fmt.Errorf("helper find: %s", s)
		}

		return "", errors.New("helper find produced no output (sudo/codesign/exec issue?)")
	default:
		return "", fmt.Errorf("helper find exit %d: stdout=%q stderr=%q", code, out, errOut)
	}
}

func (c *Client) VerifyHelper(helperPath string) error {
	path, err := c.FindInstalled(helperPath, "__ipadecrypt_probe_nope__.app")
	if err != nil {
		return err
	}

	if path != "" {
		return fmt.Errorf("unexpected match for probe bundle: %s", path)
	}

	return nil
}

type EventHandler func(Event)

func (c *Client) RunHelper(helperPath, bundlePath, outIPA string, onEvent EventHandler, humanFallback io.Writer) (string, string, int, error) {
	cmd := fmt.Sprintf("%s -e %q %q", helperPath, bundlePath, outIPA)
	splitter := newEventSplitter(onEvent, humanFallback)
	defer splitter.Close()
	return c.RunSudoStream(cmd, nil, splitter)
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
