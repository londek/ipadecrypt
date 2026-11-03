package credmint

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/londek/ipadecrypt/internal/config"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

const (
	defaultUSBPort = 2222
	runTimeout     = 120 * time.Second
)

var remoteNameRe = regexp.MustCompile(`^[a-zA-Z0-9_.-]+$`)

// sshDevice is a slim root-SSH client for credential minting: it pushes the
// device bundle, runs the native programs, and tears down its temp dirs. It
// is a Go port of credential-retrieval/native_ssh.py's SSHDevice.
type sshDevice struct {
	ssh        *ssh.Client
	sftp       *sftp.Client
	tunnel     *exec.Cmd
	ps         string
	dir        string
	triggerDir string
}

func dial(ctx context.Context, dev config.Device) (*sshDevice, error) {
	host := dev.Host
	port := dev.Port

	d := &sshDevice{}

	if dev.USB {
		if port == 0 {
			port = defaultUSBPort
		}

		if err := d.startTunnel(dev.UDID, port); err != nil {
			return nil, err
		}

		host = "127.0.0.1"
	}

	if port == 0 {
		port = 22
	}

	auth, err := sshAuthMethods(dev.Auth)
	if err != nil {
		d.closeTunnel()
		return nil, err
	}

	cfg := &ssh.ClientConfig{
		User:            dev.User,
		Auth:            auth,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         15 * time.Second,
	}

	addr := net.JoinHostPort(host, strconv.Itoa(port))
	dialer := &net.Dialer{Timeout: 15 * time.Second}

	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		d.closeTunnel()
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}

	sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		conn.Close()
		d.closeTunnel()

		return nil, fmt.Errorf("ssh handshake: %w", err)
	}

	d.ssh = ssh.NewClient(sshConn, chans, reqs)

	sftpClient, err := sftp.NewClient(d.ssh)
	if err != nil {
		d.ssh.Close()
		d.closeTunnel()

		return nil, fmt.Errorf("sftp open: %w", err)
	}

	d.sftp = sftpClient

	return d, nil
}

// startTunnel forwards a local port to the device's SSH port over USB with
// iproxy, mirroring native_ssh.py. It no-ops if something already listens on
// the port (a tunnel the user started by hand).
func (d *sshDevice) startTunnel(udid string, port int) error {
	if conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), time.Second); err == nil {
		conn.Close()
		return nil
	}

	iproxy, err := exec.LookPath("iproxy")
	if err != nil {
		return errors.New("USB mode needs iproxy on PATH (libimobiledevice); install it or use a network connection")
	}

	args := []string{fmt.Sprintf("%d:22", port)}
	if udid != "" {
		args = append(args, "-u", udid)
	}

	cmd := exec.Command(iproxy, args...)
	cmd.Stdout = nil
	cmd.Stderr = nil

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start iproxy: %w", err)
	}

	d.tunnel = cmd

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cmd.ProcessState != nil && cmd.ProcessState.Exited() {
			return errors.New("USB SSH tunnel exited before opening")
		}

		if conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), time.Second); err == nil {
			conn.Close()
			return nil
		}

		time.Sleep(100 * time.Millisecond)
	}

	d.closeTunnel()

	return errors.New("USB SSH tunnel did not open")
}

func (d *sshDevice) closeTunnel() {
	if d.tunnel != nil && d.tunnel.Process != nil {
		d.tunnel.Process.Kill()
		d.tunnel.Wait()
		d.tunnel = nil
	}
}

func sshAuthMethods(a config.DeviceAuth) ([]ssh.AuthMethod, error) {
	if a.Kind == "key" {
		path, err := expandUser(a.KeyPath)
		if err != nil {
			return nil, fmt.Errorf("expand key path: %w", err)
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read key %s: %w", path, err)
		}

		var signer ssh.Signer
		if a.KeyPassphrase != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase(data, []byte(a.KeyPassphrase))
		} else {
			signer, err = ssh.ParsePrivateKey(data)
		}

		if err != nil {
			return nil, fmt.Errorf("parse key %s: %w", path, err)
		}

		return []ssh.AuthMethod{ssh.PublicKeys(signer)}, nil
	}

	return []ssh.AuthMethod{ssh.Password(a.Password)}, nil
}

func expandUser(path string) (string, error) {
	if !strings.HasPrefix(path, "~") {
		return path, nil
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	return filepath.Join(home, strings.TrimPrefix(path, "~")), nil
}

// setup resolves the jailbreak's real temp root (RootHide exposes it via
// jbroot) and creates the retriever work dirs. Mirrors native_ssh.py.
func (d *sshDevice) setup() error {
	out, err := d.run("if command -v jbroot >/dev/null 2>&1; then jbroot /var/tmp; fi", nil)
	if err != nil {
		return err
	}

	temporary := strings.TrimSpace(string(out))

	d.ps = "ps"
	if temporary != "" {
		d.ps = "/rootfs/bin/ps"

		if !strings.HasPrefix(temporary, "/") {
			return errors.New("jbroot returned a non-absolute temporary directory")
		}
	} else {
		temporary = "/var/tmp"
	}

	suffix, err := randomToken()
	if err != nil {
		return err
	}

	triggerSuffix, err := randomToken()
	if err != nil {
		return err
	}

	d.dir = temporary + "/fp-retrieve-" + suffix
	d.triggerDir = temporary + "/fp-trigger-" + triggerSuffix

	if _, err := d.run("umask 077; mkdir "+shellQuote(d.dir), nil); err != nil {
		return err
	}

	if _, err := d.run("mkdir -m 755 "+shellQuote(d.triggerDir), nil); err != nil {
		return err
	}

	return nil
}

func (d *sshDevice) path(name string) (string, error) {
	if !remoteNameRe.MatchString(name) {
		return "", fmt.Errorf("invalid remote filename %q", name)
	}

	return d.dir + "/" + name, nil
}

func (d *sshDevice) writeFile(name string, data []byte, executable bool) (string, error) {
	remote, err := d.path(name)
	if err != nil {
		return "", err
	}

	f, err := d.sftp.Create(remote)
	if err != nil {
		return "", fmt.Errorf("create %s: %w", remote, err)
	}

	if _, err := f.Write(data); err != nil {
		f.Close()
		return "", fmt.Errorf("write %s: %w", remote, err)
	}

	if err := f.Close(); err != nil {
		return "", fmt.Errorf("close %s: %w", remote, err)
	}

	mode := os.FileMode(0o600)
	if executable {
		mode = 0o700
	}

	if err := d.sftp.Chmod(remote, mode); err != nil {
		return "", fmt.Errorf("chmod %s: %w", remote, err)
	}

	return remote, nil
}

func (d *sshDevice) readFile(remote string) ([]byte, error) {
	f, err := d.sftp.Open(remote)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", remote, err)
	}

	defer f.Close()

	return io.ReadAll(f)
}

// run executes cmd and returns stdout, erroring (with combined output) on a
// non-zero exit or timeout. Mirrors native_ssh.py SSHDevice.run.
func (d *sshDevice) run(cmd string, stdin []byte) ([]byte, error) {
	sess, err := d.ssh.NewSession()
	if err != nil {
		return nil, fmt.Errorf("new session: %w", err)
	}

	defer sess.Close()

	var out, errBuf bytes.Buffer

	sess.Stdout = &out
	sess.Stderr = &errBuf

	if stdin != nil {
		sess.Stdin = bytes.NewReader(stdin)
	}

	done := make(chan error, 1)

	go func() { done <- sess.Run(cmd) }()

	select {
	case err := <-done:
		if err != nil {
			combined := strings.TrimSpace(out.String() + errBuf.String())
			return out.Bytes(), fmt.Errorf("device command failed (%v): %s", err, combined)
		}

		return out.Bytes(), nil
	case <-time.After(runTimeout):
		sess.Signal(ssh.SIGKILL)
		sess.Close()

		return nil, fmt.Errorf("device command timed out: %s", cmd)
	}
}

// runCode executes cmd and reports its exit code without treating a non-zero
// exit as an error (transport failures and the timeout still error). Used for
// the trigger, whose exit code 3 selects a fallback launch path.
func (d *sshDevice) runCode(cmd string, timeout time.Duration) (stdout, stderr []byte, code int, err error) {
	sess, err := d.ssh.NewSession()
	if err != nil {
		return nil, nil, -1, fmt.Errorf("new session: %w", err)
	}

	defer sess.Close()

	var out, errBuf bytes.Buffer

	sess.Stdout = &out
	sess.Stderr = &errBuf

	done := make(chan error, 1)

	go func() { done <- sess.Run(cmd) }()

	select {
	case runErr := <-done:
		code = 0

		if runErr != nil {
			var ee *ssh.ExitError
			if errors.As(runErr, &ee) {
				code = ee.ExitStatus()
			} else {
				return out.Bytes(), errBuf.Bytes(), -1, runErr
			}
		}

		return out.Bytes(), errBuf.Bytes(), code, nil
	case <-time.After(timeout):
		sess.Signal(ssh.SIGKILL)
		sess.Close()

		return nil, nil, -1, fmt.Errorf("device command timed out: %s", cmd)
	}
}

func (d *sshDevice) processes() ([]byte, error) {
	return d.run(shellQuote(d.ps)+" -e -o pid,comm", nil)
}

func (d *sshDevice) cleanup() {
	if d.dir != "" || d.triggerDir != "" {
		d.run("rm -r -- "+shellQuote(d.dir)+" "+shellQuote(d.triggerDir), nil)
	}

	d.close()
}

func (d *sshDevice) close() {
	if d.sftp != nil {
		d.sftp.Close()
	}

	if d.ssh != nil {
		d.ssh.Close()
	}

	d.closeTunnel()
}

// remoteCmd is a running device program whose stderr is scanned for a
// readiness marker while it runs (used by the FairPlay observer).
type remoteCmd struct {
	sess   *ssh.Session
	ready  chan struct{}
	done   chan error
	stderr *syncBuffer
}

func (d *sshDevice) start(cmd, readyMarker string) (*remoteCmd, error) {
	sess, err := d.ssh.NewSession()
	if err != nil {
		return nil, fmt.Errorf("new session: %w", err)
	}

	pipe, err := sess.StderrPipe()
	if err != nil {
		sess.Close()
		return nil, fmt.Errorf("stderr pipe: %w", err)
	}

	rc := &remoteCmd{
		sess:   sess,
		ready:  make(chan struct{}, 1),
		done:   make(chan error, 1),
		stderr: &syncBuffer{},
	}

	if err := sess.Start(cmd); err != nil {
		sess.Close()
		return nil, fmt.Errorf("start %s: %w", cmd, err)
	}

	go func() {
		scanner := bufio.NewScanner(pipe)
		for scanner.Scan() {
			line := scanner.Bytes()
			rc.stderr.Write(line)
			rc.stderr.Write([]byte{'\n'})

			if readyMarker != "" && bytes.Contains(line, []byte(readyMarker)) {
				select {
				case rc.ready <- struct{}{}:
				default:
				}
			}
		}
	}()

	go func() { rc.done <- rc.sess.Wait() }()

	return rc, nil
}

func (rc *remoteCmd) waitReady(timeout time.Duration) error {
	select {
	case <-rc.ready:
		return nil
	case err := <-rc.done:
		return fmt.Errorf("program exited before ready: %v: %s", err, strings.TrimSpace(rc.stderr.String()))
	case <-time.After(timeout):
		return errors.New("program did not become ready")
	}
}

func (rc *remoteCmd) wait(timeout time.Duration) error {
	select {
	case err := <-rc.done:
		if err != nil {
			return fmt.Errorf("%v: %s", err, strings.TrimSpace(rc.stderr.String()))
		}

		return nil
	case <-time.After(timeout):
		rc.stop()
		return errors.New("program timed out")
	}
}

func (rc *remoteCmd) running() bool {
	select {
	case err := <-rc.done:
		rc.done <- err
		return false
	default:
		return true
	}
}

func (rc *remoteCmd) stop() {
	rc.sess.Signal(ssh.SIGTERM)
	rc.sess.Close()
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
