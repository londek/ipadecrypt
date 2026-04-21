package device

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/londek/ipadecrypt/internal/config"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

const RemoteRoot = "/var/mobile/Media/ipadecrypt"

var ErrSudoPasswordRejected = errors.New("sudo password rejected")

type Client struct {
	cfg  config.Device
	ssh  *ssh.Client
	sftp *sftp.Client
}

func Connect(ctx context.Context, dev config.Device) (*Client, error) {
	auth, err := sshAuthMethods(dev.Auth)
	if err != nil {
		return nil, err
	}

	cfg := &ssh.ClientConfig{
		User:            dev.User,
		Auth:            auth,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         15 * time.Second,
	}

	addr := net.JoinHostPort(dev.Host, strconv.Itoa(dev.Port))
	dialer := &net.Dialer{Timeout: 15 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}

	sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("ssh handshake: %w", err)
	}

	sshClient := ssh.NewClient(sshConn, chans, reqs)
	sftpClient, err := sftp.NewClient(sshClient)
	if err != nil {
		sshClient.Close()
		return nil, fmt.Errorf("sftp open: %w", err)
	}

	return &Client{cfg: dev, ssh: sshClient, sftp: sftpClient}, nil
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

func (c *Client) Close() {
	if c.sftp != nil {
		c.sftp.Close()
	}
	if c.ssh != nil {
		c.ssh.Close()
	}
}

func (c *Client) Run(cmd string) (string, string, int, error) {
	sess, err := c.ssh.NewSession()
	if err != nil {
		return "", "", -1, fmt.Errorf("new session: %w", err)
	}
	defer sess.Close()

	var so, se bytes.Buffer
	sess.Stdout = &so
	sess.Stderr = &se

	err = sess.Run(cmd)

	exit := 0
	if err != nil {
		var ee *ssh.ExitError
		if errors.As(err, &ee) {
			exit = ee.ExitStatus()
			err = nil
		} else {
			return so.String(), se.String(), -1, err
		}
	}

	return so.String(), se.String(), exit, nil
}

func (c *Client) RunSudo(cmd string) (string, string, int, error) {
	return c.RunSudoStream(cmd, nil, nil)
}

func (c *Client) RunSudoStream(cmd string, stdoutW, stderrW io.Writer) (string, string, int, error) {
	full := "sudo -S -p '' " + cmd

	sess, err := c.ssh.NewSession()
	if err != nil {
		return "", "", -1, fmt.Errorf("new session: %w", err)
	}
	defer sess.Close()

	stdin, err := sess.StdinPipe()
	if err != nil {
		return "", "", -1, fmt.Errorf("stdin pipe: %w", err)
	}

	go func() {
		_, _ = stdin.Write([]byte(c.cfg.Auth.Password + "\n"))
		_ = stdin.Close()
	}()

	var soBuf, seBuf bytes.Buffer
	if stdoutW != nil {
		sess.Stdout = io.MultiWriter(stdoutW, &soBuf)
	} else {
		sess.Stdout = &soBuf
	}
	if stderrW != nil {
		sess.Stderr = io.MultiWriter(stderrW, &seBuf)
	} else {
		sess.Stderr = &seBuf
	}

	err = sess.Run(full)

	exit := 0
	if err != nil {
		var ee *ssh.ExitError
		if errors.As(err, &ee) {
			exit = ee.ExitStatus()
			err = nil
		} else {
			return soBuf.String(), seBuf.String(), -1, err
		}
	}

	if s := seBuf.String(); strings.Contains(s, "incorrect password") ||
		strings.Contains(s, "Sorry, try again") ||
		strings.Contains(s, "try again") {
		return soBuf.String(), s, exit, ErrSudoPasswordRejected
	}

	return soBuf.String(), seBuf.String(), exit, nil
}

func (c *Client) Mkdir(path string) error {
	if err := c.sftp.MkdirAll(path); err != nil {
		return fmt.Errorf("mkdir %s: %w", path, err)
	}
	return nil
}

func (c *Client) Upload(local, remote string) error {
	if err := c.Mkdir(filepath.Dir(remote)); err != nil {
		return err
	}

	src, err := os.Open(local)
	if err != nil {
		return fmt.Errorf("open %s: %w", local, err)
	}
	defer src.Close()

	dst, err := c.sftp.Create(remote)
	if err != nil {
		return fmt.Errorf("create %s: %w", remote, err)
	}
	defer dst.Close()

	if _, err := io.Copy(dst, src); err != nil {
		return fmt.Errorf("upload %s: %w", remote, err)
	}

	return nil
}

func (c *Client) UploadBytes(data []byte, remote string, mode os.FileMode) error {
	if err := c.Mkdir(filepath.Dir(remote)); err != nil {
		return err
	}

	dst, err := c.sftp.Create(remote)
	if err != nil {
		return fmt.Errorf("create %s: %w", remote, err)
	}

	if _, err := dst.Write(data); err != nil {
		dst.Close()
		return fmt.Errorf("write %s: %w", remote, err)
	}

	if err := dst.Close(); err != nil {
		return fmt.Errorf("close %s: %w", remote, err)
	}

	return c.sftp.Chmod(remote, mode)
}

func (c *Client) Download(remote, local string) error {
	src, err := c.sftp.Open(remote)
	if err != nil {
		return fmt.Errorf("open remote %s: %w", remote, err)
	}
	defer src.Close()

	if err := os.MkdirAll(filepath.Dir(local), 0o755); err != nil {
		return fmt.Errorf("mkdir local: %w", err)
	}

	dst, err := os.OpenFile(local, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("open %s: %w", local, err)
	}
	defer dst.Close()

	if _, err := io.Copy(dst, src); err != nil {
		return fmt.Errorf("download %s: %w", remote, err)
	}

	return nil
}

func (c *Client) Exists(path string) bool {
	_, err := c.sftp.Stat(path)
	return err == nil
}

func (c *Client) Remove(path string) error { return c.sftp.Remove(path) }

func expandHome(p string) string {
	if strings.HasPrefix(p, "~/") {
		if h, err := os.UserHomeDir(); err == nil {
			return filepath.Join(h, p[2:])
		}
	}
	return p
}
