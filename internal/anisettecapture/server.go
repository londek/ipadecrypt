package anisettecapture

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/londek/ipadecrypt/internal/device"
)

var (
	remoteFridaServer = "/tmp/ipadecrypt-frida-server-" + fridaVersion
	remoteFridaAgent  = "/tmp/frida-agent.dylib"
	remoteFridaLog    = "/tmp/ipadecrypt-frida-server.log"
)

type fridaServer struct {
	client      *device.Client
	startedPIDs []string
	uploaded    []string
	once        sync.Once
	closeErr    error
}

// Close releases only the process and files created by this instance. A server
// that was already running belongs to its original caller.
func (s *fridaServer) Close() error {
	s.once.Do(func() {
		if len(s.startedPIDs) > 0 {
			current, err := s.pids()
			if err != nil {
				s.closeErr = err
				return
			}

			var owned []string

			for _, pid := range s.startedPIDs {
				for _, running := range current {
					if pid == running {
						owned = append(owned, pid)
						break
					}
				}
			}

			if len(owned) > 0 {
				_, stderr, code, err := s.client.RunSudo("kill -9 " + strings.Join(owned, " "))
				if err != nil {
					s.closeErr = err
					return
				}

				if code != 0 {
					s.closeErr = fmt.Errorf("stop Frida (exit %d): %s", code, strings.TrimSpace(stderr))
					return
				}
			}
		}

		for _, path := range s.uploaded {
			_, stderr, code, err := s.client.RunSudo("rm -f " + path)
			if err == nil && code != 0 {
				err = fmt.Errorf("remove Frida file (exit %d): %s", code, strings.TrimSpace(stderr))
			}

			s.closeErr = errors.Join(s.closeErr, err)
		}
	})

	return s.closeErr
}

func (s *fridaServer) pids() ([]string, error) {
	command := fmt.Sprintf("ps -ax | awk '/\\/%s/ && !/awk/ {print $1}'", strings.ReplaceAll(strings.TrimPrefix(remoteFridaServer, "/"), "/", "\\/"))

	out, _, _, err := s.client.Run(command)
	if err != nil {
		return nil, err
	}

	return strings.Fields(out), nil
}

// StartFrida prepares a loopback-only server and returns its cleanup function.
// The caller must keep the SSH client open until cleanup has completed.
func StartFrida(ctx context.Context, client *device.Client) (func() error, error) {
	artifacts, err := ensureFridaArtifacts(ctx)
	if err != nil {
		return nil, err
	}

	server, err := startFridaServerAt(client, artifacts, "127.0.0.1:27042")
	if err != nil {
		return nil, err
	}

	return server.Close, nil
}

// StartFridaTunnel forwards the loopback-only device Frida port over USB. The
// returned stop function closes only a tunnel created by this call.
func StartFridaTunnel(udid string) (func(), error) {
	if conn, err := net.DialTimeout("tcp", "127.0.0.1:27042", time.Second); err == nil {
		conn.Close()
		return nil, errors.New("local Frida port 27042 is already in use; cannot verify its device")
	}

	iproxy, err := exec.LookPath("iproxy")
	if err != nil {
		return nil, errors.New("USB Frida mode needs iproxy on PATH")
	}

	args := []string{"27042:27042"}
	if udid != "" {
		args = append(args, "-u", udid)
	}

	command := exec.Command(iproxy, args...)
	if err := command.Start(); err != nil {
		return nil, fmt.Errorf("start USB Frida tunnel: %w", err)
	}

	stop := func() {
		if command.Process != nil {
			_ = command.Process.Kill()
		}

		_, _ = command.Process.Wait()
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if conn, err := net.DialTimeout("tcp", "127.0.0.1:27042", time.Second); err == nil {
			conn.Close()
			return stop, nil
		}

		time.Sleep(100 * time.Millisecond)
	}

	stop()

	return nil, errors.New("USB Frida tunnel did not open")
}

func startFridaServerAt(client *device.Client, artifacts fridaArtifacts, listen string) (*fridaServer, error) {
	server := &fridaServer{client: client}

	failed := true
	defer func() {
		if failed {
			server.Close()
		}
	}()

	pids, err := server.pids()
	if err != nil {
		return nil, fmt.Errorf("inspect Frida server: %w", err)
	}

	for _, item := range []struct {
		local  string
		remote string
		mode   os.FileMode
	}{
		{artifacts.server, remoteFridaServer, 0o755},
		{artifacts.agent, remoteFridaAgent, 0o644},
	} {
		info, statErr := client.Stat(item.remote)
		if statErr == nil && info.Size() > 0 {
			continue
		}

		file, err := os.Open(item.local)
		if err != nil {
			return nil, fmt.Errorf("open Frida runtime: %w", err)
		}

		err = client.Upload(file, item.remote, item.mode)
		closeErr := file.Close()

		if err != nil {
			return nil, err
		}

		if closeErr != nil {
			return nil, fmt.Errorf("close Frida runtime: %w", closeErr)
		}

		server.uploaded = append(server.uploaded, item.remote)
	}

	if len(pids) == 0 {
		command := fmt.Sprintf("chmod 755 %s && nohup %s -l %s >%s 2>&1 </dev/null &", remoteFridaServer, remoteFridaServer, listen, remoteFridaLog)
		if _, stderr, code, err := client.RunSudo("sh -c " + shellQuote(command)); err != nil {
			return nil, fmt.Errorf("start Frida server: %w", err)
		} else if code != 0 {
			return nil, fmt.Errorf("start Frida server (exit %d): %s", code, strings.TrimSpace(stderr))
		}

		deadline := time.Now().Add(10 * time.Second)
		for len(pids) == 0 && time.Now().Before(deadline) {
			time.Sleep(250 * time.Millisecond)

			pids, err = server.pids()
			if err != nil {
				return nil, fmt.Errorf("inspect started Frida server: %w", err)
			}
		}

		if len(pids) == 0 {
			return nil, errors.New("the Frida server did not start")
		}

		server.startedPIDs = pids
		server.uploaded = append(server.uploaded, remoteFridaLog)
	}

	failed = false

	return server, nil
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

func prepareCaptureDaemons(client *device.Client) error {
	if os.Getenv("IPADECRYPT_KEEP_ADID") == "" {
		if err := kickstartCaptureDaemon(client, "com.apple.adid"); err != nil {
			return err
		}
	}

	if os.Getenv("IPADECRYPT_RESTART_ITUNESSTORED") != "" {
		return kickstartCaptureDaemon(client, "com.apple.itunesstored")
	}

	return EnsureItunesstored(client)
}

// EnsureItunesstored starts the daemon required for native Store operations when absent.
func EnsureItunesstored(client *device.Client) error {
	_, _, code, err := client.Run(`ps -axo comm= | awk '$1 ~ /\/itunesstored$/ { found = 1 } END { exit !found }'`)
	if err != nil {
		return fmt.Errorf("inspect itunesstored: %w", err)
	}

	if code != 0 {
		return kickstartCaptureDaemon(client, "com.apple.itunesstored")
	}

	return nil
}

// A timed-out Frida unload can leave the capture daemon instrumented. Release
// only that exact PID, never killall or a newly launched replacement daemon.
func releaseCapturedAdid(client *device.Client, pid int) error {
	if pid <= 1 {
		return errors.New("invalid captured adid PID")
	}

	out, stderr, code, err := client.Run(fmt.Sprintf("ps -p %d -o comm=", pid))
	if err != nil {
		return fmt.Errorf("inspect captured adid: %w", err)
	}

	if code == 1 && strings.TrimSpace(out) == "" {
		return nil
	}

	if code != 0 {
		return fmt.Errorf("inspect captured adid (exit %d): %s", code, strings.TrimSpace(stderr))
	}

	if strings.TrimSpace(out) != "/usr/libexec/adid" {
		return errors.New("capture cleanup PID no longer belongs to adid; left it untouched")
	}

	_, stderr, code, err = client.RunSudo(fmt.Sprintf("kill -TERM %d", pid))
	if err != nil {
		return fmt.Errorf("release captured adid: %w", err)
	}

	if code != 0 {
		return fmt.Errorf("release captured adid (exit %d): %s", code, strings.TrimSpace(stderr))
	}

	for i := 0; i < 20; i++ {
		out, _, code, err = client.Run(fmt.Sprintf("ps -p %d -o comm=", pid))
		if err != nil {
			return fmt.Errorf("verify adid cleanup: %w", err)
		}

		if code == 1 && strings.TrimSpace(out) == "" {
			return nil
		}

		if code == 0 && strings.TrimSpace(out) != "/usr/libexec/adid" {
			return nil
		}

		time.Sleep(100 * time.Millisecond)
	}

	return errors.New("captured adid did not exit after cleanup signal")
}

func kickstartCaptureDaemon(client *device.Client, label string) error {
	command := fmt.Sprintf("launchctl kickstart -k user/foreground/%s", label)
	if _, stderr, code, err := client.RunSudo(command); err != nil {
		return fmt.Errorf("start %s: %w", label, err)
	} else if code != 0 {
		return fmt.Errorf("start %s (exit %d): %s", label, code, strings.TrimSpace(stderr))
	}

	return nil
}

func liftAdidJetsamLimit(client *device.Client, helper string) error {
	// kickstart can return before launchd has spawned the process.
	pid := ""

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		out, _, code, err := client.Run(`ps -axo pid=,comm= | awk '$2 == "/usr/libexec/adid" {print $1; exit}'`)
		if err != nil {
			return fmt.Errorf("find adid for Jetsam setup: %w", err)
		}

		if code != 0 {
			return errors.New("could not enumerate adid for Jetsam setup")
		}

		pid = strings.TrimSpace(out)
		if pid != "" {
			if value, err := strconv.Atoi(pid); err != nil || value <= 0 {
				return errors.New("invalid adid PID")
			}

			break
		}

		time.Sleep(100 * time.Millisecond)
	}

	if pid == "" {
		return errors.New("adid did not start within 3s after launchctl kickstart")
	}

	file, err := os.Open(helper)
	if err != nil {
		return fmt.Errorf("open Jetsam helper: %w", err)
	}

	const remote = "/tmp/ipadecrypt-jetsam-limit"
	if err := client.Upload(file, remote, 0o755); err != nil {
		file.Close()
		return fmt.Errorf("upload Jetsam helper: %w", err)
	}

	if err := file.Close(); err != nil {
		return fmt.Errorf("close Jetsam helper: %w", err)
	}

	defer client.Remove(remote)

	_, stderr, code, err := client.RunSudo(remote + " " + pid)
	if err != nil {
		return fmt.Errorf("lift adid Jetsam limit: %w", err)
	}

	if code != 0 {
		return fmt.Errorf("lift adid Jetsam limit (exit %d): %s", code, strings.TrimSpace(stderr))
	}

	return nil
}
