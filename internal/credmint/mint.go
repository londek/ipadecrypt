// Package credmint mints the reusable 16-byte FairPlay account credential by
// orchestrating prebuilt native programs on a jailbroken device over root SSH.
// It is a one-time step; the cached credential then decrypts every app for
// that Apple account offline. Port of credential-retrieval/retrieve.py.
package credmint

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/londek/ipadecrypt/internal/config"
	"howett.net/plist"
)

const credentialSize = 16

var fairplaydRe = regexp.MustCompile(`^fairplayd(?:\.[AH][0-9]+)?$`)

// Mint connects to the jailbroken device described by dev, runs the FairPlay
// credential retriever, and returns the 16-byte account credential. The
// device must be signed into the same Apple account and have at least one
// owned App Store app installed.
func Mint(ctx context.Context, dev config.Device) ([]byte, error) {
	files, err := bundleFiles()
	if err != nil {
		return nil, err
	}

	d, err := dial(ctx, dev)
	if err != nil {
		return nil, err
	}

	defer d.cleanup()

	if err := d.setup(); err != nil {
		return nil, err
	}

	for _, f := range files {
		if _, err := d.writeFile(f.name, f.data, f.executable); err != nil {
			return nil, fmt.Errorf("push %s: %w", f.name, err)
		}
	}

	program, err := d.path("credential.ios")
	if err != nil {
		return nil, err
	}

	if err := verifyDevice(d, program, dev.UDID); err != nil {
		return nil, err
	}

	installedApp, executable, installedSinf, err := triggerApp(d)
	if err != nil {
		return nil, err
	}

	if err := validLicense(installedSinf); err != nil {
		return nil, fmt.Errorf("installed license: %w", err)
	}

	licensePath, err := d.writeFile("license.sinf", installedSinf, false)
	if err != nil {
		return nil, err
	}

	if _, err := d.run("cp -R "+shellQuote(installedApp)+" "+shellQuote(d.triggerDir), nil); err != nil {
		return nil, fmt.Errorf("stage trigger app: %w", err)
	}

	uniqueExecutable := d.triggerDir + "/" + path.Base(installedApp) + "/" + executable

	uidLayerPath, err := d.path("uid-layer.bin")
	if err != nil {
		return nil, err
	}

	triggerProgram, err := d.path("trigger.ios")
	if err != nil {
		return nil, err
	}

	newPID, err := restartFairplayd(d)
	if err != nil {
		return nil, err
	}

	if err := observeUIDLayer(d, program, newPID, uidLayerPath, triggerProgram, uniqueExecutable); err != nil {
		return nil, err
	}

	credentialPath, err := d.path("credential.bin")
	if err != nil {
		return nil, err
	}

	retrieve := strings.Join([]string{
		shellQuote(program), "retrieve",
		shellQuote(licensePath), shellQuote(uidLayerPath), shellQuote(credentialPath),
	}, " ")
	if _, err := d.run(retrieve, nil); err != nil {
		return nil, fmt.Errorf("retrieve credential: %w", err)
	}

	credential, err := d.readFile(credentialPath)
	if err != nil {
		return nil, err
	}

	if len(credential) != credentialSize {
		return nil, fmt.Errorf("device returned a %d-byte credential, expected %d", len(credential), credentialSize)
	}

	return credential, nil
}

func verifyDevice(d *sshDevice, program, udid string) error {
	actualPath, err := d.path("device-udid.bin")
	if err != nil {
		return err
	}

	if _, err := d.run(shellQuote(program)+" device-udid "+shellQuote(actualPath), nil); err != nil {
		return fmt.Errorf("read device identity: %w", err)
	}

	if udid == "" {
		return nil
	}

	want, err := fairplayDeviceID(udid)
	if err != nil {
		return err
	}

	got, err := d.readFile(actualPath)
	if err != nil {
		return err
	}

	if !bytes.Equal(got, want) {
		return errors.New("the SSH connection is pointed at a different device than the configured UDID")
	}

	return nil
}

// triggerApp finds the first installed App Store app with a supported license
// and returns its bundle path, main executable name, and license bytes.
// Mirrors retrieve.py trigger_app with no account filter.
func triggerApp(d *sshDevice) (bundle, executable string, sinf []byte, err error) {
	listing, err := d.run("find /var/containers/Bundle/Application -type f -path '*/SC_Info/*.sinf' -print0", nil)
	if err != nil {
		return "", "", nil, fmt.Errorf("scan installed apps: %w", err)
	}

	var paths [][]byte

	for _, p := range bytes.Split(listing, []byte{0}) {
		if len(p) == 0 || bytes.HasSuffix(p, []byte(".v4.sinf")) {
			continue
		}

		paths = append(paths, p)
	}

	sort.Slice(paths, func(i, j int) bool { return bytes.Compare(paths[i], paths[j]) < 0 })

	for _, raw := range paths {
		sinfPath := string(raw)
		appBundle := path.Dir(path.Dir(sinfPath))

		if !strings.HasSuffix(appBundle, ".app") {
			continue
		}

		installedSinf, err := d.readFile(sinfPath)
		if err != nil || len(installedSinf) > maxSinfBytes || !supportedSinf(installedSinf) {
			continue
		}

		infoData, err := d.readFile(appBundle + "/Info.plist")
		if err != nil {
			continue
		}

		var info map[string]any
		if _, err := plist.Unmarshal(infoData, &info); err != nil {
			continue
		}

		exec, ok := info["CFBundleExecutable"].(string)
		if !ok || exec == "" || exec == "." || exec == ".." || strings.Contains(exec, "/") {
			continue
		}

		return appBundle, exec, installedSinf, nil
	}

	return "", "", nil, errors.New("no installed App Store app has a supported license; install an app bought with this Apple ID and retry")
}

func fairplaydPID(d *sshDevice) (int, error) {
	listing, err := d.processes()
	if err != nil {
		return 0, err
	}

	var pids []int

	for _, line := range strings.Split(string(listing), "\n") {
		pid, comm, ok := splitProcessLine(line)
		if ok && fairplaydRe.MatchString(path.Base(comm)) {
			pids = append(pids, pid)
		}
	}

	if len(pids) != 1 {
		return 0, fmt.Errorf("expected one fairplayd process, found %d", len(pids))
	}

	return pids[0], nil
}

func restartFairplayd(d *sshDevice) (int, error) {
	previous, err := fairplaydPID(d)
	if err != nil {
		return 0, err
	}

	if _, err := d.run("kill -TERM "+strconv.Itoa(previous), nil); err != nil {
		return 0, fmt.Errorf("restart fairplayd: %w", err)
	}

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		current, err := fairplaydPID(d)
		if err != nil {
			current = previous
		}

		if current != previous {
			return current, nil
		}

		time.Sleep(100 * time.Millisecond)
	}

	return 0, errors.New("fairplayd did not restart")
}

func remotePIDs(d *sshDevice, executable string) []int {
	listing, err := d.processes()
	if err != nil {
		return nil
	}

	var out []int

	for _, line := range strings.Split(string(listing), "\n") {
		pid, comm, ok := splitProcessLine(line)
		if ok && comm == executable {
			out = append(out, pid)
		}
	}

	return out
}

func stopRemote(d *sshDevice, executable string) {
	for _, pid := range remotePIDs(d, executable) {
		d.run("kill -TERM "+strconv.Itoa(pid), nil)
	}
}

// observeUIDLayer starts the observer, fires the trigger once it is ready,
// and waits for the observer to capture the uid-layer. Mirrors retrieve.py
// observe_uid_layer, including the exit-code-3 direct-launch fallback.
func observeUIDLayer(d *sshDevice, program string, pid int, output, triggerProgram, executable string) (err error) {
	command := strings.Join([]string{
		shellQuote(program), "observe-uid-layer",
		strconv.Itoa(pid), shellQuote(output), "90",
	}, " ")

	observer, err := d.start(command, "observing FairPlay requests")
	if err != nil {
		return err
	}

	var direct *remoteCmd

	defer func() {
		stopRemote(d, triggerProgram)

		if direct != nil {
			stopRemote(d, executable)
			direct.stop()
		}

		if observer.running() {
			stopRemote(d, program)
			observer.wait(10 * time.Second)
		}
	}()

	if err := observer.waitReady(15 * time.Second); err != nil {
		return fmt.Errorf("FairPlay observer: %w", err)
	}

	triggerCommand := shellQuote(triggerProgram) + " " + shellQuote(executable)

	_, triggerErr, code, err := d.runCode(triggerCommand, 15*time.Second)
	if err != nil {
		return fmt.Errorf("FairPlay trigger: %w", err)
	}

	if code != 0 {
		if code != 3 {
			return fmt.Errorf("FairPlay trigger failed (exit %d): %s", code, strings.TrimSpace(string(triggerErr)))
		}

		direct, err = d.start(shellQuote(executable), "")
		if err != nil {
			return fmt.Errorf("direct launch: %w", err)
		}
	}

	if err := observer.wait(100 * time.Second); err != nil {
		return fmt.Errorf("FairPlay observation failed: %w", err)
	}

	return nil
}

func splitProcessLine(line string) (pid int, comm string, ok bool) {
	fields := strings.Fields(strings.TrimSpace(line))
	if len(fields) < 2 {
		return 0, "", false
	}

	pid, err := strconv.Atoi(fields[0])
	if err != nil {
		return 0, "", false
	}

	// comm may contain spaces; rejoin everything after the pid.
	rest := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), fields[0]))

	return pid, rest, true
}
