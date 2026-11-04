package credmint

import "fmt"

func (d *sshDevice) prepareFreya() error {
	const detect = "if [ -x /usr/lib/suckmyd ] && [ -r /usr/share/jailbreak/signcert.p12 ] && command -v ldid >/dev/null 2>&1 && launchctl list suckmyd >/dev/null 2>&1; then printf freya; fi"

	out, err := d.run(detect, nil)
	if err != nil {
		return fmt.Errorf("detect Freya: %w", err)
	}

	if string(out) != "freya" {
		return nil
	}

	// Freya's amfid can kill ad-hoc helpers, so re-sign them with the existing
	// device certificate while preserving their entitlements.
	for _, name := range []string{"credential.ios", "driver.ios", "trigger.ios"} {
		program, err := d.path(name)
		if err != nil {
			return err
		}

		entitlements, err := d.path(name + ".entitlements.plist")
		if err != nil {
			return err
		}

		command := "ldid -e " + shellQuote(program) + " > " + shellQuote(entitlements) +
			" && ldid -K/usr/share/jailbreak/signcert.p12 -S" + shellQuote(entitlements) + " " + shellQuote(program)
		if _, err := d.run(command, nil); err != nil {
			return fmt.Errorf("prepare %s for Freya: %w", name, err)
		}
	}

	d.freya = true

	return nil
}

func (d *sshDevice) credentialCommand(program string) string {
	if d.freya {
		return "IPADECRYPT_FREYA_PLATFORMIZE=1 " + shellQuote(program)
	}

	return shellQuote(program)
}
