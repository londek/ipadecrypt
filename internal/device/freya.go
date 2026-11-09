package device

import (
	"fmt"
	"strings"
)

func (c *Client) prepareFreyaHelper(helperPath string) error {
	const detect = "if [ -x /usr/lib/suckmyd ] && " +
		"[ -r /usr/share/jailbreak/signcert.p12 ] && " +
		"command -v ldid >/dev/null 2>&1 && " +
		"launchctl list suckmyd >/dev/null 2>&1; then printf freya; fi"

	out, errOut, code, err := c.RunSudo("sh -c " + shellQuote(detect))
	if err != nil {
		return fmt.Errorf("detect Freya: %w", err)
	}

	if code != 0 {
		return fmt.Errorf("detect Freya: exit %d: %s", code, strings.TrimSpace(errOut))
	}

	if strings.TrimSpace(out) != "freya" {
		return nil
	}

	// Freya's amfid kills the ad-hoc helper before main; preserve its
	// entitlements but replace the signature with the device certificate.
	entitlementsPath := helperPath + ".entitlements.plist"
	command := "ldid -e " + shellQuote(helperPath) + " > " + shellQuote(entitlementsPath) +
		" && ldid -K/usr/share/jailbreak/signcert.p12 -S" + shellQuote(entitlementsPath) + " " + shellQuote(helperPath)

	_, errOut, code, err = c.RunSudo("sh -c " + shellQuote(command))
	if err != nil {
		return fmt.Errorf("prepare helper for Freya: %w", err)
	}

	if code != 0 {
		return fmt.Errorf("prepare helper for Freya: exit %d: %s", code, strings.TrimSpace(errOut))
	}

	return nil
}
