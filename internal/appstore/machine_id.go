package appstore

import (
	"encoding/hex"
	"fmt"
	"net"
	"strings"
)

// machineIdentity derives the Configurator GUID and the raw machine id (the MAC
// address bytes) used to establish the SAP signing session from the same MAC
// address that seeds the GUID.
func machineIdentity(macAddress string) (string, []byte, error) {
	hardwareAddress, err := net.ParseMAC(macAddress)
	if err != nil {
		return "", nil, fmt.Errorf("failed to parse mac address: %w", err)
	}

	if len(hardwareAddress) == 0 || len(hardwareAddress) > 20 {
		return "", nil, fmt.Errorf("hardware address must contain between 1 and 20 bytes, got %d", len(hardwareAddress))
	}

	machineID := append([]byte(nil), hardwareAddress...)
	guid := strings.ToUpper(hex.EncodeToString(machineID))

	return guid, machineID, nil
}
