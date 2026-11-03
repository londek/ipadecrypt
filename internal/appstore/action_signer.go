package appstore

import (
	"context"
	"fmt"

	apphttp "github.com/londek/ipadecrypt/internal/apphttp"
	"github.com/londek/ipadecrypt/internal/sap"
)

// SAPConfig is the signing configuration Apple returns in the bag. The login
// request body must be signed with a machine identity established against the
// setup/certificate endpoints before it is accepted.
type SAPConfig struct {
	AuthEndpoint   string
	SetupURL       string
	CertificateURL string
	Version        uint32
}

// ActionSigner signs App Store request bodies with a virtual machine identity.
type ActionSigner interface {
	apphttp.ActionSigner
	Close() error
}

// ActionSignerFactory builds a signer from the bag's SAP config and the caller's
// machine id (the MAC address bytes).
type ActionSignerFactory func(config SAPConfig, machineID []byte) (ActionSigner, error)

// frameworkActionSignerFactory is the built-in SAP signer backed by Apple's
// FairPlay runtime. Its setup/certificate exchange runs through the emulated
// AppleMediaServices backend (client), so it is attested like every other store
// request.
func frameworkActionSignerFactory(client apphttp.Executor) ActionSignerFactory {
	return func(config SAPConfig, machineID []byte) (ActionSigner, error) {
		signer, err := sap.NewSigner(context.Background(), sap.Config{
			SetupURL:       config.SetupURL,
			CertificateURL: config.CertificateURL,
			Version:        config.Version,
			HardwareID:     machineID,
			HTTPClient:     client,
		})
		if err != nil {
			return nil, fmt.Errorf("create SAP signer: %w", err)
		}

		return signer, nil
	}
}
