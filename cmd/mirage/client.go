package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/travisbale/mirage/sdk"
)

// newClient builds an sdk.Client for the given endpoint by reading the
// cert files from disk and delegating transport construction to the SDK.
func newClient(ep *Endpoint) (*sdk.Client, error) {
	certPEM, err := os.ReadFile(ep.ClientCertPath)
	if err != nil {
		return nil, fmt.Errorf("reading client cert: %w", err)
	}
	keyPEM, err := os.ReadFile(ep.ClientKeyPath)
	if err != nil {
		return nil, fmt.Errorf("reading client key: %w", err)
	}
	caPEM, err := os.ReadFile(ep.ServerCACert)
	if err != nil {
		return nil, fmt.Errorf("reading server CA: %w", err)
	}
	return sdk.NewClient(ep.Address, ep.SecretHostname, certPEM, keyPEM, caPEM)
}

// resolveClient loads the config, finds the target endpoint, and returns a
// ready API client. All API subcommands call this at the start of RunE.
func resolveClient(cmd *cobra.Command) (*sdk.Client, error) {
	cfgPath, _ := cmd.Flags().GetString("config")
	if cfgPath == "" {
		var err error
		cfgPath, err = defaultConfigPath()
		if err != nil {
			return nil, err
		}
	}
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		return nil, err
	}
	alias, _ := cmd.Flags().GetString("server")
	ep, err := cfg.findServer(alias)
	if err != nil {
		return nil, err
	}
	return newClient(ep)
}
