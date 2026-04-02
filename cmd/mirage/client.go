package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/travisbale/mirage/sdk"
)

// newClient builds an sdk.Client for the given server by reading the
// cert files from disk and delegating transport construction to the SDK.
func newClient(server *Server) (*sdk.Client, error) {
	certPEM, err := os.ReadFile(server.ClientCertPath)
	if err != nil {
		return nil, fmt.Errorf("reading client cert: %w", err)
	}
	keyPEM, err := os.ReadFile(server.ClientKeyPath)
	if err != nil {
		return nil, fmt.Errorf("reading client key: %w", err)
	}
	caPEM, err := os.ReadFile(server.ServerCACert)
	if err != nil {
		return nil, fmt.Errorf("reading server CA: %w", err)
	}
	return sdk.NewClient(server.Address, server.SecretHostname, certPEM, keyPEM, caPEM)
}

// resolveClient loads the config, finds the target server, and returns a
// ready API client. All API subcommands call this at the start of RunE.
func resolveClient(cmd *cobra.Command) (*sdk.Client, error) {
	client, _, err := resolveClientAndServer(cmd)
	return client, err
}

// resolveClientAndServer is like resolveClient but also returns the server
// config, useful when the caller needs connection details like the address.
func resolveClientAndServer(cmd *cobra.Command) (*sdk.Client, *Server, error) {
	cfgPath, _ := cmd.Flags().GetString("config")
	if cfgPath == "" {
		var err error
		cfgPath, err = defaultConfigPath()
		if err != nil {
			return nil, nil, err
		}
	}
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		return nil, nil, err
	}
	alias, _ := cmd.Flags().GetString("server")
	server, err := cfg.findServer(alias)
	if err != nil {
		return nil, nil, err
	}
	client, err := newClient(server)
	if err != nil {
		return nil, nil, err
	}
	return client, server, nil
}
