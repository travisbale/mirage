package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newServerCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "server",
		Short: "Manage miraged server endpoints",
	}
	cmd.AddCommand(
		newServerAddCmd(),
		newServerListCmd(),
		newServerRemoveCmd(),
		newServerDefaultCmd(),
	)
	return cmd
}

func newServerAddCmd() *cobra.Command {
	var (
		alias          string
		address        string
		secretHostname string
		certPath       string
		keyPath        string
		caCertPath     string
	)
	cmd := &cobra.Command{
		Use:   "add",
		Short: "Add a miraged server endpoint",
		RunE: func(cmd *cobra.Command, args []string) error {
			ep := Endpoint{
				Alias:          alias,
				Address:        address,
				SecretHostname: secretHostname,
				ClientCertPath: certPath,
				ClientKeyPath:  keyPath,
				ServerCACert:   caCertPath,
			}

			// Verify the connection before saving.
			client, err := newClient(&ep)
			if err != nil {
				return fmt.Errorf("building client: %w", err)
			}
			status, err := client.Status()
			if err != nil {
				return fmt.Errorf("connecting to server: %w", err)
			}

			cfg, cfgPath, err := resolveConfig(cmd)
			if err != nil {
				return err
			}
			cfg.addServer(ep)
			if cfg.DefaultServer == "" {
				cfg.DefaultServer = alias
			}
			if err := saveConfig(cfg, cfgPath); err != nil {
				return err
			}

			fmt.Printf("Connected to miraged %s — endpoint saved as %q\n", status.Version, alias)
			return nil
		},
	}
	cmd.Flags().StringVar(&alias, "alias", "default", "name for this server endpoint")
	cmd.Flags().StringVar(&address, "address", "", "server address (e.g. https://1.2.3.4:443)")
	cmd.Flags().StringVar(&secretHostname, "secret-hostname", "", "secret management hostname")
	cmd.Flags().StringVar(&certPath, "cert", "", "path to client certificate (PEM)")
	cmd.Flags().StringVar(&keyPath, "key", "", "path to client private key (PEM)")
	cmd.Flags().StringVar(&caCertPath, "ca-cert", "", "path to server CA certificate (PEM)")
	_ = cmd.MarkFlagRequired("address")
	_ = cmd.MarkFlagRequired("secret-hostname")
	_ = cmd.MarkFlagRequired("cert")
	_ = cmd.MarkFlagRequired("key")
	_ = cmd.MarkFlagRequired("ca-cert")
	return cmd
}

func newServerListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List configured server endpoints",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, _, err := resolveConfig(cmd)
			if err != nil {
				return err
			}
			if len(cfg.Servers) == 0 {
				fmt.Println("No servers configured. Run `mirage server add` to add one.")
				return nil
			}
			rows := make([][]string, len(cfg.Servers))
			for i, s := range cfg.Servers {
				def := ""
				if s.Alias == cfg.DefaultServer {
					def = "*"
				}
				rows[i] = []string{s.Alias, s.Address, s.SecretHostname, def}
			}
			printTable([]string{"ALIAS", "ADDRESS", "SECRET HOSTNAME", "DEFAULT"}, rows)
			return nil
		},
	}
}

func newServerRemoveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "remove <alias>",
		Short: "Remove a server endpoint",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, cfgPath, err := resolveConfig(cmd)
			if err != nil {
				return err
			}
			if err := cfg.removeServer(args[0]); err != nil {
				return err
			}
			if err := saveConfig(cfg, cfgPath); err != nil {
				return err
			}
			fmt.Printf("Removed server %q\n", args[0])
			return nil
		},
	}
}

func newServerDefaultCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "default <alias>",
		Short: "Set the default server endpoint",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, cfgPath, err := resolveConfig(cmd)
			if err != nil {
				return err
			}
			if _, err := cfg.findServer(args[0]); err != nil {
				return err
			}
			cfg.DefaultServer = args[0]
			if err := saveConfig(cfg, cfgPath); err != nil {
				return err
			}
			fmt.Printf("Default server set to %q\n", args[0])
			return nil
		},
	}
}
