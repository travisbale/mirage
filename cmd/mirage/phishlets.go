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
			rows := make([][]string, len(resp.Items))
			for i, p := range resp.Items {
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
		baseDomain  string
		dnsProvider string
	)
	cmd := &cobra.Command{
		Use:   "enable <name>",
		Short: "Enable a phishlet",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := resolveClient(cmd)
			if err != nil {
				return err
			}
			p, err := client.EnablePhishlet(args[0], sdk.EnablePhishletRequest{
				Hostname:    hostname,
				BaseDomain:  baseDomain,
				DNSProvider: dnsProvider,
			})
			if err != nil {
				return err
			}
			if jsonMode(cmd) {
				return printJSON(p)
			}
			printPhishlet(p)
			return nil
		},
	}
	cmd.Flags().StringVar(&hostname, "hostname", "", "phishing hostname (e.g. login.phish.example.com)")
	cmd.Flags().StringVar(&baseDomain, "domain", "", "base domain")
	cmd.Flags().StringVar(&dnsProvider, "dns-provider", "", "DNS provider alias")
	_ = cmd.MarkFlagRequired("hostname")
	return cmd
}

func newPhishletsDisableCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "disable <name>",
		Short: "Disable a phishlet",
		Args:  cobra.ExactArgs(1),
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
			printPhishlet(p)
			return nil
		},
	}
}

func newPhishletsHideCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "hide <name>",
		Short: "Hide a phishlet (serve blank page to non-lure traffic)",
		Args:  cobra.ExactArgs(1),
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
			printPhishlet(p)
			return nil
		},
	}
}

func newPhishletsUnhideCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "unhide <name>",
		Short: "Unhide a phishlet",
		Args:  cobra.ExactArgs(1),
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
			printPhishlet(p)
			return nil
		},
	}
}

func printPhishlet(p *sdk.PhishletResponse) {
	fmt.Printf("Name:         %s\n", p.Name)
	fmt.Printf("Hostname:     %s\n", p.Hostname)
	fmt.Printf("Domain:       %s\n", p.BaseDomain)
	fmt.Printf("DNS Provider: %s\n", p.DNSProvider)
	fmt.Printf("Enabled:      %s\n", fmtBool(p.Enabled))
	fmt.Printf("Hidden:       %s\n", fmtBool(p.Hidden))
}
