package main

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/travisbale/mirage/sdk"
)

func newBlacklistCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "blacklist",
		Short: "Manage the IP blacklist",
	}
	cmd.AddCommand(
		newBlacklistListCmd(),
		newBlacklistAddCmd(),
		newBlacklistRemoveCmd(),
	)
	return cmd
}

func newBlacklistListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List blacklisted entries",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := resolveClient(cmd)
			if err != nil {
				return err
			}
			resp, err := client.ListBlacklist()
			if err != nil {
				return err
			}
			if jsonMode(cmd) {
				return printJSON(resp)
			}
			rows := make([][]string, len(resp.Items))
			for i, e := range resp.Items {
				rows[i] = []string{e.Value}
			}
			printTable([]string{"ENTRY"}, rows)
			return nil
		},
	}
}

func newBlacklistAddCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "add <ip-or-cidr>",
		Short: "Add an entry to the blacklist",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := resolveClient(cmd)
			if err != nil {
				return err
			}
			entry, err := client.AddBlacklistEntry(sdk.AddBlacklistEntryRequest{Value: args[0]})
			if err != nil {
				return err
			}
			fmt.Printf("Blacklisted %s\n", entry.Value)
			return nil
		},
	}
}

func newBlacklistRemoveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "remove <ip-or-cidr>",
		Short: "Remove an entry from the blacklist",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := resolveClient(cmd)
			if err != nil {
				return err
			}
			if err := client.RemoveBlacklistEntry(args[0]); err != nil {
				return err
			}
			fmt.Printf("Removed %s from blacklist\n", args[0])
			return nil
		},
	}
}
