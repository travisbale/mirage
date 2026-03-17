package main

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/travisbale/mirage/sdk"
)

func newBotguardCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "botguard",
		Short: "Manage bot signatures",
	}
	cmd.AddCommand(
		newBotguardListCmd(),
		newBotguardAddCmd(),
		newBotguardRemoveCmd(),
	)
	return cmd
}

func newBotguardListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List bot signatures",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := resolveClient(cmd)
			if err != nil {
				return err
			}
			resp, err := client.ListBotSignatures()
			if err != nil {
				return err
			}
			if jsonMode(cmd) {
				return printJSON(resp)
			}
			rows := make([][]string, len(resp.Items))
			for i := range resp.Items {
				s := &resp.Items[i]
				rows[i] = []string{s.JA4Hash, s.Description, fmtTime(s.AddedAt)}
			}
			printTable([]string{"JA4 HASH", "DESCRIPTION", "ADDED"}, rows)
			return nil
		},
	}
}

func newBotguardAddCmd() *cobra.Command {
	var desc string
	cmd := &cobra.Command{
		Use:   "add <ja4-hash>",
		Short: "Add a bot signature",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := resolveClient(cmd)
			if err != nil {
				return err
			}
			req := sdk.AddBotSignatureRequest{
				JA4Hash:     args[0],
				Description: desc,
			}
			if err := req.Validate(); err != nil {
				return err
			}
			sig, err := client.AddBotSignature(req)
			if err != nil {
				return err
			}
			fmt.Printf("Added bot signature %s\n", sig.JA4Hash)
			return nil
		},
	}
	cmd.Flags().StringVar(&desc, "desc", "", "description of the bot signature")
	return cmd
}

func newBotguardRemoveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "remove <ja4-hash>",
		Short: "Remove a bot signature",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := resolveClient(cmd)
			if err != nil {
				return err
			}
			if err := client.RemoveBotSignature(args[0]); err != nil {
				return err
			}
			fmt.Printf("Removed bot signature %s\n", args[0])
			return nil
		},
	}
}
