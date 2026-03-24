package main

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/travisbale/mirage/sdk"
)

func newOperatorsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "operators",
		Short: "Manage operators",
	}
	cmd.AddCommand(
		newOperatorsInviteCmd(),
		newOperatorsListCmd(),
		newOperatorsRemoveCmd(),
	)
	return cmd
}

func newOperatorsInviteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "invite <name>",
		Short: "Create an invite token for a new operator",
		Args:  requireOneArg,
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := resolveClient(cmd)
			if err != nil {
				return err
			}
			resp, err := client.InviteOperator(sdk.InviteOperatorRequest{Name: args[0]})
			if err != nil {
				return err
			}
			fmt.Printf("Invite token for %q:\n\n", args[0])
			fmt.Printf("  %s\n\n", resp.Token)
			fmt.Println("The new operator can enroll with:")
			fmt.Printf("  mirage server add --address <address> --secret-hostname <hostname> --token %s\n", resp.Token)
			return nil
		},
	}
}

func newOperatorsListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List registered operators",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := resolveClient(cmd)
			if err != nil {
				return err
			}
			resp, err := client.ListOperators()
			if err != nil {
				return err
			}
			if jsonMode(cmd) {
				return printJSON(resp)
			}
			if len(resp.Operators) == 0 {
				fmt.Println("No operators registered.")
				return nil
			}
			rows := make([][]string, len(resp.Operators))
			for i, op := range resp.Operators {
				rows[i] = []string{op.Name, fmtTime(op.CreatedAt)}
			}
			printTable([]string{"NAME", "CREATED"}, rows)
			return nil
		},
	}
}

func newOperatorsRemoveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "remove <name>",
		Short: "Remove an operator",
		Args:  requireOneArg,
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := resolveClient(cmd)
			if err != nil {
				return err
			}
			if err := client.DeleteOperator(args[0]); err != nil {
				return err
			}
			fmt.Printf("Removed operator %q\n", args[0])
			return nil
		},
	}
}
