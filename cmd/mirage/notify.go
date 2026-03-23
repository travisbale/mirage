package main

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/travisbale/mirage/sdk"
)

func newNotifyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "notify",
		Short: "Manage notification channels",
	}
	cmd.AddCommand(
		newNotifyListCmd(),
		newNotifyAddCmd(),
		newNotifyRemoveCmd(),
		newNotifyTestCmd(),
	)
	return cmd
}

func newNotifyListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List notification channels",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := resolveClient(cmd)
			if err != nil {
				return err
			}
			resp, err := client.ListNotificationChannels()
			if err != nil {
				return err
			}
			if jsonMode(cmd) {
				return printJSON(resp)
			}
			if len(resp.Channels) == 0 {
				fmt.Println("No notification channels configured.")
				return nil
			}
			rows := make([][]string, len(resp.Channels))
			for i, ch := range resp.Channels {
				filter := "all"
				if len(ch.Filter) > 0 {
					filter = strings.Join(ch.Filter, ", ")
				}
				rows[i] = []string{
					ch.ID,
					string(ch.Type),
					ch.URL,
					filter,
					fmtBool(ch.Enabled),
					fmtTime(ch.CreatedAt),
				}
			}
			printTable([]string{"ID", "TYPE", "URL", "FILTER", "ENABLED", "CREATED"}, rows)
			return nil
		},
	}
}

func newNotifyAddCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "add",
		Short: "Add a notification channel",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := resolveClient(cmd)
			if err != nil {
				return err
			}

			channelType, _ := cmd.Flags().GetString("type")
			url, _ := cmd.Flags().GetString("url")
			authHeader, _ := cmd.Flags().GetString("auth-header")
			filterStr, _ := cmd.Flags().GetString("filter")

			var filter []string
			if filterStr != "" {
				filter = strings.Split(filterStr, ",")
				for i := range filter {
					filter[i] = strings.TrimSpace(filter[i])
				}
			}

			req := sdk.CreateNotificationChannelRequest{
				Type:       sdk.ChannelType(channelType),
				URL:        url,
				AuthHeader: authHeader,
				Filter:     filter,
			}
			if err := req.Validate(); err != nil {
				return err
			}

			channel, err := client.CreateNotificationChannel(req)
			if err != nil {
				return err
			}
			fmt.Printf("Created %s channel %s\n", channel.Type, channel.ID)
			return nil
		},
	}
	cmd.Flags().String("type", "", "channel type (webhook or slack)")
	cmd.Flags().String("url", "", "destination URL")
	cmd.Flags().String("auth-header", "", "Authorization header value (webhook only)")
	cmd.Flags().String("filter", "", "comma-separated event types to filter (empty = all)")
	_ = cmd.MarkFlagRequired("type")
	_ = cmd.MarkFlagRequired("url")
	return cmd
}

func newNotifyRemoveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "remove <id>",
		Short: "Remove a notification channel",
		Args:  requireOneArg,
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := resolveClient(cmd)
			if err != nil {
				return err
			}
			if err := client.DeleteNotificationChannel(args[0]); err != nil {
				return err
			}
			fmt.Printf("Removed notification channel %s\n", args[0])
			return nil
		},
	}
}

func newNotifyTestCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "test <id>",
		Short: "Send a test notification to a channel",
		Args:  requireOneArg,
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := resolveClient(cmd)
			if err != nil {
				return err
			}
			if err := client.TestNotificationChannel(args[0]); err != nil {
				return err
			}
			fmt.Println("Test notification sent successfully.")
			return nil
		},
	}
}
