package main

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/travisbale/mirage/sdk"
)

func newLuresCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "lures",
		Short: "Manage phishing lures",
	}
	cmd.AddCommand(
		newLuresListCmd(),
		newLuresCreateCmd(),
		newLuresUpdateCmd(),
		newLuresDeleteCmd(),
		newLuresURLCmd(),
		newLuresPauseCmd(),
		newLuresUnpauseCmd(),
	)
	return cmd
}

func newLuresListCmd() *cobra.Command {
	var phishlet string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List lures",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := resolveClient(cmd)
			if err != nil {
				return err
			}
			resp, err := client.ListLures()
			if err != nil {
				return err
			}
			if jsonMode(cmd) {
				return printJSON(resp)
			}
			var items []sdk.LureResponse
			for i := range resp.Items {
				if phishlet == "" || resp.Items[i].Phishlet == phishlet {
					items = append(items, resp.Items[i])
				}
			}
			rows := make([][]string, len(items))
			for i := range items {
				rows[i] = []string{
					truncate(items[i].ID, 8),
					items[i].Phishlet,
					items[i].Hostname,
					items[i].Path,
					items[i].RedirectURL,
					fmtOptTime(items[i].PausedUntil),
				}
			}
			printTable([]string{"ID", "PHISHLET", "HOSTNAME", "PATH", "REDIRECT URL", "PAUSED UNTIL"}, rows)
			return nil
		},
	}
	cmd.Flags().StringVar(&phishlet, "phishlet", "", "filter by phishlet name")
	return cmd
}

func newLuresCreateCmd() *cobra.Command {
	var (
		redirectURL string
		spoofURL    string
		uaFilter    string
		redirector  string
		path        string
	)
	cmd := &cobra.Command{
		Use:   "create <phishlet>",
		Short: "Create a lure",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := resolveClient(cmd)
			if err != nil {
				return err
			}
			req := sdk.CreateLureRequest{
				Phishlet:    args[0],
				Path:        path,
				RedirectURL: redirectURL,
				SpoofURL:    spoofURL,
				UAFilter:    uaFilter,
				Redirector:  redirector,
			}
			if err := req.Validate(); err != nil {
				return err
			}
			lure, err := client.CreateLure(req)
			if err != nil {
				return err
			}
			if jsonMode(cmd) {
				return printJSON(lure)
			}
			fmt.Printf("Created lure %s on %s%s\n", truncate(lure.ID, 8), lure.Hostname, lure.Path)
			return nil
		},
	}
	cmd.Flags().StringVar(&path, "path", "", "lure path (default: random)")
	cmd.Flags().StringVar(&redirectURL, "redirect", "", "URL to redirect unauthenticated visitors")
	cmd.Flags().StringVar(&spoofURL, "spoof", "", "URL to display in the browser address bar")
	cmd.Flags().StringVar(&uaFilter, "ua-filter", "", "user-agent regex filter")
	cmd.Flags().StringVar(&redirector, "redirector", "", "redirector name")
	return cmd
}

func newLuresUpdateCmd() *cobra.Command {
	var (
		redirectURL string
		spoofURL    string
		uaFilter    string
		redirector  string
		ogTitle     string
		ogDesc      string
		ogImage     string
		ogURL       string
	)
	cmd := &cobra.Command{
		Use:   "update <id>",
		Short: "Update a lure",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := resolveClient(cmd)
			if err != nil {
				return err
			}
			req := sdk.UpdateLureRequest{}
			if cmd.Flags().Changed("redirect") {
				req.RedirectURL = &redirectURL
			}
			if cmd.Flags().Changed("spoof") {
				req.SpoofURL = &spoofURL
			}
			if cmd.Flags().Changed("ua-filter") {
				req.UAFilter = &uaFilter
			}
			if cmd.Flags().Changed("redirector") {
				req.Redirector = &redirector
			}
			if cmd.Flags().Changed("og-title") {
				req.OGTitle = &ogTitle
			}
			if cmd.Flags().Changed("og-desc") {
				req.OGDesc = &ogDesc
			}
			if cmd.Flags().Changed("og-image") {
				req.OGImage = &ogImage
			}
			if cmd.Flags().Changed("og-url") {
				req.OGURL = &ogURL
			}
			if err := req.Validate(); err != nil {
				return err
			}
			lure, err := client.UpdateLure(args[0], req)
			if err != nil {
				return err
			}
			if jsonMode(cmd) {
				return printJSON(lure)
			}
			fmt.Printf("Updated lure %s\n", truncate(lure.ID, 8))
			return nil
		},
	}
	cmd.Flags().StringVar(&redirectURL, "redirect", "", "URL to redirect unauthenticated visitors")
	cmd.Flags().StringVar(&spoofURL, "spoof", "", "URL to display in the browser address bar")
	cmd.Flags().StringVar(&uaFilter, "ua-filter", "", "user-agent regex filter")
	cmd.Flags().StringVar(&redirector, "redirector", "", "redirector name")
	cmd.Flags().StringVar(&ogTitle, "og-title", "", "Open Graph title")
	cmd.Flags().StringVar(&ogDesc, "og-desc", "", "Open Graph description")
	cmd.Flags().StringVar(&ogImage, "og-image", "", "Open Graph image URL")
	cmd.Flags().StringVar(&ogURL, "og-url", "", "Open Graph URL")
	return cmd
}

func newLuresDeleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "delete <id>",
		Short: "Delete a lure",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := resolveClient(cmd)
			if err != nil {
				return err
			}
			if err := client.DeleteLure(args[0]); err != nil {
				return err
			}
			fmt.Printf("Deleted lure %s\n", args[0])
			return nil
		},
	}
}

func newLuresURLCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "url <id> [key=value ...]",
		Short: "Generate a lure URL",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := resolveClient(cmd)
			if err != nil {
				return err
			}
			params := map[string]string{}
			for _, kv := range args[1:] {
				if k, v, ok := strings.Cut(kv, "="); ok {
					params[k] = v
				}
			}
			resp, err := client.GenerateLureURL(args[0], sdk.GenerateURLRequest{Params: params})
			if err != nil {
				return err
			}
			fmt.Println(resp.URL)
			return nil
		},
	}
}

func newLuresPauseCmd() *cobra.Command {
	var duration string
	cmd := &cobra.Command{
		Use:   "pause <id>",
		Short: "Pause a lure (e.g. --duration 15m, 2h, 1d)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := resolveClient(cmd)
			if err != nil {
				return err
			}
			// Normalise "d" suffix before sending to server.
			if len(duration) > 1 && duration[len(duration)-1] == 'd' {
				d, err := parseDuration(duration)
				if err != nil {
					return fmt.Errorf("invalid duration: %w", err)
				}
				duration = d.String()
			}
			req := sdk.PauseLureRequest{Duration: duration}
			if err := req.Validate(); err != nil {
				return err
			}
			if err := client.PauseLure(args[0], req); err != nil {
				return err
			}
			fmt.Printf("Lure %s paused for %s\n", truncate(args[0], 8), duration)
			return nil
		},
	}
	cmd.Flags().StringVar(&duration, "duration", "", "how long to pause (e.g. 15m, 2h, 1d)")
	_ = cmd.MarkFlagRequired("duration")
	return cmd
}

func newLuresUnpauseCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "unpause <id>",
		Short: "Unpause a lure",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := resolveClient(cmd)
			if err != nil {
				return err
			}
			if err := client.UnpauseLure(args[0]); err != nil {
				return err
			}
			fmt.Printf("Lure %s unpaused\n", truncate(args[0], 8))
			return nil
		},
	}
}
