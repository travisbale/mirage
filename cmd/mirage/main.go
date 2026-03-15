package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
)

var Version = "dev"

func main() {
	root := newRootCmd()

	// When invoked with no subcommand, drop into the REPL if a server is configured.
	root.RunE = func(cmd *cobra.Command, args []string) error {
		cfg, cfgPath, err := resolveConfig(cmd)
		if err != nil || len(cfg.Servers) == 0 {
			return cmd.Help()
		}
		alias, _ := cmd.Flags().GetString("server")
		ep, err := cfg.findServer(alias)
		if err != nil {
			return err
		}
		return runREPL(cmd.Context(), ep.Alias, cfgPath)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	if err := root.ExecuteContext(ctx); err != nil {
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:          "mirage",
		Short:        "Mirage CLI — manage miraged instances",
		SilenceUsage: true,
	}

	root.PersistentFlags().String("server", "", "server alias (default: client.json default_server)")
	root.PersistentFlags().Bool("json", false, "output raw JSON instead of formatted tables")
	root.PersistentFlags().String("config", "", "path to client.json (default: ~/.mirage/client.json)")

	root.AddCommand(
		newServerCmd(),
		newSessionsCmd(),
		newLuresCmd(),
		newPhishletsCmd(),
		newBlacklistCmd(),
		newBotguardCmd(),
		&cobra.Command{
			Use:   "version",
			Short: "Print the version and exit",
			Run: func(cmd *cobra.Command, args []string) {
				fmt.Println(Version)
			},
		},
	)

	return root
}
