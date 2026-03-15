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
		return newREPLCmd().RunE(cmd, args)
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
		newREPLCmd(),
		newDeployCmd(),
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
