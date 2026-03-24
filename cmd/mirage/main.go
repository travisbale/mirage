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

// requireOneArg is a cobra Args validator that replaces ExactArgs(1) with a
// message that shows the correct usage instead of "accepts 1 arg(s), received 0".
func requireOneArg(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: %s", cmd.UseLine())
	}
	return cobra.ExactArgs(1)(cmd, args)
}

func main() {
	if err := run(); err != nil {
		os.Exit(1)
	}
}

func run() error {
	root := newRootCmd()

	// When invoked with no subcommand, drop into the REPL.
	root.RunE = func(cmd *cobra.Command, args []string) error {
		return newREPLCmd().RunE(cmd, args)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	return root.ExecuteContext(ctx)
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
		newNotifyCmd(),
		newOperatorsCmd(),
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
