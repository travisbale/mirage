package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/travisbale/mirage/internal/config"
)

var Version = "dev"

func main() {
	var (
		configPath string
		debug      bool
		developer  bool
	)

	root := &cobra.Command{
		Use:          "miraged",
		Short:        "Mirage AiTM phishing framework daemon",
		RunE:         func(cmd *cobra.Command, args []string) error { return cmd.Help() },
		SilenceUsage: true,
	}

	root.PersistentFlags().StringVar(&configPath, "config", "/etc/mirage/miraged.yaml", "path to config file")
	root.PersistentFlags().BoolVar(&debug, "debug", false, "enable debug logging")
	root.PersistentFlags().BoolVar(&developer, "developer", false, "use self-signed certs (no ACME); safe for local testing")

	serveCmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the miraged daemon (default)",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runServe(cmd.Context(), configPath, debug, developer)
		},
	}
	root.RunE = serveCmd.RunE // serve is the default when no subcommand is given

	validateCmd := &cobra.Command{
		Use:   "validate",
		Short: "Validate the config file and exit",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(configPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "INVALID: %v\n", err)
				os.Exit(1)
			}
			if err := cfg.Validate(); err != nil {
				fmt.Fprintf(os.Stderr, "INVALID: %v\n", err)
				os.Exit(1)
			}
			fmt.Println("OK")
			return nil
		},
	}

	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Print the version and exit",
		Run:   func(cmd *cobra.Command, args []string) { fmt.Println(Version) },
	}

	root.AddCommand(serveCmd, validateCmd, versionCmd)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	if err := root.ExecuteContext(ctx); err != nil {
		os.Exit(1)
	}
}

func runServe(ctx context.Context, configPath string, debug, developer bool) error {
	level := slog.LevelInfo
	if debug {
		level = slog.LevelDebug
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	slog.SetDefault(logger)

	daemon, err := NewDaemon(ctx, configPath, developer, logger)
	if err != nil {
		return err
	}

	daemon.Run(ctx)
	daemon.Shutdown()

	return nil
}
