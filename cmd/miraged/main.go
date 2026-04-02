package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/internal/config"
	"github.com/travisbale/mirage/internal/daemon"
	"github.com/travisbale/mirage/internal/store/sqlite"
)

var Version = "dev"

func main() {
	var (
		configPath string
		debug      bool
	)

	root := &cobra.Command{
		Use:          "miraged",
		Short:        "Mirage AiTM phishing framework daemon",
		RunE:         func(cmd *cobra.Command, args []string) error { return cmd.Help() },
		SilenceUsage: true,
	}

	root.PersistentFlags().StringVar(&configPath, "config", "/etc/mirage/miraged.yaml", "path to config file")
	root.PersistentFlags().BoolVar(&debug, "debug", false, "enable debug logging")

	serveCmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the miraged daemon (default)",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runServe(cmd.Context(), configPath, debug)
		},
	}
	root.RunE = serveCmd.RunE

	validateCmd := &cobra.Command{
		Use:   "validate",
		Short: "Validate the config file and exit",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(configPath)
			if err != nil {
				return fmt.Errorf("invalid config: %w", err)
			}
			if err := cfg.Validate(); err != nil {
				return fmt.Errorf("invalid config: %w", err)
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

	inviteCmd := &cobra.Command{
		Use:   "invite <name>",
		Short: "Create an invite token for a new operator",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runInvite(configPath, args[0])
		},
	}

	root.AddCommand(serveCmd, validateCmd, versionCmd, inviteCmd)

	if err := run(root); err != nil {
		os.Exit(1)
	}
}

func run(root *cobra.Command) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	return root.ExecuteContext(ctx)
}

func runInvite(configPath, name string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	db, err := sqlite.Open(filepath.Join(cfg.DataDir, "data.db"))
	if err != nil {
		return fmt.Errorf("opening database: %w", err)
	}
	defer db.Close()

	svc := &aitm.OperatorService{Store: sqlite.NewOperatorStore(db)}
	invite, err := svc.Invite(name)
	if err != nil {
		return fmt.Errorf("creating invite: %w", err)
	}

	fmt.Printf("mirage server add --address %s:%d --secret-hostname %s --token %s\n",
		cfg.ExternalIPv4, cfg.HTTPSPort, cfg.API.SecretHostname, invite.Token)
	return nil
}

func runServe(ctx context.Context, configPath string, debug bool) error {
	level := slog.LevelInfo
	if debug {
		level = slog.LevelDebug
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	slog.SetDefault(logger)

	d, err := daemon.New(configPath, Version, logger)
	if err != nil {
		return err
	}

	d.Run(ctx)

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	d.Shutdown(shutdownCtx)

	return nil
}
