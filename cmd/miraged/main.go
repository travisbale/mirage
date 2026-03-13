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
	)

	root := &cobra.Command{
		Use:   "miraged",
		Short: "Mirage AiTM phishing framework daemon",
		// Running with no subcommand is equivalent to `miraged serve`.
		RunE: func(cmd *cobra.Command, args []string) error {
			return runServe(cmd.Context(), configPath, debug)
		},
		SilenceUsage: true,
	}

	root.PersistentFlags().StringVar(&configPath, "config", "/etc/mirage/miraged.yaml", "path to config file")
	root.PersistentFlags().BoolVar(&debug, "debug", false, "enable debug logging")

	serveCmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the miraged daemon",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runServe(cmd.Context(), configPath, debug)
		},
	}

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
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println(Version)
		},
	}

	root.AddCommand(serveCmd, validateCmd, versionCmd)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	if err := root.ExecuteContext(ctx); err != nil {
		os.Exit(1)
	}
}

func runServe(ctx context.Context, configPath string, debug bool) error {
	level := slog.LevelInfo
	if debug {
		level = slog.LevelDebug
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})))
	slog.Info("miraged starting", "version", Version)

	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("invalid config: %w", err)
	}

	slog.Info("config loaded",
		"domain", cfg.Domain,
		"external_ipv4", cfg.ExternalIPv4,
		"https_port", cfg.HTTPSPort,
		"dns_port", cfg.DNSPort,
	)

	slog.Info("miraged ready — waiting for shutdown signal")
	<-ctx.Done()
	slog.Info("shutdown signal received, exiting")
	return nil
}
