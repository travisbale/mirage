package mem

import (
	"sync"

	"github.com/travisbale/mirage/aitm"
	"github.com/travisbale/mirage/store"
)

var _ aitm.PhishletStore = (*Phishlets)(nil)

type Phishlets struct {
	mu          sync.RWMutex
	configs     map[string]*aitm.PhishletConfig
	subPhishlets map[string]*aitm.SubPhishlet
}

func NewPhishlets() *Phishlets {
	return &Phishlets{
		configs:      make(map[string]*aitm.PhishletConfig),
		subPhishlets: make(map[string]*aitm.SubPhishlet),
	}
}

func (s *Phishlets) GetPhishletConfig(name string) (*aitm.PhishletConfig, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cfg, ok := s.configs[name]
	if !ok {
		return nil, store.ErrNotFound
	}
	cp := *cfg
	return &cp, nil
}

func (s *Phishlets) SetPhishletConfig(cfg *aitm.PhishletConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *cfg
	s.configs[cfg.Name] = &cp
	return nil
}

func (s *Phishlets) ListPhishletConfigs() ([]*aitm.PhishletConfig, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*aitm.PhishletConfig, 0, len(s.configs))
	for _, cfg := range s.configs {
		cp := *cfg
		out = append(out, &cp)
	}
	return out, nil
}

func (s *Phishlets) DeletePhishletConfig(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.configs[name]; !ok {
		return store.ErrNotFound
	}
	delete(s.configs, name)
	return nil
}

func (s *Phishlets) CreateSubPhishlet(sp *aitm.SubPhishlet) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.subPhishlets[sp.Name]; ok {
		return store.ErrConflict
	}
	cp := *sp
	s.subPhishlets[sp.Name] = &cp
	return nil
}

func (s *Phishlets) GetSubPhishlet(name string) (*aitm.SubPhishlet, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sp, ok := s.subPhishlets[name]
	if !ok {
		return nil, store.ErrNotFound
	}
	cp := *sp
	return &cp, nil
}

func (s *Phishlets) ListSubPhishlets(parent string) ([]*aitm.SubPhishlet, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*aitm.SubPhishlet
	for _, sp := range s.subPhishlets {
		if parent != "" && sp.ParentName != parent {
			continue
		}
		cp := *sp
		out = append(out, &cp)
	}
	return out, nil
}

func (s *Phishlets) DeleteSubPhishlet(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.subPhishlets[name]; !ok {
		return store.ErrNotFound
	}
	delete(s.subPhishlets, name)
	return nil
}
