package mem

import (
	"sync"

	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/internal/store"
)

var _ aitm.LureStore = (*Lures)(nil)

type Lures struct {
	mu   sync.RWMutex
	data map[string]*aitm.Lure
	order []string // insertion order for ListLures
}

func NewLures() *Lures {
	return &Lures{data: make(map[string]*aitm.Lure)}
}

func (s *Lures) CreateLure(l *aitm.Lure) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.data[l.ID]; ok {
		return store.ErrConflict
	}
	cp := *l
	s.data[l.ID] = &cp
	s.order = append(s.order, l.ID)
	return nil
}

func (s *Lures) GetLure(id string) (*aitm.Lure, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	l, ok := s.data[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	cp := *l
	return &cp, nil
}

func (s *Lures) UpdateLure(l *aitm.Lure) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.data[l.ID]; !ok {
		return store.ErrNotFound
	}
	cp := *l
	s.data[l.ID] = &cp
	return nil
}

func (s *Lures) DeleteLure(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.data[id]; !ok {
		return store.ErrNotFound
	}
	delete(s.data, id)
	for i, oid := range s.order {
		if oid == id {
			s.order = append(s.order[:i], s.order[i+1:]...)
			break
		}
	}
	return nil
}

func (s *Lures) ListLures() ([]*aitm.Lure, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*aitm.Lure, 0, len(s.order))
	for _, id := range s.order {
		if l, ok := s.data[id]; ok {
			cp := *l
			out = append(out, &cp)
		}
	}
	return out, nil
}
