// Package mem provides in-memory implementations of the aitm store interfaces
// for use in tests across other packages.
package mem

import (
	"sort"
	"sync"

	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/internal/store"
)

var _ aitm.SessionStore = (*Sessions)(nil)

type Sessions struct {
	mu   sync.RWMutex
	data map[string]*aitm.Session
}

func NewSessions() *Sessions {
	return &Sessions{data: make(map[string]*aitm.Session)}
}

func (s *Sessions) CreateSession(sess *aitm.Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.data[sess.ID]; ok {
		return store.ErrConflict
	}
	cp := *sess
	s.data[sess.ID] = &cp
	return nil
}

func (s *Sessions) GetSession(id string) (*aitm.Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sess, ok := s.data[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	cp := *sess
	return &cp, nil
}

func (s *Sessions) UpdateSession(sess *aitm.Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.data[sess.ID]; !ok {
		return store.ErrNotFound
	}
	cp := *sess
	s.data[sess.ID] = &cp
	return nil
}

func (s *Sessions) DeleteSession(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.data[id]; !ok {
		return store.ErrNotFound
	}
	delete(s.data, id)
	return nil
}

func (s *Sessions) ListSessions(f aitm.SessionFilter) ([]*aitm.Session, error) {
	if f.CompletedOnly && f.IncompleteOnly {
		return nil, store.ErrInvalidFilter
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	var out []*aitm.Session
	for _, sess := range s.data {
		if f.Phishlet != "" && sess.Phishlet != f.Phishlet {
			continue
		}
		if f.CompletedOnly && sess.CompletedAt == nil {
			continue
		}
		if f.IncompleteOnly && sess.CompletedAt != nil {
			continue
		}
		if !f.After.IsZero() && !sess.StartedAt.After(f.After) {
			continue
		}
		if !f.Before.IsZero() && !sess.StartedAt.Before(f.Before) {
			continue
		}
		cp := *sess
		out = append(out, &cp)
	}

	sort.Slice(out, func(i, j int) bool {
		return out[i].StartedAt.After(out[j].StartedAt)
	})
	if f.Offset < len(out) {
		out = out[f.Offset:]
	} else {
		out = nil
	}
	if f.Limit > 0 && f.Limit < len(out) {
		out = out[:f.Limit]
	}
	return out, nil
}
