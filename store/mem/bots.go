package mem

import (
	"sort"
	"sync"

	"github.com/travisbale/mirage/aitm"
	"github.com/travisbale/mirage/store"
)

var _ aitm.BotStore = (*Bots)(nil)

type Bots struct {
	mu   sync.RWMutex
	data map[string]*aitm.BotTelemetry // keyed by ID
}

func NewBots() *Bots {
	return &Bots{data: make(map[string]*aitm.BotTelemetry)}
}

func (s *Bots) StoreBotTelemetry(t *aitm.BotTelemetry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.data[t.ID]; ok {
		return store.ErrConflict
	}
	cp := *t
	s.data[t.ID] = &cp
	return nil
}

func (s *Bots) GetBotTelemetry(sessionID string) ([]*aitm.BotTelemetry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*aitm.BotTelemetry
	for _, t := range s.data {
		if t.SessionID == sessionID {
			cp := *t
			out = append(out, &cp)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].CollectedAt.Before(out[j].CollectedAt)
	})
	return out, nil
}

func (s *Bots) DeleteBotTelemetry(sessionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, t := range s.data {
		if t.SessionID == sessionID {
			delete(s.data, id)
		}
	}
	return nil
}
