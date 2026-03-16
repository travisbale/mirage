package proxy

import (
	"strings"
	"sync"
)

// ActiveHostnameSet is a concurrency-safe O(1) lookup set of lowercase phishing
// hostnames the proxy should intercept. Updated atomically when phishlets are
// enabled or disabled.
type ActiveHostnameSet struct {
	m sync.Map // key: lowercase hostname, value: struct{}
}

func (a *ActiveHostnameSet) Add(hostname string) {
	a.m.Store(strings.ToLower(hostname), struct{}{})
}

func (a *ActiveHostnameSet) Remove(hostname string) {
	a.m.Delete(strings.ToLower(hostname))
}

func (a *ActiveHostnameSet) Contains(hostname string) bool {
	_, ok := a.m.Load(strings.ToLower(hostname))
	return ok
}

// Snapshot returns a slice of all currently active hostnames.
// Use only for logging/debugging — not for hot-path lookups.
func (a *ActiveHostnameSet) Snapshot() []string {
	var hostnames []string
	a.m.Range(func(key, _ any) bool {
		hostnames = append(hostnames, key.(string))
		return true
	})
	return hostnames
}

// Compile-time check: ActiveHostnameSet satisfies HostnameSet.
var _ HostnameSet = (*ActiveHostnameSet)(nil)
