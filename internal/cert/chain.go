package cert

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"
)

// certEntry wraps a certificate with an expiry for cache eviction.
type certEntry struct {
	cert      *tls.Certificate
	expiresAt time.Time
}

// certCache is a thread-safe in-memory cache keyed by lowercase hostname.
// Entries are evicted lazily on Get (on miss) and eagerly by a background
// ticker that runs every hour.
type certCache struct {
	mu      sync.RWMutex
	entries map[string]certEntry
}

func newCertCache() *certCache {
	cache := &certCache{entries: make(map[string]certEntry)}
	go cache.evictLoop()
	return cache
}

// Get returns the cached certificate for hostname, or nil if not cached or expired.
func (c *certCache) Get(hostname string) *tls.Certificate {
	c.mu.RLock()
	entry, ok := c.entries[hostname]
	c.mu.RUnlock()
	if !ok || time.Now().After(entry.expiresAt) {
		return nil
	}
	return entry.cert
}

// Set stores a certificate in the cache. expiresAt should be set to the
// certificate's NotAfter minus a renewal buffer (typically 30 days).
func (c *certCache) Set(hostname string, cert *tls.Certificate, expiresAt time.Time) {
	c.mu.Lock()
	c.entries[hostname] = certEntry{cert: cert, expiresAt: expiresAt}
	c.mu.Unlock()
}

// Invalidate removes a hostname from the cache, forcing the next request to
// re-fetch from the underlying source.
func (c *certCache) Invalidate(hostname string) {
	c.mu.Lock()
	delete(c.entries, hostname)
	c.mu.Unlock()
}

// evictLoop removes expired entries every hour.
func (c *certCache) evictLoop() {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		c.mu.Lock()
		for hostname, entry := range c.entries {
			if now.After(entry.expiresAt) {
				delete(c.entries, hostname)
			}
		}
		c.mu.Unlock()
	}
}

// ChainedCertSource tries each source in order and returns the first non-nil
// certificate. It maintains a shared in-memory cache so that a certificate
// resolved by any source is served immediately on subsequent requests without
// re-invoking the source chain.
//
// Sources are evaluated in the order they were passed to NewChainedCertSource.
// The canonical order for production use is:
//  1. FileCertSource       (operator-supplied PEM overrides)
//  2. WildcardACMECertSource (DNS-01 wildcard; used when DNSProvider is set)
//  3. PerHostACMECertSource  (CertMagic fallback)
//  4. SelfSignedCertSource   (dev mode only; last resort)
type certSource interface {
	GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error)
}

type ChainedCertSource struct {
	sources []certSource
	cache   *certCache
	logger  *slog.Logger
}

// NewChainedCertSource constructs a ChainedCertSource. sources must not be empty.
func NewChainedCertSource(logger *slog.Logger, sources ...certSource) *ChainedCertSource {
	return &ChainedCertSource{
		sources: sources,
		cache:   newCertCache(),
		logger:  logger,
	}
}

// GetCertificate is the tls.Config.GetCertificate callback.
// It checks the cache first, then walks the source chain.
func (c *ChainedCertSource) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	hostname := strings.ToLower(hello.ServerName)
	if hostname == "" {
		return nil, fmt.Errorf("cert: TLS ClientHello has no SNI")
	}

	// Fast path: cache hit.
	if cert := c.cache.Get(hostname); cert != nil {
		return cert, nil
	}

	// Slow path: walk the chain.
	for _, source := range c.sources {
		cert, err := source.GetCertificate(hello)
		if err != nil {
			return nil, fmt.Errorf("cert: source %T: %w", source, err)
		}
		if cert == nil {
			continue
		}

		expiry := leafExpiry(cert)
		c.cache.Set(hostname, cert, expiry)
		c.logger.Debug("cert resolved",
			"hostname", hostname,
			"source", fmt.Sprintf("%T", source),
			"expires", expiry,
		)
		return cert, nil
	}

	return nil, fmt.Errorf("cert: no source provided a certificate for %q", hostname)
}

// InvalidateCache removes a hostname from the chain's cache.
func (c *ChainedCertSource) InvalidateCache(hostname string) {
	c.cache.Invalidate(hostname)
}

// leafExpiry returns the NotAfter of the leaf certificate minus a 30-day
// renewal buffer, used as the cache TTL.
func leafExpiry(cert *tls.Certificate) time.Time {
	if len(cert.Certificate) == 0 {
		return time.Now().Add(24 * time.Hour)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return time.Now().Add(24 * time.Hour)
	}
	return leaf.NotAfter.Add(-30 * 24 * time.Hour)
}
