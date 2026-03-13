package dns

import (
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// recordKey is the lookup key for the in-memory zone store.
type recordKey struct {
	Name string // lowercase FQDN with trailing dot, e.g. "mail.attacker.com."
	Type uint16 // dns.TypeA, dns.TypeTXT, etc.
}

// recordUpdate is sent over the update channel to add or remove a record.
type recordUpdate struct {
	op  string // "upsert" or "delete"
	key recordKey
	rr  dns.RR // only set for "upsert"
}

// BuiltInDNSProvider is a self-contained authoritative DNS server.
// It is the default provider when no external DNS API is configured.
type BuiltInDNSProvider struct {
	externalIP string
	port       int

	mu      sync.RWMutex
	records map[recordKey]dns.RR

	updates chan recordUpdate
	server  *dns.Server
	logger  *slog.Logger
}

// NewBuiltInDNSProvider constructs the provider. Call Start to begin listening.
func NewBuiltInDNSProvider(externalIP string, port int) (*BuiltInDNSProvider, error) {
	return &BuiltInDNSProvider{
		externalIP: externalIP,
		port:       port,
		records:    make(map[recordKey]dns.RR),
		updates:    make(chan recordUpdate, 256),
		logger:     slog.Default().With("provider", "builtin"),
	}, nil
}

// Start launches the UDP listener in a background goroutine.
func (p *BuiltInDNSProvider) Start() error {
	mux := dns.NewServeMux()
	mux.HandleFunc(".", p.handleQuery)

	p.server = &dns.Server{
		Addr:    fmt.Sprintf("0.0.0.0:%d", p.port),
		Net:     "udp",
		Handler: mux,
	}

	go p.drainUpdates()

	started := make(chan struct{})
	p.server.NotifyStartedFunc = func() { close(started) }
	go func() {
		if err := p.server.ListenAndServe(); err != nil {
			p.logger.Error("dns server stopped", "error", err)
		}
	}()
	select {
	case <-started:
		return nil
	case <-time.After(3 * time.Second):
		return fmt.Errorf("builtin dns: server did not start within 3s")
	}
}

// Stop shuts down the UDP listener gracefully.
func (p *BuiltInDNSProvider) Stop() error {
	if p.server != nil {
		return p.server.Shutdown()
	}
	return nil
}

func (p *BuiltInDNSProvider) handleQuery(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	if len(r.Question) == 0 {
		w.WriteMsg(m)
		return
	}

	q := r.Question[0]
	name := strings.ToLower(q.Name)

	p.mu.RLock()
	rr, found := p.records[recordKey{Name: name, Type: q.Qtype}]
	p.mu.RUnlock()

	if found {
		m.Answer = append(m.Answer, rr)
	} else {
		m.Rcode = dns.RcodeNameError
	}

	if err := w.WriteMsg(m); err != nil {
		p.logger.Warn("dns write failed", "error", err)
	}
}

func (p *BuiltInDNSProvider) drainUpdates() {
	for upd := range p.updates {
		p.mu.Lock()
		switch upd.op {
		case "upsert":
			p.records[upd.key] = upd.rr
		case "delete":
			delete(p.records, upd.key)
		}
		p.mu.Unlock()
	}
}

func fqdn(name, zone string) string {
	if name == "@" || name == "" {
		return dns.Fqdn(zone)
	}
	return dns.Fqdn(name + "." + zone)
}

func (p *BuiltInDNSProvider) upsert(zone, name, typ, value string, ttl int) error {
	if ttl == 0 {
		ttl = 300
	}
	q := fqdn(name, zone)
	var rr dns.RR

	switch strings.ToUpper(typ) {
	case "A":
		ip := net.ParseIP(value)
		if ip == nil {
			return fmt.Errorf("builtin dns: invalid A record value %q", value)
		}
		rr = &dns.A{
			Hdr: dns.RR_Header{Name: q, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: uint32(ttl)},
			A:   ip.To4(),
		}
	case "AAAA":
		ip := net.ParseIP(value)
		if ip == nil {
			return fmt.Errorf("builtin dns: invalid AAAA record value %q", value)
		}
		rr = &dns.AAAA{
			Hdr:  dns.RR_Header{Name: q, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: uint32(ttl)},
			AAAA: ip.To16(),
		}
	case "TXT":
		rr = &dns.TXT{
			Hdr: dns.RR_Header{Name: q, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: uint32(ttl)},
			Txt: []string{value},
		}
	case "NS":
		rr = &dns.NS{
			Hdr: dns.RR_Header{Name: q, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: uint32(ttl)},
			Ns:  dns.Fqdn(value),
		}
	default:
		return fmt.Errorf("builtin dns: unsupported record type %q", typ)
	}

	key := recordKey{Name: q, Type: rr.Header().Rrtype}
	p.updates <- recordUpdate{op: "upsert", key: key, rr: rr}
	return nil
}

func (p *BuiltInDNSProvider) CreateRecord(zone, name, typ, value string, ttl int) error {
	return p.upsert(zone, name, typ, value, ttl)
}

func (p *BuiltInDNSProvider) UpdateRecord(zone, name, typ, value string, ttl int) error {
	return p.upsert(zone, name, typ, value, ttl)
}

func (p *BuiltInDNSProvider) DeleteRecord(zone, name, typ string) error {
	q := fqdn(name, zone)
	var qtype uint16
	switch strings.ToUpper(typ) {
	case "A":
		qtype = dns.TypeA
	case "AAAA":
		qtype = dns.TypeAAAA
	case "TXT":
		qtype = dns.TypeTXT
	case "NS":
		qtype = dns.TypeNS
	default:
		return fmt.Errorf("builtin dns: unsupported record type %q", typ)
	}
	p.updates <- recordUpdate{op: "delete", key: recordKey{Name: q, Type: qtype}}
	return nil
}

func (p *BuiltInDNSProvider) Present(domain, token, keyAuth string) error {
	zone := p.zoneOf(domain)
	label := acmeChallengeKey(domain, zone)
	return p.upsert(zone, label, "TXT", acmeTXTValue(keyAuth), 120)
}

func (p *BuiltInDNSProvider) CleanUp(domain, token, keyAuth string) error {
	zone := p.zoneOf(domain)
	label := acmeChallengeKey(domain, zone)
	return p.DeleteRecord(zone, label, "TXT")
}

func (p *BuiltInDNSProvider) Ping() error { return nil }

func (p *BuiltInDNSProvider) Name() string { return "builtin" }

// zoneOf extracts the base domain from a FQDN by finding the shortest suffix
// that has an NS record. Falls back to the last two labels if none is found.
func (p *BuiltInDNSProvider) zoneOf(domain string) string {
	parts := strings.Split(domain, ".")
	for i := 1; i < len(parts)-1; i++ {
		candidate := strings.Join(parts[i:], ".")
		p.mu.RLock()
		_, found := p.records[recordKey{Name: dns.Fqdn(candidate), Type: dns.TypeNS}]
		p.mu.RUnlock()
		if found {
			return candidate
		}
	}
	if len(parts) >= 2 {
		return strings.Join(parts[len(parts)-2:], ".")
	}
	return domain
}
