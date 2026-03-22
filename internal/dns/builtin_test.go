package dns_test

import (
	"context"
	"strings"
	"testing"
	"time"

	mdns "github.com/miekg/dns"

	"github.com/travisbale/mirage/internal/dns"
)

func TestBuiltInProvider_ARecord(t *testing.T) {
	p, err := dns.NewBuiltInDNSProvider("1.2.3.4", 15353)
	if err != nil {
		t.Fatalf("NewBuiltInDNSProvider: %v", err)
	}
	if err := p.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { p.Stop() })

	if err := p.CreateRecord(context.Background(), "attacker.com", "mail", "A", "1.2.3.4", 300); err != nil {
		t.Fatalf("CreateRecord: %v", err)
	}
	time.Sleep(10 * time.Millisecond)

	c := new(mdns.Client)
	m := new(mdns.Msg)
	m.SetQuestion("mail.attacker.com.", mdns.TypeA)
	r, _, err := c.Exchange(m, "127.0.0.1:15353")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if len(r.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(r.Answer))
	}
	a, ok := r.Answer[0].(*mdns.A)
	if !ok {
		t.Fatalf("expected *dns.A, got %T", r.Answer[0])
	}
	if a.A.String() != "1.2.3.4" {
		t.Errorf("A record: got %q, want %q", a.A.String(), "1.2.3.4")
	}
}

func TestBuiltInProvider_DeleteRecord_NXDOMAIN(t *testing.T) {
	p, _ := dns.NewBuiltInDNSProvider("1.2.3.4", 15354)
	if err := p.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { p.Stop() })

	p.CreateRecord(context.Background(), "attacker.com", "gone", "A", "1.2.3.4", 300)
	time.Sleep(10 * time.Millisecond)
	p.DeleteRecord(context.Background(), "attacker.com", "gone", "A")
	time.Sleep(10 * time.Millisecond)

	c := new(mdns.Client)
	m := new(mdns.Msg)
	m.SetQuestion("gone.attacker.com.", mdns.TypeA)
	r, _, err := c.Exchange(m, "127.0.0.1:15354")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if r.Rcode != mdns.RcodeNameError {
		t.Errorf("expected NXDOMAIN, got rcode %d", r.Rcode)
	}
}

func TestBuiltInProvider_Present_CleanUp(t *testing.T) {
	p, _ := dns.NewBuiltInDNSProvider("1.2.3.4", 15355)
	if err := p.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { p.Stop() })

	if err := p.Present(context.Background(), "attacker.com", "token", "keyAuth"); err != nil {
		t.Fatalf("Present: %v", err)
	}
	time.Sleep(10 * time.Millisecond)

	c := new(mdns.Client)
	m := new(mdns.Msg)
	m.SetQuestion("_acme-challenge.attacker.com.", mdns.TypeTXT)
	r, _, err := c.Exchange(m, "127.0.0.1:15355")
	if err != nil {
		t.Fatalf("Exchange after Present: %v", err)
	}
	if len(r.Answer) == 0 {
		t.Fatal("expected TXT answer after Present, got none")
	}

	if err := p.CleanUp(context.Background(), "attacker.com", "token", "keyAuth"); err != nil {
		t.Fatalf("CleanUp: %v", err)
	}
	time.Sleep(10 * time.Millisecond)

	r, _, err = c.Exchange(m, "127.0.0.1:15355")
	if err != nil {
		t.Fatalf("Exchange after CleanUp: %v", err)
	}
	if r.Rcode != mdns.RcodeNameError {
		t.Errorf("expected NXDOMAIN after CleanUp, got rcode %d", r.Rcode)
	}
}

func TestBuiltInProvider_Ping(t *testing.T) {
	p, _ := dns.NewBuiltInDNSProvider("1.2.3.4", 0)
	if err := p.Ping(context.Background()); err != nil {
		t.Errorf("Ping: %v", err)
	}
	if p.Name() != "builtin" {
		t.Errorf("Name: got %q, want %q", p.Name(), "builtin")
	}
}

func TestBuiltInProvider_UnsupportedRecordType(t *testing.T) {
	p, _ := dns.NewBuiltInDNSProvider("1.2.3.4", 0)
	err := p.CreateRecord(context.Background(), "attacker.com", "mail", "MX", "mx.attacker.com", 300)
	if err == nil {
		t.Fatal("expected error for unsupported record type, got nil")
	}
	if !strings.Contains(err.Error(), "unsupported record type") {
		t.Errorf("error %q does not mention unsupported record type", err.Error())
	}
}

func TestBuiltInProvider_InvalidARecordValue(t *testing.T) {
	p, _ := dns.NewBuiltInDNSProvider("1.2.3.4", 0)
	err := p.CreateRecord(context.Background(), "attacker.com", "mail", "A", "not-an-ip", 300)
	if err == nil {
		t.Fatal("expected error for invalid A record value, got nil")
	}
	if !strings.Contains(err.Error(), "invalid A record value") {
		t.Errorf("error %q does not mention invalid A record value", err.Error())
	}
}

func TestBuiltInProvider_DeleteUnsupportedType(t *testing.T) {
	p, _ := dns.NewBuiltInDNSProvider("1.2.3.4", 0)
	err := p.DeleteRecord(context.Background(), "attacker.com", "mail", "SRV")
	if err == nil {
		t.Fatal("expected error for unsupported record type, got nil")
	}
}
