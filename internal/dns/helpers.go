package dns

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

// acmeChallengeKey returns the relative _acme-challenge label for a domain.
// e.g. "attacker.com" → "_acme-challenge"
//
//	"mail.attacker.com" → "_acme-challenge.mail"
func acmeChallengeKey(domain, zone string) string {
	if domain == zone {
		return "_acme-challenge"
	}
	sub := strings.TrimSuffix(domain, "."+zone)
	return "_acme-challenge." + sub
}

// acmeTXTValue computes the TXT record value for an ACME DNS-01 challenge.
// This is SHA-256(keyAuth) encoded as base64url (no padding).
// Returns the raw value without quotes. Some APIs (Route53, Gandi) require
// the caller to wrap TXT values in literal double-quotes; others (Cloudflare,
// builtin) do not.
func acmeTXTValue(keyAuth string) string {
	sum := sha256.Sum256([]byte(keyAuth))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// extractZone returns the registrable zone (last two labels) of a FQDN.
// e.g. "mail.sub.attacker.com" → "attacker.com"
func extractZone(domain string) string {
	parts := strings.Split(strings.TrimSuffix(domain, "."), ".")
	if len(parts) < 2 {
		return domain
	}
	return strings.Join(parts[len(parts)-2:], ".")
}

// fqdn builds a fully qualified domain name from a record name and zone.
// "@" or "" means the zone apex.
func fqdn(name, zone string) string {
	if name == "@" || name == "" {
		return dns.Fqdn(zone)
	}
	return dns.Fqdn(name + "." + zone)
}

// parseRecordType converts a string record type (e.g. "A", "TXT") to the
// corresponding miekg/dns constant. Returns an error for unsupported types.
func parseRecordType(typ string) (uint16, error) {
	switch strings.ToUpper(typ) {
	case "A":
		return dns.TypeA, nil
	case "AAAA":
		return dns.TypeAAAA, nil
	case "TXT":
		return dns.TypeTXT, nil
	case "NS":
		return dns.TypeNS, nil
	default:
		return 0, fmt.Errorf("unsupported record type %q", typ)
	}
}
