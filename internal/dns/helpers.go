package dns

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
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
func acmeTXTValue(keyAuth string) string {
	sum := sha256.Sum256([]byte(keyAuth))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// extractZone returns the registrable zone (last two labels) of a FQDN.
// e.g. "mail.sub.attacker.com" → "attacker.com"
func extractZone(fqdn string) string {
	parts := strings.Split(strings.TrimSuffix(fqdn, "."), ".")
	if len(parts) < 2 {
		return fqdn
	}
	return strings.Join(parts[len(parts)-2:], ".")
}
