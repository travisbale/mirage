package phishlet

import (
	"fmt"
	"strings"

	"github.com/travisbale/mirage/internal/aitm"
)

// ParseError is a single field-level problem found while validating or
// compiling a phishlet YAML file.
type ParseError struct {
	// File is the path of the YAML file being parsed.
	File string

	// Field is the dot-separated path to the problematic field,
	// e.g. "sub_filters[0].search" or "proxy_hosts[1].phish_sub".
	Field string

	// Message describes the problem in human-readable form.
	Message string
}

func (e ParseError) Error() string {
	if e.File != "" {
		return fmt.Sprintf("%s: %s: %s", e.File, e.Field, e.Message)
	}
	return fmt.Sprintf("%s: %s", e.Field, e.Message)
}

// ParseErrors is a collection of ParseError values returned when multiple
// problems are found in a single phishlet file.
type ParseErrors []ParseError

func (p ParseErrors) Error() string {
	msgs := make([]string, len(p))
	for i, e := range p {
		msgs[i] = e.Error()
	}
	return strings.Join(msgs, "\n")
}

// Is implements errors.Is for ParseErrors so callers can use
// errors.Is(err, ErrParseError) as a type check.
func (p ParseErrors) Is(target error) bool {
	_, ok := target.(ParseErrors)
	return ok
}

// ErrParseError is a sentinel that can be used with errors.Is to check
// whether an error came from phishlet parsing.
var ErrParseError = ParseErrors{}

// CollisionError describes a hostname collision detected by Validate.
type CollisionError struct {
	// NewHostname is the hostname declared by the phishlet being validated.
	NewHostname string
	// ConflictingPhishlet is the name of the already-active phishlet that owns the hostname.
	ConflictingPhishlet string
}

func (e CollisionError) Error() string {
	return fmt.Sprintf("hostname %q conflicts with active phishlet %q",
		e.NewHostname, e.ConflictingPhishlet)
}

// Validate checks a compiled Phishlet against the list of currently active
// phishlets for hostname collisions. It returns all conflicts found, not just the first.
//
// A collision occurs when a proxy_host in the new phishlet would resolve to a
// hostname that is already owned by another enabled phishlet.
//
// baseDomain is the global domain (from config) used to construct full hostnames
// for comparison.
func Validate(p *aitm.Phishlet, active []*aitm.Phishlet, baseDomain string) []CollisionError {
	// Build a map from full hostname → phishlet name for all active, enabled phishlets.
	owned := make(map[string]string)
	for _, a := range active {
		if !a.Enabled {
			continue
		}
		if a.Hostname != "" {
			owned[a.Hostname] = a.Name
		}
	}

	var collisions []CollisionError
	for _, ph := range p.ProxyHosts {
		hostname := ph.PhishSubdomain + "." + baseDomain
		if owner, conflict := owned[hostname]; conflict && owner != p.Name {
			collisions = append(collisions, CollisionError{
				NewHostname:         hostname,
				ConflictingPhishlet: owner,
			})
		}
	}
	return collisions
}
