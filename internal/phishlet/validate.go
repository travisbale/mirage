package phishlet

import (
	"errors"
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

// ErrTemplateRequired is returned by Load (non-template path) when the
// phishlet YAML declares template params — it must be loaded via LoadWithParams.
var ErrTemplateRequired = errors.New("phishlet is a template: use LoadWithParams and supply required params")

// ErrMissingParams is returned by LoadWithParams when one or more required
// template parameters are absent from the supplied map.
type ErrMissingParams struct {
	Missing []string
}

func (e ErrMissingParams) Error() string {
	return fmt.Sprintf("missing template params: %s", strings.Join(e.Missing, ", "))
}

// CollisionError describes a hostname collision detected by PhishletDef.Validate.
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

// Validate checks a compiled PhishletDef against the list of currently active
// phishlet configs for hostname collisions. It returns all conflicts found,
// not just the first.
//
// A collision occurs when a proxy_host in the new phishlet would resolve to a
// hostname that is already owned by another enabled phishlet.
//
// baseDomain is the global domain (from config) used when a PhishletConfig does
// not override it. It is needed to construct the full hostname for comparison.
func Validate(def *aitm.PhishletDef, active []*aitm.PhishletConfig, baseDomain string) []CollisionError {
	// Build a map from full hostname → phishlet name for all active, enabled phishlets.
	owned := make(map[string]string)
	for _, cfg := range active {
		if !cfg.Enabled {
			continue
		}
		if cfg.Hostname != "" {
			owned[cfg.Hostname] = cfg.Name
		}
	}

	var collisions []CollisionError
	for _, ph := range def.ProxyHosts {
		hostname := ph.PhishSubdomain + "." + baseDomain
		if owner, conflict := owned[hostname]; conflict && owner != def.Name {
			collisions = append(collisions, CollisionError{
				NewHostname:         hostname,
				ConflictingPhishlet: owner,
			})
		}
	}
	return collisions
}
