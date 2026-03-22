package phishlet

import (
	"fmt"
	"strings"
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
