package aitm

import "errors"

// ErrNotFound is returned when a requested entity does not exist.
var ErrNotFound = errors.New("not found")

// ErrConflict is returned when an insert would violate a uniqueness constraint.
var ErrConflict = errors.New("conflict")

// ErrInvalidFilter is returned when a filter contains contradictory options.
var ErrInvalidFilter = errors.New("invalid filter")
