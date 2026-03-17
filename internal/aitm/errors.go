package aitm

import "errors"

var ErrNotFound = errors.New("not found")
var ErrConflict = errors.New("conflict")
var ErrInvalidFilter = errors.New("invalid filter")
var ErrHostnameRequired = errors.New("hostname is required")
var ErrHostnameConflict = errors.New("hostname is already in use by another phishlet")
