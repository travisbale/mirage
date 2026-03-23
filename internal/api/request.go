package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/travisbale/mirage/sdk"
)

type validatable interface {
	Validate() error
}

// decodeAndValidate decodes a JSON request body into T and calls Validate on it.
// On failure it writes the appropriate error response and returns false.
func decodeAndValidate[T validatable](w http.ResponseWriter, req *http.Request) (T, bool) {
	var body T
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, sdk.ErrorResponse{Error: "invalid request body"})
		return body, false
	}
	if err := body.Validate(); err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, sdk.ErrorResponse{Error: err.Error()})
		return body, false
	}
	return body, true
}

func parsePagination(req *http.Request) (limit, offset int) {
	limit = 50
	if limitStr := req.URL.Query().Get("limit"); limitStr != "" {
		if n, err := strconv.Atoi(limitStr); err == nil && n > 0 {
			limit = n
		}
	}
	if limit > 500 {
		limit = 500
	}
	if offsetStr := req.URL.Query().Get("offset"); offsetStr != "" {
		if n, err := strconv.Atoi(offsetStr); err == nil && n >= 0 {
			offset = n
		}
	}
	return
}

// paginateSlice returns the page of items defined by limit and offset.
func paginateSlice[T any](items []T, limit, offset int) []T {
	total := len(items)
	start := min(offset, total)
	end := min(start+limit, total)
	return items[start:end]
}

// parseRFC3339Param parses an RFC3339 timestamp query parameter. It writes a
// 400 error and returns false if the value is present but malformed.
func parseRFC3339Param(w http.ResponseWriter, name, value string) (time.Time, bool) {
	t, err := time.Parse(time.RFC3339, value)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, sdk.ErrorResponse{Error: name + ": invalid RFC3339 timestamp"})
		return time.Time{}, false
	}
	return t, true
}
