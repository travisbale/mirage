package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"
)

// validatable is implemented by SDK request types that expose a Validate method.
type validatable interface {
	Validate() error
}

// decodeAndValidate decodes a JSON request body into T and calls Validate on it.
// On failure it writes the appropriate error response and returns false.
func decodeAndValidate[T validatable](w http.ResponseWriter, req *http.Request) (T, bool) {
	var body T
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		writeError(w, http.StatusUnprocessableEntity, "invalid request body")
		return body, false
	}
	if err := body.Validate(); err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return body, false
	}
	return body, true
}

func parsePagination(req *http.Request) (limit, offset int) {
	limit = 50
	if v := req.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	if limit > 500 {
		limit = 500
	}
	if v := req.URL.Query().Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			offset = n
		}
	}
	return
}

// parseRFC3339Param parses an RFC3339 timestamp query parameter. It writes a
// 400 error and returns false if the value is present but malformed.
func parseRFC3339Param(w http.ResponseWriter, name, value string) (time.Time, bool) {
	t, err := time.Parse(time.RFC3339, value)
	if err != nil {
		writeError(w, http.StatusBadRequest, name+": invalid RFC3339 timestamp")
		return time.Time{}, false
	}
	return t, true
}
