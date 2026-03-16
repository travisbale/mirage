package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/travisbale/mirage/internal/store"
	"github.com/travisbale/mirage/sdk"
)

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, sdk.ErrorResponse{Error: message})
}

// errStatus maps store sentinel errors to HTTP status codes and API error codes.
func errStatus(err error) (int, string) {
	if errors.Is(err, store.ErrNotFound) {
		return http.StatusNotFound, "NOT_FOUND"
	}
	if errors.Is(err, store.ErrConflict) {
		return http.StatusConflict, "CONFLICT"
	}
	return http.StatusInternalServerError, "INTERNAL_ERROR"
}
