package api

import (
	"encoding/json"
	"net/http"

	"github.com/travisbale/mirage/sdk"
)

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(payload)
}

func (r *Router) writeError(w http.ResponseWriter, status int, message string, err error) {
	if status >= 500 && err != nil {
		r.Logger.Error(message, "error", err)
	}
	writeJSON(w, status, sdk.ErrorResponse{Error: message})
}
