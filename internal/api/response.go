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

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, sdk.ErrorResponse{Error: message})
}
