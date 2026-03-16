package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/sdk"
)

func (r *Router) listBotSignatures(w http.ResponseWriter, req *http.Request) {
	limit, offset := parsePagination(req)
	sigs, err := r.botguard.ListBotSignatures()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list signatures", "INTERNAL_ERROR")
		return
	}

	total := len(sigs)
	start := min(offset, total)
	end := min(start+limit, total)
	page := sigs[start:end]

	items := make([]sdk.BotSignatureResponse, len(page))
	for i, sig := range page {
		items[i] = sdk.BotSignatureResponse{
			JA4Hash:     sig.JA4Hash,
			Description: sig.Description,
			AddedAt:     sig.AddedAt,
		}
	}
	writeJSON(w, http.StatusOK, sdk.PaginatedResponse[sdk.BotSignatureResponse]{
		Items:  items,
		Total:  total,
		Limit:  limit,
		Offset: offset,
	})
}

func (r *Router) addBotSignature(w http.ResponseWriter, req *http.Request) {
	var body sdk.AddBotSignatureRequest
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		writeError(w, http.StatusUnprocessableEntity, "invalid request body", "VALIDATION_ERROR")
		return
	}
	if body.JA4Hash == "" {
		writeError(w, http.StatusUnprocessableEntity, "ja4_hash: required", "VALIDATION_ERROR")
		return
	}

	signature := aitm.BotSignature{
		JA4Hash:     body.JA4Hash,
		Description: body.Description,
		AddedAt:     time.Now(),
	}

	if err := r.botguard.CreateBotSignature(signature); err != nil {
		status, code := errStatus(err)
		writeError(w, status, err.Error(), code)
		return
	}

	writeJSON(w, http.StatusCreated, sdk.BotSignatureResponse{
		JA4Hash:     signature.JA4Hash,
		Description: signature.Description,
		AddedAt:     signature.AddedAt,
	})
}

func (r *Router) removeBotSignature(w http.ResponseWriter, req *http.Request) {
	hash := req.PathValue("hash")
	found, err := r.botguard.DeleteBotSignature(hash)
	if err != nil {
		status, code := errStatus(err)
		writeError(w, status, err.Error(), code)
		return
	}
	if !found {
		writeError(w, http.StatusNotFound, "signature not found", "NOT_FOUND")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (r *Router) updateBotThreshold(w http.ResponseWriter, req *http.Request) {
	var body sdk.UpdateBotThresholdRequest
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		writeError(w, http.StatusUnprocessableEntity, "invalid request body", "VALIDATION_ERROR")
		return
	}
	if body.Threshold < 0.0 || body.Threshold > 1.0 {
		writeError(w, http.StatusUnprocessableEntity, "threshold: must be between 0.0 and 1.0", "VALIDATION_ERROR")
		return
	}
	// Runtime threshold updates are not yet supported — accepted but not applied.
	writeJSON(w, http.StatusOK, map[string]float64{"threshold": body.Threshold})
}
