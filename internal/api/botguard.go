package api

import (
	"errors"
	"net/http"
	"time"

	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/sdk"
)

func (r *Router) listBotSignatures(w http.ResponseWriter, req *http.Request) {
	limit, offset := parsePagination(req)
	sigs, err := r.Botguard.ListSignatures()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list signatures")
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
	body, ok := decodeAndValidate[sdk.AddBotSignatureRequest](w, req)
	if !ok {
		return
	}

	signature := aitm.BotSignature{
		JA4Hash:     body.JA4Hash,
		Description: body.Description,
		AddedAt:     time.Now(),
	}

	if err := r.Botguard.AddSignature(signature); err != nil {
		if errors.Is(err, aitm.ErrConflict) {
			writeError(w, http.StatusConflict, "signature already exists")
		} else {
			writeError(w, http.StatusInternalServerError, "failed to add signature")
		}
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
	found, err := r.Botguard.RemoveSignature(hash)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to remove signature")
		return
	}
	if !found {
		writeError(w, http.StatusNotFound, "signature does not exist")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (r *Router) updateBotThreshold(w http.ResponseWriter, req *http.Request) {
	body, ok := decodeAndValidate[sdk.UpdateBotThresholdRequest](w, req)
	if !ok {
		return
	}
	// Runtime threshold updates are not yet supported — accepted but not applied.
	writeJSON(w, http.StatusOK, map[string]float64{"threshold": body.Threshold})
}
