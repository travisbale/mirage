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
		r.writeError(w, http.StatusInternalServerError, "failed to list signatures", err)
		return
	}

	page := paginateSlice(sigs, limit, offset)

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
		Total:  len(sigs),
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
			r.writeError(w, http.StatusConflict, "signature already exists", err)
		} else {
			r.writeError(w, http.StatusInternalServerError, "failed to add signature", err)
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
	if err := r.Botguard.RemoveSignature(hash); err != nil {
		if errors.Is(err, aitm.ErrNotFound) {
			r.writeError(w, http.StatusNotFound, "signature does not exist", err)
		} else {
			r.writeError(w, http.StatusInternalServerError, "failed to remove signature", err)
		}
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
