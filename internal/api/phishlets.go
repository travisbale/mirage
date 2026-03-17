package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/sdk"
)

func (r *Router) getPhishlet(w http.ResponseWriter, req *http.Request) {
	phishlet, err := r.phishlets.Get(req.PathValue("name"))
	if err != nil {
		if errors.Is(err, aitm.ErrNotFound) {
			writeError(w, http.StatusNotFound, "phishlet not found")
		} else {
			writeError(w, http.StatusInternalServerError, "failed to get phishlet")
		}

		return
	}

	writeJSON(w, http.StatusOK, phishletToResponse(phishlet))
}

func (r *Router) listPhishlets(w http.ResponseWriter, req *http.Request) {
	limit, offset := parsePagination(req)

	phishlets, err := r.phishlets.List()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list phishlets")
		return
	}

	total := len(phishlets)
	start := min(offset, total)
	end := min(start+limit, total)
	page := phishlets[start:end]

	items := make([]sdk.PhishletResponse, len(page))
	for i, p := range page {
		items[i] = phishletToResponse(p)
	}
	writeJSON(w, http.StatusOK, sdk.PaginatedResponse[sdk.PhishletResponse]{
		Items:  items,
		Total:  total,
		Limit:  limit,
		Offset: offset,
	})
}

func (r *Router) enablePhishlet(w http.ResponseWriter, req *http.Request) {
	name := req.PathValue("name")

	var body sdk.EnablePhishletRequest
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		writeError(w, http.StatusUnprocessableEntity, "invalid request body")
		return
	}

	p, err := r.phishlets.Enable(name, body.Hostname, body.BaseDomain, body.DNSProvider)
	if err != nil {
		switch {
		case errors.Is(err, aitm.ErrHostnameRequired):
			writeError(w, http.StatusUnprocessableEntity, "hostname is required")
		case errors.Is(err, aitm.ErrHostnameConflict):
			writeError(w, http.StatusConflict, "hostname is already in use by another phishlet")
		default:
			writeError(w, http.StatusInternalServerError, "failed to enable phishlet")
		}

		return
	}

	writeJSON(w, http.StatusOK, phishletToResponse(p))
}

func (r *Router) disablePhishlet(w http.ResponseWriter, req *http.Request) {
	p, err := r.phishlets.Disable(req.PathValue("name"))
	if err != nil {
		if errors.Is(err, aitm.ErrNotFound) {
			writeError(w, http.StatusNotFound, "phishlet does not exist")
		} else {
			writeError(w, http.StatusInternalServerError, "failed to disable phishlet")
		}

		return
	}

	writeJSON(w, http.StatusOK, phishletToResponse(p))
}

func (r *Router) hidePhishlet(w http.ResponseWriter, req *http.Request) {
	p, err := r.phishlets.Hide(req.PathValue("name"))
	if err != nil {
		if errors.Is(err, aitm.ErrNotFound) {
			writeError(w, http.StatusNotFound, "phishlet does not exist")
		} else {
			writeError(w, http.StatusInternalServerError, "failed to hide phishlet")
		}

		return
	}

	writeJSON(w, http.StatusOK, phishletToResponse(p))
}

func (r *Router) unhidePhishlet(w http.ResponseWriter, req *http.Request) {
	p, err := r.phishlets.Unhide(req.PathValue("name"))
	if err != nil {
		if errors.Is(err, aitm.ErrNotFound) {
			writeError(w, http.StatusNotFound, "phishlet does not exist")
		} else {
			writeError(w, http.StatusInternalServerError, "failed to unhide phishlet")
		}

		return
	}

	writeJSON(w, http.StatusOK, phishletToResponse(p))
}

// listRegistry stubs the phishlet registry — not implemented until Phase 15.
func (r *Router) listRegistry(w http.ResponseWriter, req *http.Request) {
	limit, offset := parsePagination(req)
	writeJSON(w, http.StatusOK, sdk.PaginatedResponse[sdk.PhishletResponse]{
		Items:  []sdk.PhishletResponse{},
		Total:  0,
		Limit:  limit,
		Offset: offset,
	})
}

// getPhishletHosts returns /etc/hosts lines for a phishlet. Stubbed until
// the PhishletResolver is wired into the Router.
func (r *Router) getPhishletHosts(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
}

func phishletToResponse(p *aitm.Phishlet) sdk.PhishletResponse {
	return sdk.PhishletResponse{
		Name:        p.Name,
		BaseDomain:  p.BaseDomain,
		Hostname:    p.Hostname,
		DNSProvider: p.DNSProvider,
		UnauthURL:   p.UnauthURL,
		SpoofURL:    p.SpoofURL,
		Enabled:     p.Enabled,
		Hidden:      p.Hidden,
	}
}
