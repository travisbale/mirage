package api

import (
	"encoding/json"
	"net/http"

	"github.com/travisbale/mirage/internal/aitm"
)

func (r *Router) listPhishlets(w http.ResponseWriter, req *http.Request) {
	limit, offset := parsePagination(req)

	cfgs, err := r.phishlets.ListPhishletConfigs()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error(), "INTERNAL_ERROR")
		return
	}

	total := len(cfgs)
	start := min(offset, total)
	end := min(start+limit, total)
	page := cfgs[start:end]

	items := make([]PhishletResponse, len(page))
	for i, cfg := range page {
		items[i] = phishletConfigToResponse(cfg)
	}
	writeJSON(w, http.StatusOK, PaginatedResponse[PhishletResponse]{
		Items:  items,
		Total:  total,
		Limit:  limit,
		Offset: offset,
	})
}

func (r *Router) enablePhishlet(w http.ResponseWriter, req *http.Request) {
	name := req.PathValue("name")

	var body EnablePhishletRequest
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		writeError(w, http.StatusUnprocessableEntity, "invalid request body", "VALIDATION_ERROR")
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
		writeError(w, http.StatusUnprocessableEntity, "hostname: required", "VALIDATION_ERROR")
		return
	}

	cfg.Enabled = true
	if err := r.phishlets.SetPhishletConfig(cfg); err != nil {
		status, code := errStatus(err)
		writeError(w, status, err.Error(), code)
		return
	}
	writeJSON(w, http.StatusOK, phishletConfigToResponse(cfg))
}

func (r *Router) disablePhishlet(w http.ResponseWriter, req *http.Request) {
	name := req.PathValue("name")
	cfg, err := r.phishlets.GetPhishletConfig(name)
	if err != nil {
		status, code := errStatus(err)
		writeError(w, status, "phishlet not found", code)
		return
	}
	cfg.Enabled = false
	if err := r.phishlets.SetPhishletConfig(cfg); err != nil {
		status, code := errStatus(err)
		writeError(w, status, err.Error(), code)
		return
	}
	writeJSON(w, http.StatusOK, phishletConfigToResponse(cfg))
}

func (r *Router) hidePhishlet(w http.ResponseWriter, req *http.Request) {
	name := req.PathValue("name")
	cfg, err := r.phishlets.GetPhishletConfig(name)
	if err != nil {
		status, code := errStatus(err)
		writeError(w, status, "phishlet not found", code)
		return
	}
	cfg.Hidden = true
	if err := r.phishlets.SetPhishletConfig(cfg); err != nil {
		status, code := errStatus(err)
		writeError(w, status, err.Error(), code)
		return
	}
	writeJSON(w, http.StatusOK, phishletConfigToResponse(cfg))
}

func (r *Router) unhidePhishlet(w http.ResponseWriter, req *http.Request) {
	name := req.PathValue("name")
	cfg, err := r.phishlets.GetPhishletConfig(name)
	if err != nil {
		status, code := errStatus(err)
		writeError(w, status, "phishlet not found", code)
		return
	}
	cfg.Hidden = false
	if err := r.phishlets.SetPhishletConfig(cfg); err != nil {
		status, code := errStatus(err)
		writeError(w, status, err.Error(), code)
		return
	}
	writeJSON(w, http.StatusOK, phishletConfigToResponse(cfg))
}

func (r *Router) createSubPhishlet(w http.ResponseWriter, req *http.Request) {
	var body CreateSubPhishletRequest
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		writeError(w, http.StatusUnprocessableEntity, "invalid request body", "VALIDATION_ERROR")
		return
	}
	if body.ParentName == "" {
		writeError(w, http.StatusUnprocessableEntity, "parent_name: required", "VALIDATION_ERROR")
		return
	}
	if body.Name == "" {
		writeError(w, http.StatusUnprocessableEntity, "name: required", "VALIDATION_ERROR")
		return
	}

	sp := &aitm.SubPhishlet{
		Name:       body.Name,
		ParentName: body.ParentName,
		Params:     body.Params,
	}
	if err := r.phishlets.CreateSubPhishlet(sp); err != nil {
		status, code := errStatus(err)
		writeError(w, status, err.Error(), code)
		return
	}
	writeJSON(w, http.StatusCreated, PhishletResponse{
		Name:       sp.Name,
		ParentName: sp.ParentName,
	})
}

func (r *Router) deleteSubPhishlet(w http.ResponseWriter, req *http.Request) {
	name := req.PathValue("name")
	if err := r.phishlets.DeleteSubPhishlet(name); err != nil {
		status, code := errStatus(err)
		writeError(w, status, err.Error(), code)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// listRegistry stubs the phishlet registry — not implemented until Phase 15.
func (r *Router) listRegistry(w http.ResponseWriter, req *http.Request) {
	limit, offset := parsePagination(req)
	writeJSON(w, http.StatusOK, PaginatedResponse[PhishletResponse]{
		Items:  []PhishletResponse{},
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

func phishletConfigToResponse(cfg *aitm.PhishletConfig) PhishletResponse {
	return PhishletResponse{
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
