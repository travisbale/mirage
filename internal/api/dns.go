package api

import (
	"net/http"

	"github.com/travisbale/mirage/sdk"
)

func (r *Router) listDNSProviders(w http.ResponseWriter, req *http.Request) {
	writeJSON(w, http.StatusOK, r.DNS.ListProviders())
}

func (r *Router) listDNSZones(w http.ResponseWriter, req *http.Request) {
	zones := r.DNS.ListZones()
	resp := make([]sdk.DNSZoneResponse, len(zones))
	for i, z := range zones {
		resp[i] = sdk.DNSZoneResponse{
			Zone:     z.Zone,
			Provider: z.ProviderName,
			IP:       z.ExternalIP,
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

func (r *Router) syncDNS(w http.ResponseWriter, req *http.Request) {
	if err := r.Phishlets.ReconcileAll(req.Context()); err != nil {
		r.writeError(w, http.StatusInternalServerError, "dns sync failed", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
