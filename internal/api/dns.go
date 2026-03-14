package api

import "net/http"

// listDNSZones returns configured DNS zones. Stubbed until the DNS service
// is wired into the Router.
func (r *Router) listDNSZones(w http.ResponseWriter, req *http.Request) {
	writeJSON(w, http.StatusOK, []struct{}{})
}

// syncDNS forces DNS record reconciliation. Stubbed until the DNS service
// is wired into the Router.
func (r *Router) syncDNS(w http.ResponseWriter, req *http.Request) {
	writeJSON(w, http.StatusOK, map[string]bool{"synced": true})
}
