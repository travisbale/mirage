package api

import (
	"net/http"

	"github.com/travisbale/mirage/sdk"
)

// listCampaignMappings returns GoPhish campaign mappings. Stubbed until
// the GoPhish integration is implemented.
func (r *Router) listCampaignMappings(w http.ResponseWriter, req *http.Request) {
	limit, offset := parsePagination(req)
	writeJSON(w, http.StatusOK, sdk.PaginatedResponse[struct{}]{
		Items:  []struct{}{},
		Total:  0,
		Limit:  limit,
		Offset: offset,
	})
}

// syncCampaign fetches a GoPhish campaign and maps its results. Stubbed.
func (r *Router) syncCampaign(w http.ResponseWriter, req *http.Request) {
	writeJSON(w, http.StatusOK, map[string]int{"mapped_count": 0})
}
