package api

import (
	"net/http"
	"net/url"

	"github.com/travisbale/mirage/sdk"
)

func (r *Router) listBlacklist(w http.ResponseWriter, req *http.Request) {
	limit, offset := parsePagination(req)
	entries := r.Blacklist.List()

	page := paginateSlice(entries, limit, offset)

	items := make([]sdk.BlacklistEntryResponse, len(page))
	for i, entry := range page {
		items[i] = sdk.BlacklistEntryResponse{Value: entry}
	}
	writeJSON(w, http.StatusOK, sdk.PaginatedResponse[sdk.BlacklistEntryResponse]{
		Items:  items,
		Total:  len(entries),
		Limit:  limit,
		Offset: offset,
	})
}

func (r *Router) addBlacklistEntry(w http.ResponseWriter, req *http.Request) {
	body, ok := decodeAndValidate[sdk.AddBlacklistEntryRequest](w, req)
	if !ok {
		return
	}

	r.Blacklist.Block(body.Value)
	writeJSON(w, http.StatusCreated, sdk.BlacklistEntryResponse(body))
}

func (r *Router) removeBlacklistEntry(w http.ResponseWriter, req *http.Request) {
	entry, err := url.PathUnescape(req.PathValue("entry"))
	if err != nil {
		r.writeError(w, http.StatusUnprocessableEntity, "invalid entry", err)
		return
	}
	r.Blacklist.Unblock(entry)
	w.WriteHeader(http.StatusNoContent)
}
