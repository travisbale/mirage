package api

import (
	"encoding/json"
	"net"
	"net/http"
	"net/url"

	"github.com/travisbale/mirage/sdk"
)

func (r *Router) listBlacklist(w http.ResponseWriter, req *http.Request) {
	limit, offset := parsePagination(req)
	entries := r.blacklist.List()

	total := len(entries)
	start := min(offset, total)
	end := min(start+limit, total)
	page := entries[start:end]

	items := make([]sdk.BlacklistEntryResponse, len(page))
	for i, v := range page {
		items[i] = sdk.BlacklistEntryResponse{Value: v}
	}
	writeJSON(w, http.StatusOK, sdk.PaginatedResponse[sdk.BlacklistEntryResponse]{
		Items:  items,
		Total:  total,
		Limit:  limit,
		Offset: offset,
	})
}

func (r *Router) addBlacklistEntry(w http.ResponseWriter, req *http.Request) {
	var body sdk.AddBlacklistEntryRequest
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		writeError(w, http.StatusUnprocessableEntity, "invalid request body", "VALIDATION_ERROR")
		return
	}
	if body.Value == "" {
		writeError(w, http.StatusUnprocessableEntity, "value: required", "VALIDATION_ERROR")
		return
	}
	if !isValidIPOrCIDR(body.Value) {
		writeError(w, http.StatusUnprocessableEntity, "value: must be a valid IP or CIDR", "VALIDATION_ERROR")
		return
	}

	r.blacklist.Block(body.Value)
	writeJSON(w, http.StatusCreated, sdk.BlacklistEntryResponse{Value: body.Value})
}

func (r *Router) removeBlacklistEntry(w http.ResponseWriter, req *http.Request) {
	entry, err := url.PathUnescape(req.PathValue("entry"))
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "invalid entry", "VALIDATION_ERROR")
		return
	}
	r.blacklist.Unblock(entry)
	w.WriteHeader(http.StatusNoContent)
}

func isValidIPOrCIDR(s string) bool {
	if net.ParseIP(s) != nil {
		return true
	}
	_, _, err := net.ParseCIDR(s)
	return err == nil
}
