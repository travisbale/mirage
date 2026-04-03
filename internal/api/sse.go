package api

import (
	"fmt"
	"net/http"
)

type sseWriter struct {
	w       http.ResponseWriter
	flusher http.Flusher
}

// newSSEWriter sets the required SSE headers and returns a sseWriter.
// Returns (nil, false) if the underlying ResponseWriter does not support flushing.
func newSSEWriter(w http.ResponseWriter) (*sseWriter, bool) {
	f, ok := w.(http.Flusher)
	if !ok {
		return nil, false
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no") // disable nginx buffering if behind a proxy
	// Send headers immediately so the client's Do() returns without
	// waiting for the first event.
	w.WriteHeader(http.StatusOK)
	return &sseWriter{w: w, flusher: f}, true
}

// WriteEvent writes a single SSE event and flushes immediately.
// Returns an error if the write failed (client disconnected).
func (s *sseWriter) WriteEvent(eventType string, data []byte) error {
	if _, err := fmt.Fprintf(s.w, "event: %s\ndata: %s\n\n", eventType, data); err != nil {
		return err
	}
	s.flusher.Flush()
	return nil
}
