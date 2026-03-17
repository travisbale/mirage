package request_test

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func newReq(method, rawURL string, body io.Reader) *http.Request {
	req := httptest.NewRequest(method, rawURL, body)
	req.RequestURI = ""
	return req
}

type stubSpoofer struct{ called bool }

func (s *stubSpoofer) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	s.called = true
	w.WriteHeader(http.StatusOK)
}
