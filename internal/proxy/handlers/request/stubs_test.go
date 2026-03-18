package request_test

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"

	"github.com/travisbale/mirage/internal/aitm"
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

func (s *stubSpoofer) ServeWithTarget(w http.ResponseWriter, r *http.Request, _ string) {
	s.ServeHTTP(w, r)
}

type stubSessionManager struct {
	getSession *aitm.Session
	getErr     error
	newSession *aitm.Session
	newErr     error
}

func (s *stubSessionManager) Get(_ string) (*aitm.Session, error) {
	return s.getSession, s.getErr
}

func (s *stubSessionManager) NewSession(_ *aitm.ProxyContext) (*aitm.Session, error) {
	return s.newSession, s.newErr
}
