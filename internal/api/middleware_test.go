package api_test

import (
	"crypto/tls"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/travisbale/mirage/internal/api"
	"github.com/travisbale/mirage/sdk"
)

// newRouter returns a Router with nil service fields. Safe for tests that
// exercise auth middleware rejection paths — the wrapped handler is never
// reached, so the services are never dereferenced.
func newRouter() *api.Router {
	return &api.Router{
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

func TestAuthMiddleware_RejectsNilTLS(t *testing.T) {
	router := newRouter()

	req := httptest.NewRequest(http.MethodGet, sdk.RouteSessions, nil)
	// req.TLS is nil — simulates a plain HTTP request
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status: got %d, want 401", rec.Code)
	}
}

func TestAuthMiddleware_RejectsEmptyVerifiedChains(t *testing.T) {
	router := newRouter()

	req := httptest.NewRequest(http.MethodGet, sdk.RouteSessions, nil)
	req.TLS = &tls.ConnectionState{} // TLS established but no verified chains
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status: got %d, want 401", rec.Code)
	}
}
