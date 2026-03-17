package api

import (
	"context"
	"net/http"
	"time"
)

type operatorKey struct{}

// authMiddleware is a secondary check confirming a verified client cert chain
// exists. The TLS stack already enforces RequireAndVerifyClientCert for the
// secret hostname before any request reaches this handler.
func (r *Router) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		if req.TLS == nil || len(req.TLS.VerifiedChains) == 0 {
			writeError(w, http.StatusUnauthorized, "client certificate required")
			return
		}

		leaf := req.TLS.VerifiedChains[0][0]
		ctx := context.WithValue(req.Context(), operatorKey{}, leaf.Subject.CommonName)
		next(w, req.WithContext(ctx))
	}
}

func operatorFromCtx(ctx context.Context) string {
	name, _ := ctx.Value(operatorKey{}).(string)
	return name
}

// auditMiddleware logs each API call. Must chain after authMiddleware so the
// operator CN is already in context.
func (r *Router) auditMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next(rec, req)
		r.Logger.Info("api",
			"operator", operatorFromCtx(req.Context()),
			"method", req.Method,
			"path", req.URL.Path,
			"status", rec.status,
			"duration", time.Since(start),
		)
	}
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(status int) {
	s.status = status
	s.ResponseWriter.WriteHeader(status)
}
