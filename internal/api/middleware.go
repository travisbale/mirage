package api

import (
	"context"
	"crypto/x509"
	"net/http"
)

type contextKey struct{}

// authMiddleware verifies that the request arrived with a valid client
// certificate. The TLS stack already enforces RequireAndVerifyClientCert for
// the secret hostname, so by the time a request reaches this middleware the
// chain is already validated. This is a secondary check that confirms at least
// one verified chain exists and that the leaf cert has not been revoked.
func (r *Router) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		if req.TLS == nil || len(req.TLS.VerifiedChains) == 0 {
			writeError(w, http.StatusUnauthorized, "client certificate required", "UNAUTHORIZED")
			return
		}
		leaf := req.TLS.VerifiedChains[0][0]
		if r.isRevoked(leaf) {
			writeError(w, http.StatusUnauthorized, "client certificate revoked", "UNAUTHORIZED")
			return
		}
		ctx := context.WithValue(req.Context(), contextKey{}, leaf.Subject.CommonName)
		next(w, req.WithContext(ctx))
	}
}

// isRevoked consults the in-memory revocation set. Always returns false until
// a revocation endpoint is added in a future phase.
func (r *Router) isRevoked(_ *x509.Certificate) bool {
	return false
}

// operatorFromCtx returns the operator common name stored by authMiddleware.
func operatorFromCtx(ctx context.Context) string {
	name, _ := ctx.Value(contextKey{}).(string)
	return name
}
