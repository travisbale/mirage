package cert

import (
	"fmt"
	"log/slog"
	"path/filepath"
)

// NewSource returns the appropriate CertSource for the given mode.
// When selfSigned is true a local CA is used; otherwise ACME is required
// (not yet wired — returns an error until implemented).
func NewSource(selfSigned bool, caDir string, logger *slog.Logger) (*SelfSignedCertSource, error) {
	if selfSigned {
		src := NewSelfSignedCertSource(caDir)
		logger.Info("using self-signed certificates", "ca_dir", caDir)
		logger.Info("import the CA cert into your browser to avoid TLS warnings",
			"ca_cert", filepath.Join(caDir, "mirage-ca.crt"))
		return src, nil
	}

	return nil, fmt.Errorf("autocert not yet wired — pass selfSigned=true for local testing")
}
