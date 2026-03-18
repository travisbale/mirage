package cert

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/travisbale/mirage/internal/aitm"
)

// SourceConfig holds all parameters needed to construct a cert source chain.
type SourceConfig struct {
	// SelfSigned selects local-CA mode. When true, ACME fields are ignored.
	SelfSigned bool

	// CADir is the directory where the self-signed CA key and cert are stored.
	// Only used when SelfSigned is true.
	CADir string

	// CertFileDir is the base directory for operator-supplied PEM overrides.
	// Checked first in both modes.
	CertFileDir string

	// ACMEEmail is the contact address for ACME account registration.
	ACMEEmail string

	// ACMEDirectoryURL is the ACME directory URL. Defaults to the Let's Encrypt
	// production URL when empty. Set to the staging URL to avoid rate limits
	// during testing: https://acme-staging-v02.api.letsencrypt.org/directory
	ACMEDirectoryURL string

	// ACMEStorageDir is the directory for persisting ACME-issued certs across restarts.
	ACMEStorageDir string

	// Providers maps each base domain to the DNS provider used for DNS-01 challenges.
	// Domains without an entry fall through to per-host ACME (TLS-ALPN-01).
	Providers map[string]aitm.DNSProvider
}

// NewSource constructs the appropriate cert source chain for the given config.
// In self-signed mode: FileCertSource → SelfSignedCertSource.
// In production mode:  FileCertSource → WildcardACMECertSource → PerHostACMECertSource.
func NewSource(cfg SourceConfig, logger *slog.Logger) (aitm.CertSource, error) {
	fileSrc := &FileCertSource{BaseDir: cfg.CertFileDir}

	if cfg.SelfSigned {
		caCertPath := filepath.Join(cfg.CADir, "mirage-ca.crt")
		firstRun := isNotExist(caCertPath)

		selfSigned := NewSelfSignedCertSource(cfg.CADir)
		if err := selfSigned.EnsureCA(); err != nil {
			return nil, fmt.Errorf("initializing CA: %w", err)
		}

		logger.Info("using self-signed certificates", "ca_dir", cfg.CADir)
		if firstRun {
			logger.Info("import the CA cert into your browser to avoid TLS warnings", "ca_cert", caCertPath)
		}

		return NewChainedCertSource(logger, fileSrc, selfSigned), nil
	}

	wildcardSrc := &WildcardACMECertSource{
		providers:  cfg.Providers,
		acmeDir:    cfg.ACMEDirectoryURL,
		email:      cfg.ACMEEmail,
		storageDir: cfg.ACMEStorageDir,
		certs:      make(map[string]*tls.Certificate),
		logger:     logger,
	}
	perHostSrc := NewPerHostACMECertSource(cfg.ACMEEmail, cfg.ACMEDirectoryURL, cfg.ACMEStorageDir, logger)

	logger.Info("using ACME certificates", "directory", cfg.ACMEDirectoryURL, "email", cfg.ACMEEmail)

	return NewChainedCertSource(logger, fileSrc, wildcardSrc, perHostSrc), nil
}

func isNotExist(path string) bool {
	_, err := os.Stat(path)
	return os.IsNotExist(err)
}
