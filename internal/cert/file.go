package cert

import (
	"crypto/tls"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// FileCertSource loads TLS certificates from PEM files on disk.
// Directory layout:
//
//	baseDir/
//	└── sites/
//	    ├── mail.attacker.com/
//	    │   ├── fullchain.pem
//	    │   └── privkey.pem
//	    └── *.attacker.com/
//	        ├── fullchain.pem
//	        └── privkey.pem
//
// FileCertSource checks the exact hostname first, then falls back to a wildcard
// entry ("*.base_domain") if present.
type FileCertSource struct {
	baseDir string // e.g. "/home/operator/.mirage/crt"
}

// NewFileCertSource constructs a FileCertSource rooted at baseDir.
// baseDir does not need to exist at construction time.
func NewFileCertSource(baseDir string) *FileCertSource {
	return &FileCertSource{baseDir: baseDir}
}

// GetCertificate returns the PEM-loaded certificate for hello.ServerName,
// or (nil, nil) if no PEM files are found for that hostname.
func (s *FileCertSource) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	hostname := strings.ToLower(hello.ServerName)

	// Try exact hostname first.
	if cert, err := s.loadFromDir(hostname); cert != nil || err != nil {
		return cert, err
	}

	// Try wildcard: "mail.attacker.com" → "*.attacker.com"
	parts := strings.SplitN(hostname, ".", 2)
	if len(parts) == 2 {
		wildcard := "*." + parts[1]
		if cert, err := s.loadFromDir(wildcard); cert != nil || err != nil {
			return cert, err
		}
	}

	return nil, nil
}

// loadFromDir attempts to load fullchain.pem + privkey.pem from
// baseDir/sites/<dirName>/. Returns (nil, nil) if the directory does not exist.
func (s *FileCertSource) loadFromDir(dirName string) (*tls.Certificate, error) {
	dir := filepath.Join(s.baseDir, "sites", dirName)
	chainPath := filepath.Join(dir, "fullchain.pem")
	keyPath := filepath.Join(dir, "privkey.pem")

	if _, err := os.Stat(chainPath); os.IsNotExist(err) {
		return nil, nil
	}

	cert, err := tls.LoadX509KeyPair(chainPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("file cert: loading %s: %w", dirName, err)
	}
	return &cert, nil
}
