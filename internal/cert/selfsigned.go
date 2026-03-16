package cert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// SelfSignedCertSource generates and signs TLS certificates using a local CA.
// The CA is created once and reused for all subsequent leaf cert requests.
// The CA certificate is written to caDir/mirage-ca.crt for browser import.
type SelfSignedCertSource struct {
	caDir string

	once   sync.Once
	caKey  *ecdsa.PrivateKey
	caCert *x509.Certificate

	mu    sync.Mutex
	leafs map[string]*tls.Certificate
}

func NewSelfSignedCertSource(caDir string) *SelfSignedCertSource {
	return &SelfSignedCertSource{
		caDir: caDir,
		leafs: make(map[string]*tls.Certificate),
	}
}

// EnsureCA initializes the CA if it has not been already, and is safe to call
// more than once. After it returns without error, CACert() is non-nil and the
// CA certificate file is present in caDir.
func (s *SelfSignedCertSource) EnsureCA() error {
	var err error
	s.once.Do(func() { err = s.initCA() })
	return err
}

// CACert returns the dev CA certificate; useful for building a test trust pool.
// Returns nil until EnsureCA (or GetCertificate) has been called.
func (s *SelfSignedCertSource) CACert() *x509.Certificate {
	return s.caCert
}

// GetCertificate signs a leaf cert on first use, then serves from cache.
func (s *SelfSignedCertSource) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	var initErr error
	s.once.Do(func() {
		initErr = s.initCA()
	})
	if initErr != nil {
		return nil, fmt.Errorf("selfsigned: CA init: %w", initErr)
	}

	hostname := strings.ToLower(hello.ServerName)

	s.mu.Lock()
	cert, ok := s.leafs[hostname]
	s.mu.Unlock()

	if ok && !certExpiresSoon(cert) {
		return cert, nil
	}

	leaf, err := s.signLeaf(hostname)
	if err != nil {
		return nil, fmt.Errorf("selfsigned: sign leaf for %s: %w", hostname, err)
	}

	s.mu.Lock()
	s.leafs[hostname] = leaf
	s.mu.Unlock()
	return leaf, nil
}

// initCA creates or loads the CA key pair in caDir.
func (s *SelfSignedCertSource) initCA() error {
	caKeyPath := filepath.Join(s.caDir, "mirage-ca.key")
	caCertPath := filepath.Join(s.caDir, "mirage-ca.crt")

	if err := os.MkdirAll(s.caDir, 0700); err != nil {
		return fmt.Errorf("creating caDir: %w", err)
	}

	if _, err := os.Stat(caKeyPath); err == nil {
		return s.loadCA(caKeyPath, caCertPath)
	}

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generating CA key: %w", err)
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	caTemplate := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Mirage Dev CA", Organization: []string{"Mirage"}},
		NotBefore:             time.Now().Add(-5 * time.Minute),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("creating CA cert: %w", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return err
	}
	s.caKey = caKey
	s.caCert = caCert

	if err := writePEMFile(caCertPath, "CERTIFICATE", caDER, 0644); err != nil {
		return err
	}
	keyDER, err := x509.MarshalECPrivateKey(caKey)
	if err != nil {
		return err
	}
	return writePEMFile(caKeyPath, "EC PRIVATE KEY", keyDER, 0600)
}

func (s *SelfSignedCertSource) loadCA(keyPath, certPath string) error {
	tlsCert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return fmt.Errorf("loading existing CA: %w", err)
	}
	s.caCert, err = x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		return err
	}
	s.caKey = tlsCert.PrivateKey.(*ecdsa.PrivateKey)
	return nil
}

func (s *SelfSignedCertSource) signLeaf(hostname string) (*tls.Certificate, error) {
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	leafTemplate := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: hostname},
		DNSNames:     []string{hostname},
		NotBefore:    time.Now().Add(-5 * time.Minute),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, s.caCert, &leafKey.PublicKey, s.caKey)
	if err != nil {
		return nil, fmt.Errorf("signing leaf: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(leafKey)
	if err != nil {
		return nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	return &tlsCert, nil
}

func certExpiresSoon(cert *tls.Certificate) bool {
	if len(cert.Certificate) == 0 {
		return true
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return true
	}
	return time.Until(leaf.NotAfter) < 30*24*time.Hour
}

func writePEMFile(path, pemType string, der []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	defer file.Close()
	return pem.Encode(file, &pem.Block{Type: pemType, Bytes: der})
}

func encodeCertChain(ders [][]byte) []byte {
	var buf []byte
	for _, der := range ders {
		buf = append(buf, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	return buf
}

func encodeECPrivateKey(key *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), nil
}
