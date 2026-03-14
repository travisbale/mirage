package aitm

import "crypto/tls"

// CertSource is the interface that cert implementations satisfy implicitly.
type CertSource interface {
	GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error)
}
