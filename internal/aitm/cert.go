package aitm

import "crypto/tls"

type CertSource interface {
	GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error)
}
