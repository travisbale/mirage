package aitm

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// Operator represents a registered operator with API access.
type Operator struct {
	Name      string
	CreatedAt time.Time
}

// OperatorInvite is a single-use token for enrolling a new operator.
type OperatorInvite struct {
	Token string
	Name  string
}

var (
	ErrInvalidToken  = errors.New("invalid invite token")
	ErrInvalidCSR    = errors.New("invalid certificate signing request")
	ErrSigningFailed = errors.New("certificate signing failed")
)

type operatorStore interface {
	CreateOperator(op *Operator) error
	ListOperators() ([]*Operator, error)
	DeleteOperator(name string) error
	CreateInvite(invite *OperatorInvite) error
	ListInvites() ([]*OperatorInvite, error)
	ConsumeInvite(token string) (*OperatorInvite, error)
}

// certSigner signs CSRs to produce operator client certificates.
type certSigner interface {
	SignCSR(csr *x509.CertificateRequest, operatorName string) (certPEM []byte, err error)
	CACertPEM() []byte
}

// OperatorService manages operator lifecycle: invites, enrollment, and listing.
type OperatorService struct {
	Store  operatorStore
	Signer certSigner
}

// Invite creates a single-use invite token for the named operator.
func (s *OperatorService) Invite(name string) (*OperatorInvite, error) {
	if name == "" {
		return nil, fmt.Errorf("operator name is required")
	}
	invite := &OperatorInvite{
		Token: uuid.New().String(),
		Name:  name,
	}
	if err := s.Store.CreateInvite(invite); err != nil {
		return nil, err
	}

	return invite, nil
}

// Enroll validates the invite token, signs the CSR, registers the operator,
// and returns the signed cert + CA cert.
func (s *OperatorService) Enroll(token string, csrPEM []byte) (certPEM, caCertPEM []byte, err error) {
	invite, err := s.Store.ConsumeInvite(token)
	if errors.Is(err, ErrNotFound) {
		return nil, nil, ErrInvalidToken
	}
	if err != nil {
		return nil, nil, fmt.Errorf("consuming invite: %w", err)
	}

	der := decodePEM(csrPEM)
	if der == nil {
		return nil, nil, ErrInvalidCSR
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, nil, ErrInvalidCSR
	}

	certPEM, err = s.Signer.SignCSR(csr, invite.Name)
	if err != nil {
		return nil, nil, ErrSigningFailed
	}

	operator := &Operator{
		Name:      invite.Name,
		CreatedAt: time.Now(),
	}
	if err := s.Store.CreateOperator(operator); err != nil {
		return nil, nil, err
	}

	return certPEM, s.Signer.CACertPEM(), nil
}

func (s *OperatorService) List() ([]*Operator, error) {
	return s.Store.ListOperators()
}

func (s *OperatorService) Delete(name string) error {
	return s.Store.DeleteOperator(name)
}

// decodePEM extracts the DER bytes from a PEM block.
func decodePEM(data []byte) []byte {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil
	}
	return block.Bytes
}
