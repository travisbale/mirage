package aitm

// DNSProvider is the interface that store/dns implementations satisfy implicitly.
// It covers both record management and ACME DNS-01 challenge support.
type DNSProvider interface {
	CreateRecord(zone, name, typ, value string, ttl int) error
	UpdateRecord(zone, name, typ, value string, ttl int) error
	DeleteRecord(zone, name, typ string) error

	// ACME DNS-01 challenge
	Present(domain, token, keyAuth string) error
	CleanUp(domain, token, keyAuth string) error
}

// DNSService routes record management to the correct DNSProvider per zone.
type DNSService struct {
	providers map[string]DNSProvider // zone → provider
}

func NewDNSService(providers map[string]DNSProvider) *DNSService {
	return &DNSService{providers: providers}
}
