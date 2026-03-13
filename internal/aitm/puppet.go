package aitm

// Puppet is the interface that headless browser implementations satisfy implicitly.
type Puppet interface {
	CollectTelemetry(targetURL string) (*BotTelemetry, error)
}

// PuppetService manages headless browser interactions for bot telemetry collection.
type PuppetService struct {
	puppet Puppet
	store  BotStore
	bus    EventBus
}

func NewPuppetService(puppet Puppet, store BotStore, bus EventBus) *PuppetService {
	return &PuppetService{puppet: puppet, store: store, bus: bus}
}
