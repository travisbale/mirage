package aitm

// puppet is the interface that headless browser implementations satisfy implicitly.
type puppet interface {
	CollectTelemetry(targetURL string) (*BotTelemetry, error)
}

// PuppetService manages headless browser interactions for bot telemetry collection.
type PuppetService struct {
	puppet puppet
	store  botTelemetryStore
	bus    EventBus
}

func NewPuppetService(puppet puppet, store botTelemetryStore, bus EventBus) *PuppetService {
	return &PuppetService{puppet: puppet, store: store, bus: bus}
}
