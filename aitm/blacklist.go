package aitm

// BlacklistService manages IP-based access control.
// Store interface defined in a later phase once persistence methods are known.
type BlacklistService struct {
	bus EventBus
}

func NewBlacklistService(bus EventBus) *BlacklistService {
	return &BlacklistService{bus: bus}
}
