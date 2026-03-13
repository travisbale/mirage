package aitm

// CampaignService manages GoPhish campaign integration.
// Store interface defined in a later phase once persistence methods are known.
type CampaignService struct {
	bus EventBus
}

func NewCampaignService(bus EventBus) *CampaignService {
	return &CampaignService{bus: bus}
}
