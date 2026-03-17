package puppet

import "context"

// NoOpCollector is a puppet implementation that does nothing.
// Used when puppet is disabled or Chromium is unavailable.
type NoOpCollector struct{}

func (n *NoOpCollector) CollectTelemetry(_ context.Context, _ string) (map[string]any, error) {
	return nil, nil
}

func (n *NoOpCollector) Shutdown(_ context.Context) error {
	return nil
}
