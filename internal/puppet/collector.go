package puppet

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/chromedp/chromedp"
)

//go:embed collect.js
var collectScript string

// Collector uses a Pool of headless Chromium instances to visit target URLs
// and extract browser telemetry by evaluating the embedded collect.js script.
type Collector struct {
	pool       *Pool
	navTimeout time.Duration
	logger     *slog.Logger
}

// NewCollector creates a Collector backed by the given pool.
func NewCollector(pool *Pool, navTimeout time.Duration, logger *slog.Logger) *Collector {
	return &Collector{pool: pool, navTimeout: navTimeout, logger: logger}
}

func (c *Collector) CollectTelemetry(ctx context.Context, targetURL string) (map[string]any, error) {
	browserCtx, browserCancel, err := c.pool.Acquire(ctx)
	if err != nil {
		return nil, fmt.Errorf("acquiring browser instance: %w", err)
	}
	defer c.pool.Release(browserCtx, browserCancel)

	// Create a new tab for this navigation.
	tabCtx, tabCancel := chromedp.NewContext(browserCtx)
	defer tabCancel()

	navTimeout := c.navTimeout
	if navTimeout == 0 {
		navTimeout = 30 * time.Second
	}
	tabCtx, timeoutCancel := context.WithTimeout(tabCtx, navTimeout)
	defer timeoutCancel()

	var rawResult []byte
	err = chromedp.Run(tabCtx,
		chromedp.Navigate(targetURL),
		chromedp.WaitReady("body"),
		chromedp.EvaluateAsDevTools(collectScript, &rawResult),
	)
	if err != nil {
		return nil, fmt.Errorf("navigating to %s: %w", targetURL, err)
	}

	var telemetry map[string]any
	if err := json.Unmarshal(rawResult, &telemetry); err != nil {
		return nil, fmt.Errorf("unmarshalling telemetry: %w", err)
	}

	c.logger.Debug("puppet telemetry collected", "url", targetURL, "keys", len(telemetry))
	return telemetry, nil
}

func (c *Collector) Shutdown(ctx context.Context) error {
	return c.pool.Shutdown(ctx)
}
