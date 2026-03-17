package puppet

import (
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"sync"
	"sync/atomic"

	"github.com/chromedp/chromedp"
	"github.com/travisbale/mirage/internal/config"
)

// Pool manages a fixed set of reusable Chromium browser contexts backed by a
// shared ExecAllocator. Acquire returns a context for a new tab; Release returns
// it for reuse.
type Pool struct {
	allocCtx    context.Context
	allocCancel context.CancelFunc
	instances   chan instance
	maxSize     int32
	outstanding atomic.Int32 // currently acquired + pooled instances
	logger      *slog.Logger

	shutdownOnce sync.Once
	closed       atomic.Bool
}

type instance struct {
	ctx    context.Context
	cancel context.CancelFunc
}

// NewPool creates a Chromium instance pool. It pre-spawns cfg.MinInstances
// browser contexts and allows up to cfg.MaxInstances.
func NewPool(cfg config.PuppetConfig, logger *slog.Logger) (*Pool, error) {
	chromiumPath := cfg.ChromiumPath
	if chromiumPath == "" {
		var err error
		chromiumPath, err = findChromium()
		if err != nil {
			return nil, fmt.Errorf("chromium not found: %w", err)
		}
	}

	opts := []chromedp.ExecAllocatorOption{
		chromedp.ExecPath(chromiumPath),
		chromedp.Headless,
		chromedp.NoFirstRun,
		chromedp.NoDefaultBrowserCheck,
		chromedp.DisableGPU,
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.Flag("disable-extensions", true),
		chromedp.Flag("disable-background-networking", true),
		chromedp.Flag("disable-sync", true),
		chromedp.Flag("disable-translate", true),
		chromedp.UserAgent(cfg.UserAgent),
	}

	allocCtx, allocCancel := chromedp.NewExecAllocator(context.Background(), opts...)

	pool := &Pool{
		allocCtx:    allocCtx,
		allocCancel: allocCancel,
		instances:   make(chan instance, cfg.MaxInstances),
		maxSize:     int32(cfg.MaxInstances),
		logger:      logger,
	}

	for i := 0; i < cfg.MinInstances; i++ {
		inst, err := pool.spawn()
		if err != nil {
			allocCancel()
			return nil, fmt.Errorf("pre-spawning instance %d: %w", i, err)
		}
		pool.outstanding.Add(1)
		pool.instances <- inst
	}

	logger.Info("puppet pool started",
		"chromium", chromiumPath,
		"min", cfg.MinInstances,
		"max", cfg.MaxInstances,
	)

	return pool, nil
}

// Acquire returns a browser context from the pool, spawning a new one if the
// pool is empty and capacity allows.
func (p *Pool) Acquire(ctx context.Context) (context.Context, context.CancelFunc, error) {
	if p.closed.Load() {
		return nil, nil, fmt.Errorf("pool is shut down")
	}

	// Fast path: grab a pooled instance.
	select {
	case inst := <-p.instances:
		return inst.ctx, inst.cancel, nil
	default:
	}

	// Pool empty — try spawning if under capacity. Optimistically reserve a
	// slot first so concurrent callers cannot both pass the capacity check.
	if cur := p.outstanding.Add(1); cur <= p.maxSize {
		inst, err := p.spawn()
		if err != nil {
			p.outstanding.Add(-1)
			p.logger.Warn("failed to spawn browser instance, waiting for pool", "error", err)
		} else {
			return inst.ctx, inst.cancel, nil
		}
	} else {
		p.outstanding.Add(-1)
	}

	// At capacity or spawn failed — block until one is returned.
	select {
	case inst := <-p.instances:
		return inst.ctx, inst.cancel, nil
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	}
}

// Release returns a browser context to the pool. If the pool is shut down or
// full, the context is cancelled and discarded.
func (p *Pool) Release(browserCtx context.Context, cancel context.CancelFunc) {
	if p.closed.Load() {
		cancel()
		p.outstanding.Add(-1)
		return
	}
	select {
	case p.instances <- instance{ctx: browserCtx, cancel: cancel}:
	default:
		cancel()
		p.outstanding.Add(-1)
	}
}

// Shutdown cancels the allocator context, killing all Chromium processes.
func (p *Pool) Shutdown(_ context.Context) error {
	p.shutdownOnce.Do(func() {
		p.closed.Store(true)

		// Drain pooled instances.
		for {
			select {
			case inst := <-p.instances:
				inst.cancel()
			default:
				p.allocCancel()
				p.logger.Info("puppet pool shut down")
				return
			}
		}
	})
	return nil
}

func (p *Pool) spawn() (instance, error) {
	browserCtx, browserCancel := chromedp.NewContext(p.allocCtx)
	// Run a no-op to force the browser to start.
	if err := chromedp.Run(browserCtx); err != nil {
		browserCancel()
		return instance{}, fmt.Errorf("starting browser context: %w", err)
	}
	return instance{ctx: browserCtx, cancel: browserCancel}, nil
}

func findChromium() (string, error) {
	candidates := []string{
		"chromium-browser",
		"chromium",
		"google-chrome-stable",
		"google-chrome",
	}
	for _, name := range candidates {
		if path, err := exec.LookPath(name); err == nil {
			return path, nil
		}
	}
	return "", fmt.Errorf("no chromium/chrome binary found in PATH")
}
