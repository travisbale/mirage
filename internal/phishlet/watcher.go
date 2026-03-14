package phishlet

import (
	"log/slog"
	"path/filepath"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"

	"github.com/travisbale/mirage/internal/aitm"
)

// Watcher monitors a directory for YAML file changes and re-parses modified
// phishlet files. On successful re-parse it publishes EventPhishletReloaded on
// the event bus. Parse failures are logged but not published — the previously
// loaded definition remains in use.
type eventPublisher interface {
	Publish(event aitm.Event)
}

type Watcher struct {
	dir    string
	bus    eventPublisher
	loader Loader
	fsw    *fsnotify.Watcher
	stopCh chan struct{}
	doneCh chan struct{}
}

// NewWatcher creates a Watcher for the given directory. Call Start to begin
// watching. The watcher must be closed via Close when no longer needed.
func NewWatcher(dir string, bus eventPublisher) (*Watcher, error) {
	fsw, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}
	if err := fsw.Add(dir); err != nil {
		_ = fsw.Close()
		return nil, err
	}
	return &Watcher{
		dir:    dir,
		bus:    bus,
		fsw:    fsw,
		stopCh: make(chan struct{}),
		doneCh: make(chan struct{}),
	}, nil
}

// Start begins the watch loop in a background goroutine.
// It is safe to call Start only once.
func (w *Watcher) Start() {
	go w.loop()
}

// Close stops the watch loop and releases file-system resources.
// It blocks until the background goroutine exits.
func (w *Watcher) Close() error {
	close(w.stopCh)
	<-w.doneCh
	return w.fsw.Close()
}

// loop is the background goroutine that processes fsnotify events.
func (w *Watcher) loop() {
	defer close(w.doneCh)

	// Debounce: many editors produce rapid sequences of Write events for a
	// single save. We coalesce events for the same path within a 200ms window.
	debounce := make(map[string]*time.Timer)

	reload := func(path string) {
		def, err := w.loader.Load(path)
		if err != nil {
			// Template phishlets require params — log but don't treat as an error.
			if err == ErrTemplateRequired {
				slog.Debug("phishlet watcher: template phishlet changed (params required, skipping reload)",
					"path", path)
				return
			}
			slog.Warn("phishlet watcher: re-parse failed",
				"path", path,
				"error", err,
			)
			return
		}
		slog.Info("phishlet watcher: reloaded phishlet",
			"name", def.Name,
			"path", path,
		)
		w.bus.Publish(aitm.Event{
			Type:    aitm.EventPhishletReloaded,
			Payload: def,
		})
	}

	for {
		select {
		case <-w.stopCh:
			// Cancel any pending debounce timers.
			for _, timer := range debounce {
				timer.Stop()
			}
			return

		case evt, ok := <-w.fsw.Events:
			if !ok {
				return
			}
			if !isYAMLFile(evt.Name) {
				continue
			}
			if evt.Has(fsnotify.Write) || evt.Has(fsnotify.Create) {
				path := evt.Name
				if t, exists := debounce[path]; exists {
					t.Reset(200 * time.Millisecond)
				} else {
					debounce[path] = time.AfterFunc(200*time.Millisecond, func() {
						delete(debounce, path)
						reload(path)
					})
				}
			}

		case err, ok := <-w.fsw.Errors:
			if !ok {
				return
			}
			slog.Warn("phishlet watcher: fsnotify error", "error", err)
		}
	}
}

// isYAMLFile returns true if path has a .yaml or .yml extension.
func isYAMLFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return ext == ".yaml" || ext == ".yml"
}
