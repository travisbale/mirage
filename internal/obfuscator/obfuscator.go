// Package obfuscator transforms injected JavaScript into a semantically
// equivalent but structurally different form on every request, making
// signature-based detection ineffective against static fingerprinting.
package obfuscator

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"time"

	"github.com/travisbale/mirage/internal/config"
)

// NoOpObfuscator is the identity transform. Used when obfuscation is disabled
// or as a fallback when the Node sidecar is unavailable.
type NoOpObfuscator struct{}

func (n *NoOpObfuscator) Obfuscate(_ context.Context, html []byte) ([]byte, error) {
	return html, nil
}

func (n *NoOpObfuscator) Shutdown(_ context.Context) error {
	return nil
}

// nodeRequest is one JSON line written to the sidecar stdin.
type nodeRequest struct {
	ID string `json:"id"`
	JS string `json:"js"`
}

// nodeResponse is one JSON line read from the sidecar stdout.
type nodeResponse struct {
	ID     string `json:"id"`
	Result string `json:"result"`
	Error  string `json:"error"`
}

type sidecarProcess struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout *bufio.Scanner
	mu     sync.Mutex // serialises requests to this process
	dead   bool
}

type NodeObfuscator struct {
	cfg          config.ObfuscatorConfig
	logger       *slog.Logger
	pool         chan *sidecarProcess
	shutdown     chan struct{}
	shutdownOnce sync.Once
}

const defaultRequestTimeout = 5 * time.Second

var reqCounter atomic.Int64

func newRequestID() string {
	return fmt.Sprintf("req-%d", reqCounter.Add(1))
}

// NewNodeObfuscator starts cfg.MaxConcurrent sidecar processes.
// Returns an error if any process fails to start (e.g. node not in PATH,
// sidecar/node_modules not installed). Callers should fall back to NoOpObfuscator on error.
func NewNodeObfuscator(cfg config.ObfuscatorConfig, logger *slog.Logger) (*NodeObfuscator, error) {
	if cfg.MaxConcurrent <= 0 {
		cfg.MaxConcurrent = 4
	}
	if cfg.RequestTimeout == 0 {
		cfg.RequestTimeout = defaultRequestTimeout
	}
	ob := &NodeObfuscator{
		cfg:      cfg,
		logger:   logger,
		pool:     make(chan *sidecarProcess, cfg.MaxConcurrent),
		shutdown: make(chan struct{}),
	}
	for i := 0; i < cfg.MaxConcurrent; i++ {
		sp, err := ob.startSidecar()
		if err != nil {
			ob.Shutdown(context.Background()) //nolint:errcheck
			return nil, fmt.Errorf("starting sidecar %d: %w", i, err)
		}
		ob.pool <- sp
	}
	return ob, nil
}

// Obfuscate scans html for injected script blocks and obfuscates them.
// Returns html unchanged if no marker is present (fast path).
func (ob *NodeObfuscator) Obfuscate(ctx context.Context, html []byte) ([]byte, error) {
	if !bytes.Contains(html, markerStartBytes) {
		return html, nil
	}
	return obfuscateMarkedHTML(ctx, ob.obfuscateJS, html)
}

func (ob *NodeObfuscator) Shutdown(ctx context.Context) error {
	ob.shutdownOnce.Do(func() { close(ob.shutdown) })
	for {
		select {
		case sp := <-ob.pool:
			if !sp.dead {
				sentinel, _ := json.Marshal(nodeRequest{ID: "__shutdown__", JS: ""})
				sentinel = append(sentinel, '\n')
				sp.stdin.Write(sentinel) // best-effort
				sp.stdin.Close()
				sp.cmd.Wait()
				ob.logger.Debug("sidecar shut down", "pid", sp.cmd.Process.Pid)
			}
		default:
			return nil
		}
	}
}

func (ob *NodeObfuscator) startSidecar() (*sidecarProcess, error) {
	nodePath := ob.cfg.NodePath
	if nodePath == "" {
		var err error
		nodePath, err = exec.LookPath("node")
		if err != nil {
			return nil, fmt.Errorf("node not found in PATH: %w", err)
		}
	}
	cmd := exec.Command(nodePath, "index.js")
	cmd.Dir = ob.cfg.SidecarDir
	cmd.Stderr = os.Stderr

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("creating stdin pipe: %w", err)
	}
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("creating stdout pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("starting node process: %w", err)
	}
	ob.logger.Debug("sidecar started", "pid", cmd.Process.Pid)
	return &sidecarProcess{
		cmd:    cmd,
		stdin:  stdin,
		stdout: bufio.NewScanner(stdoutPipe),
	}, nil
}

func (ob *NodeObfuscator) obfuscateJS(ctx context.Context, js string) (string, error) {
	var sp *sidecarProcess
	select {
	case sp = <-ob.pool:
	case <-ctx.Done():
		return "", ctx.Err()
	case <-ob.shutdown:
		return "", errors.New("obfuscator is shutting down")
	}

	result, err := ob.callSidecar(ctx, sp, js)
	if err != nil {
		ob.logger.Warn("sidecar call failed, restarting", "pid", sp.cmd.Process.Pid, "error", err)
		sp.dead = true
		newSP, spawnErr := ob.startSidecar()
		if spawnErr != nil {
			ob.logger.Error("failed to restart sidecar", "error", spawnErr)
			return js, nil
		}
		ob.pool <- newSP
		return js, nil // return plain JS on this call; next call gets the fresh sidecar
	}

	ob.pool <- sp
	return result, nil
}

func (ob *NodeObfuscator) callSidecar(ctx context.Context, sp *sidecarProcess, js string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, ob.cfg.RequestTimeout)
	defer cancel()

	sp.mu.Lock()
	defer sp.mu.Unlock()

	req := nodeRequest{ID: newRequestID(), JS: js}
	line, _ := json.Marshal(req)
	line = append(line, '\n')

	// Write in a goroutine so we respect context cancellation.
	writeDone := make(chan error, 1)
	go func() {
		_, err := sp.stdin.Write(line)
		writeDone <- err
	}()
	select {
	case err := <-writeDone:
		if err != nil {
			return "", fmt.Errorf("writing to sidecar stdin: %w", err)
		}
	case <-ctx.Done():
		return "", fmt.Errorf("write timed out: %w", ctx.Err())
	}

	// Read in a goroutine so we respect context cancellation.
	type readResult struct {
		resp nodeResponse
		err  error
	}
	readDone := make(chan readResult, 1)
	go func() {
		if !sp.stdout.Scan() {
			readDone <- readResult{err: fmt.Errorf("sidecar stdout closed unexpectedly")}
			return
		}
		var resp nodeResponse
		if err := json.Unmarshal(sp.stdout.Bytes(), &resp); err != nil {
			readDone <- readResult{err: fmt.Errorf("parsing sidecar response: %w", err)}
			return
		}
		readDone <- readResult{resp: resp}
	}()
	select {
	case r := <-readDone:
		if r.err != nil {
			return "", r.err
		}
		if r.resp.Error != "" {
			return "", fmt.Errorf("sidecar obfuscation error: %s", r.resp.Error)
		}
		return r.resp.Result, nil
	case <-ctx.Done():
		return "", fmt.Errorf("read timed out: %w", ctx.Err())
	}
}
