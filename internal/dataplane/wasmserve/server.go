/*
Copyright 2025 Buzz-IT GmbH.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package wasmserve hosts one or more Proxy-Wasm binaries over HTTP so Envoy
// can fetch them for ECDS filters (ModSecurity, Challenge/PoW).
package wasmserve

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/go-logr/logr"

	"github.com/kubewaf-io/kubewaf/internal/dataplane/engine"
)

// ModulePayload is one loaded wasm binary.
type ModulePayload struct {
	Bytes  []byte
	SHA256 string
	Source string
}

// Server serves multiple wasm modules by path.
type Server struct {
	log logr.Logger

	mu      sync.RWMutex
	modules map[engine.ModuleID]*ModulePayload

	httpServer *http.Server
}

// ModuleSource describes how to load a single module.
type ModuleSource struct {
	ID        engine.ModuleID
	File      string
	SourceURL string
}

// Options configures multi-module loading.
type Options struct {
	Modules    []ModuleSource
	HTTPClient *http.Client
}

// New creates an empty multi-module wasm server.
func New(log logr.Logger) *Server {
	return &Server{
		log:     log.WithName("wasmserve"),
		modules: make(map[engine.ModuleID]*ModulePayload),
	}
}

// Load applies Options: for each module prefer File, else SourceURL.
func (s *Server) Load(ctx context.Context, opts Options) error {
	client := opts.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 120 * time.Second}
	}
	var firstErr error
	loaded := 0
	for _, m := range opts.Modules {
		if m.ID == "" {
			continue
		}
		if m.File != "" {
			if _, err := os.Stat(m.File); err == nil {
				if err := s.LoadFromFile(m.ID, m.File); err != nil {
					if firstErr == nil {
						firstErr = err
					}
					continue
				}
				loaded++
				continue
			} else if !os.IsNotExist(err) {
				if firstErr == nil {
					firstErr = err
				}
				continue
			}
			// fall through to URL if file missing
		}
		if m.SourceURL != "" {
			if err := s.LoadFromURL(ctx, m.ID, m.SourceURL, client); err != nil {
				s.log.Error(err, "failed to load wasm module", "id", m.ID, "url", m.SourceURL)
				if firstErr == nil {
					firstErr = err
				}
				continue
			}
			loaded++
		}
	}
	if loaded == 0 && firstErr != nil {
		return firstErr
	}
	if loaded == 0 {
		return fmt.Errorf("no wasm modules loaded: provide files under /wasm or source URLs")
	}
	return nil
}

// LoadFromFile reads a wasm binary for the given module id.
func (s *Server) LoadFromFile(id engine.ModuleID, path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read wasm file %s: %w", path, err)
	}
	if len(b) == 0 {
		return fmt.Errorf("wasm file %s is empty", path)
	}
	s.setPayload(id, b, path)
	s.log.Info("loaded wasm from file", "id", id, "path", path, "bytes", len(b), "sha256", s.SHA256(id))
	return nil
}

// LoadFromURL downloads a wasm binary for the given module id.
func (s *Server) LoadFromURL(ctx context.Context, id engine.ModuleID, rawURL string, client *http.Client) error {
	if client == nil {
		client = &http.Client{Timeout: 120 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("download wasm from %s: %w", rawURL, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download wasm from %s: status %d", rawURL, resp.StatusCode)
	}
	const maxWasm = 256 << 20
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxWasm+1))
	if err != nil {
		return fmt.Errorf("read wasm body: %w", err)
	}
	if len(b) > maxWasm {
		return fmt.Errorf("wasm download exceeds %d bytes", maxWasm)
	}
	if len(b) == 0 {
		return fmt.Errorf("wasm download from %s is empty", rawURL)
	}
	s.setPayload(id, b, rawURL)
	s.log.Info("loaded wasm from URL", "id", id, "url", rawURL, "bytes", len(b), "sha256", s.SHA256(id))
	return nil
}

// Ready reports whether at least one module is loaded.
func (s *Server) Ready() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.modules) > 0
}

// Has reports whether a specific module is loaded.
func (s *Server) Has(id engine.ModuleID) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.modules[id]
	return ok
}

// SHA256 returns the hex checksum for a module (empty if missing).
func (s *Server) SHA256(id engine.ModuleID) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if m := s.modules[id]; m != nil {
		return m.SHA256
	}
	return ""
}

// PublicURL is a convenience wrapper around engine.PublicURL for the WAF module.
func PublicURL(serviceHost string, port uint32) string {
	return engine.PublicURL(serviceHost, port, engine.ModuleModSecurity)
}

// PublicURLFor builds the URL for any module.
func PublicURLFor(serviceHost string, port uint32, id engine.ModuleID) string {
	return engine.PublicURL(serviceHost, port, id)
}

func (s *Server) setPayload(id engine.ModuleID, b []byte, source string) {
	sum := sha256.Sum256(b)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.modules[id] = &ModulePayload{
		Bytes:  b,
		SHA256: hex.EncodeToString(sum[:]),
		Source: source,
	}
}

// Handler returns an http.Handler serving all registered modules.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	for _, m := range engine.AllModules() {
		id := m.ID
		path := m.HTTPPath
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			s.serveModule(w, r, id)
		})
	}
	// Aliases
	mux.HandleFunc("/wasm/modsec.wasm", func(w http.ResponseWriter, r *http.Request) {
		s.serveModule(w, r, engine.ModuleModSecurity)
	})
	mux.HandleFunc("/wasm/pow-proxy-wasm.wasm", func(w http.ResponseWriter, r *http.Request) {
		s.serveModule(w, r, engine.ModuleChallenge)
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		if !s.Ready() {
			http.Error(w, "no wasm modules loaded", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		s.mu.RLock()
		defer s.mu.RUnlock()
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = fmt.Fprintf(w, "kubewaf multi-module wasm server\nmodules=%d\n", len(s.modules))
		for id, m := range s.modules {
			_, _ = fmt.Fprintf(w, "- %s bytes=%d sha256=%s source=%s path=%s\n",
				id, len(m.Bytes), m.SHA256, m.Source, engine.HTTPPath(id))
		}
	})
	return mux
}

func (s *Server) serveModule(w http.ResponseWriter, r *http.Request, id engine.ModuleID) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.mu.RLock()
	m := s.modules[id]
	s.mu.RUnlock()
	if m == nil || len(m.Bytes) == 0 {
		http.Error(w, fmt.Sprintf("wasm module %q not loaded", id), http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/wasm")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(m.Bytes)))
	w.Header().Set("X-Checksum-Sha256", m.SHA256)
	w.Header().Set("X-Wasm-Module", string(id))
	w.Header().Set("Cache-Control", "public, max-age=3600")
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	_, _ = w.Write(m.Bytes)
}

// Run starts the HTTP server on bindAddr until ctx is cancelled.
func (s *Server) Run(ctx context.Context, bindAddr string) error {
	s.httpServer = &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	lc := net.ListenConfig{}
	lis, err := lc.Listen(ctx, "tcp", bindAddr)
	if err != nil {
		return fmt.Errorf("listen wasmserve %s: %w", bindAddr, err)
	}
	s.log.Info("wasm HTTP server listening", "addr", bindAddr, "ready", s.Ready())

	errCh := make(chan error, 1)
	go func() {
		errCh <- s.httpServer.Serve(lis)
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.httpServer.Shutdown(shutdownCtx)
		return nil
	case err := <-errCh:
		if err == http.ErrServerClosed {
			return nil
		}
		return err
	}
}

// Runnable adapts Server for controller-runtime manager.Add.
type Runnable struct {
	Server   *Server
	BindAddr string
}

// Start implements manager.Runnable.
func (r Runnable) Start(ctx context.Context) error {
	return r.Server.Run(ctx, r.BindAddr)
}

// NeedLeaderElection implements manager.LeaderElectionRunnable.
func (r Runnable) NeedLeaderElection() bool { return false }
