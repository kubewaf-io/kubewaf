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

package probetest

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/kubewaf-io/kubewaf/internal/probetest/api"
)

const (
	// MaxEvalRequestJSONBytes is the max encoded EvalRequest size (4 MiB).
	MaxEvalRequestJSONBytes = 4 * 1024 * 1024
	// DefaultGlobalMaxInFlight is the default concurrent evals.
	DefaultGlobalMaxInFlight = 16
	// DefaultMaxConcurrentCompiles is the default compile gate.
	DefaultMaxConcurrentCompiles = 4
)

// ServerConfig configures the Test HTTP Server.
type ServerConfig struct {
	// Token is the shared bearer secret. Empty + AllowInsecureNoAuth enables local dev.
	Token string
	// AllowInsecureNoAuth skips bearer check (local only).
	AllowInsecureNoAuth bool
	// GlobalMaxInFlight limits concurrent evals (default 16).
	GlobalMaxInFlight int
	// MaxConcurrentCompiles limits concurrent NewWAF (default 4).
	MaxConcurrentCompiles int
	// Logger optional.
	Logger *slog.Logger
	// Eval is the evaluation function (defaults to Evaluate).
	Eval func(ctx context.Context, req *api.EvalRequest) (*api.EvalResponse, error)
}

// Server is the probe Test HTTP Server.
type Server struct {
	cfg      ServerConfig
	log      *slog.Logger
	eval     func(ctx context.Context, req *api.EvalRequest) (*api.EvalResponse, error)
	inflight atomic.Int64
	compile  chan struct{}
}

// NewServer creates a Server.
func NewServer(cfg ServerConfig) *Server {
	if cfg.GlobalMaxInFlight <= 0 {
		cfg.GlobalMaxInFlight = DefaultGlobalMaxInFlight
	}
	if cfg.MaxConcurrentCompiles <= 0 {
		cfg.MaxConcurrentCompiles = DefaultMaxConcurrentCompiles
	}
	log := cfg.Logger
	if log == nil {
		log = slog.Default()
	}
	eval := cfg.Eval
	if eval == nil {
		eval = Evaluate
	}
	return &Server{
		cfg:     cfg,
		log:     log,
		eval:    eval,
		compile: make(chan struct{}, cfg.MaxConcurrentCompiles),
	}
}

// Handler returns the HTTP mux for the test server.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/readyz", s.handleReadyz)
	mux.HandleFunc("/v1/eval", s.handleEval)
	return mux
}

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func (s *Server) handleReadyz(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func (s *Server) handleEval(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.authorize(r) {
		writeJSON(w, http.StatusUnauthorized, api.ErrorBody{Class: "unauthorized", Message: "missing or invalid bearer token"})
		return
	}

	// Reject oversized Content-Length before taking an in-flight slot.
	if r.ContentLength > MaxEvalRequestJSONBytes {
		writeJSON(w, http.StatusRequestEntityTooLarge, api.ErrorBody{Class: api.ErrClassTooLarge, Message: "request too large"})
		return
	}

	// Global in-flight gate (after cheap size check).
	cur := s.inflight.Add(1)
	defer s.inflight.Add(-1)
	if int(cur) > s.cfg.GlobalMaxInFlight {
		writeJSON(w, http.StatusTooManyRequests, api.ErrorBody{Class: api.ErrClassBusy, Message: "max in-flight exceeded"})
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, MaxEvalRequestJSONBytes+1))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, api.ErrorBody{Class: api.ErrClassInvalidRequest, Message: "read body failed"})
		return
	}
	if len(body) > MaxEvalRequestJSONBytes {
		writeJSON(w, http.StatusRequestEntityTooLarge, api.ErrorBody{Class: api.ErrClassTooLarge, Message: "request too large"})
		return
	}
	var req api.EvalRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, api.ErrorBody{Class: api.ErrClassInvalidRequest, Message: "invalid JSON"})
		return
	}

	// Compile gate: acquire before Evaluate (which compiles).
	select {
	case s.compile <- struct{}{}:
		defer func() { <-s.compile }()
	case <-r.Context().Done():
		writeJSON(w, http.StatusGatewayTimeout, api.ErrorBody{Class: api.ErrClassTimeout, Message: msgEvalTimeout})
		return
	default:
		// Try with short wait using request context; Stop timer to avoid leaks under contention.
		timer := time.NewTimer(50 * time.Millisecond)
		select {
		case s.compile <- struct{}{}:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			defer func() { <-s.compile }()
		case <-r.Context().Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			writeJSON(w, http.StatusGatewayTimeout, api.ErrorBody{Class: api.ErrClassTimeout, Message: msgEvalTimeout})
			return
		case <-timer.C:
			// If still full after brief wait, 429.
			select {
			case s.compile <- struct{}{}:
				defer func() { <-s.compile }()
			default:
				writeJSON(w, http.StatusTooManyRequests, api.ErrorBody{Class: api.ErrClassBusy, Message: "max concurrent compiles exceeded"})
				return
			}
		}
	}

	resp, err := s.eval(r.Context(), &req)
	if err != nil {
		s.writeEvalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) authorize(r *http.Request) bool {
	if s.cfg.AllowInsecureNoAuth && s.cfg.Token == "" {
		return true
	}
	if s.cfg.Token == "" {
		// Production mode with empty token is misconfiguration — reject.
		return false
	}
	const prefix = "Bearer "
	h := r.Header.Get("Authorization")
	got := ""
	if len(h) >= len(prefix) && h[:len(prefix)] == prefix {
		got = h[len(prefix):]
	}
	// Always compare digests so length mismatch cannot early-exit CT compare.
	return tokenEqualCT(got, s.cfg.Token)
}

// tokenEqualCT compares bearer tokens via SHA-256 digests so
// ConstantTimeCompare does not early-exit on length mismatch.
func tokenEqualCT(got, want string) bool {
	gh := sha256.Sum256([]byte(got))
	wh := sha256.Sum256([]byte(want))
	return subtle.ConstantTimeCompare(gh[:], wh[:]) == 1
}

func (s *Server) writeEvalError(w http.ResponseWriter, err error) {
	if ee, ok := err.(*EvalError); ok {
		status := ee.HTTPStatus
		if status == 0 {
			status = http.StatusInternalServerError
		}
		writeJSON(w, status, api.ErrorBody{Class: ee.Class, Message: ee.Message})
		return
	}
	writeJSON(w, http.StatusInternalServerError, api.ErrorBody{Class: api.ErrClassInternal, Message: "internal error"})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
