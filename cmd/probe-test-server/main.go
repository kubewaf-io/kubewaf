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

// Command probe-test-server is the kubeWAF probe Test HTTP Server (go-coraza).
// It has no kube client and is not part of the Subresource API Server.
package main

import (
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/kubewaf-io/kubewaf/internal/probetest"
)

func main() {
	var (
		bindAddr       string
		tokenFile      string
		token          string
		insecureNoAuth bool
		maxInFlight    int
		maxCompiles    int
	)
	// Default loopback: probe backend is not a public surface.
	flag.StringVar(&bindAddr, "bind-address", "127.0.0.1:8080", "HTTP listen address (prefer loopback)")
	flag.StringVar(&tokenFile, "eval-token-file", "", "Path to shared bearer token file (production)")
	flag.StringVar(&token, "eval-token", "", "Shared bearer token (dev; prefer token file)")
	flag.BoolVar(&insecureNoAuth, "insecure-no-auth", false, "Disable bearer auth (local dev only)")
	flag.IntVar(&maxInFlight, "max-in-flight", probetest.DefaultGlobalMaxInFlight, "Global max concurrent evaluations")
	flag.IntVar(&maxCompiles, "max-concurrent-compiles",
		probetest.DefaultMaxConcurrentCompiles, "Max concurrent WAF compiles")
	flag.Parse()

	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	if token == "" && tokenFile != "" {
		b, err := os.ReadFile(tokenFile)
		if err != nil {
			log.Error("read eval token file", "err", err)
			os.Exit(1)
		}
		token = strings.TrimSpace(string(b))
	}
	if token == "" && !insecureNoAuth {
		log.Error("eval token required unless --insecure-no-auth")
		os.Exit(1)
	}
	if insecureNoAuth {
		log.Warn("INSECURE: --insecure-no-auth enabled — local dev only")
	}
	if host, _, err := net.SplitHostPort(bindAddr); err == nil {
		if host != "127.0.0.1" && host != "localhost" && host != "::1" && host != "" {
			log.Warn("binding non-loopback address; ensure NetworkPolicy / firewall restricts access", "addr", bindAddr)
		}
	} else if strings.HasPrefix(bindAddr, ":") {
		log.Warn("binding all interfaces; prefer 127.0.0.1 for local or restrict network access", "addr", bindAddr)
	}

	srv := probetest.NewServer(probetest.ServerConfig{
		Token:                 token,
		AllowInsecureNoAuth:   insecureNoAuth,
		GlobalMaxInFlight:     maxInFlight,
		MaxConcurrentCompiles: maxCompiles,
		Logger:                log,
	})

	httpSrv := &http.Server{
		Addr:              bindAddr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       35 * time.Second,
		WriteTimeout:      40 * time.Second,
		IdleTimeout:       90 * time.Second,
	}

	go func() {
		log.Info("probe-test-server listening", "addr", bindAddr, "auth", !insecureNoAuth || token != "")
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error("listen failed", "err", err)
			os.Exit(1)
		}
	}()

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	sig := <-ch
	log.Info("shutting down", "signal", fmt.Sprintf("%v", sig))
	_ = httpSrv.Close()
}
