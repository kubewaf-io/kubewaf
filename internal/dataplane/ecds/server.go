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

// Package ecds implements a gRPC Extension Config Discovery Service (ECDS)
// that serves Wasm filter configurations to Envoy proxies.
package ecds

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extensionconfigservice "github.com/envoyproxy/go-control-plane/envoy/service/extension/v3"
	"github.com/envoyproxy/go-control-plane/pkg/cache/types"
	cachev3 "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	"github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	serverv3 "github.com/envoyproxy/go-control-plane/pkg/server/v3"
	"github.com/go-logr/logr"
	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"

	"github.com/kubewaf-io/kubewaf/internal/dataplane/config"
)

const (
	// NodeID is the synthetic node ID used for the global ECDS snapshot.
	// All Envoy clients receive the same set of extension configs; only those
	// with a matching config_discovery filter slot activate a given config.
	NodeID = "kubewaf"

	grpcKeepaliveTime        = 30 * time.Second
	grpcKeepaliveTimeout     = 5 * time.Second
	grpcKeepaliveMinTime     = 30 * time.Second
	grpcMaxConcurrentStreams = 1000000
)

// constHasher always returns NodeID so every Envoy shares one snapshot.
type constHasher struct{}

func (constHasher) ID(_ *core.Node) string { return NodeID }

// Server is an ECDS management server backed by a go-control-plane snapshot cache.
type Server struct {
	log     logr.Logger
	cache   cachev3.SnapshotCache
	xds     serverv3.Server
	version atomic.Uint64

	mu        sync.RWMutex
	resources map[string]*core.TypedExtensionConfig // keyed by ExtensionName

	grpcServer *grpc.Server
}

// New creates an ECDS server. Call Run to start gRPC serve.
func New(ctx context.Context, log logr.Logger) *Server {
	c := cachev3.NewSnapshotCache(false, constHasher{}, nil)
	s := &Server{
		log:       log.WithName("ecds"),
		cache:     c,
		xds:       serverv3.NewServer(ctx, c, nil),
		resources: make(map[string]*core.TypedExtensionConfig),
	}
	// Publish an empty snapshot so clients can connect before any WAF exists.
	_ = s.publishLocked()
	return s
}

// Upsert builds TypedExtensionConfigs for all filters (challenge + WAF) and publishes.
func (s *Server) Upsert(p *config.PortableConfig) error {
	tecs, err := BuildTypedExtensionConfigs(p)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	// Drop stale challenge resource if challenge was disabled.
	prefix := p.ExtensionName
	for name := range s.resources {
		if name == prefix || strings.HasPrefix(name, prefix+"/") {
			// Will re-add current set below; remove orphans after.
			delete(s.resources, name)
		}
	}
	for _, tec := range tecs {
		s.resources[tec.GetName()] = tec
	}
	if err := s.publishLocked(); err != nil {
		return err
	}
	s.log.Info("ECDS upsert", "name", p.ExtensionName, "filters", len(tecs), "version", s.version.Load())
	return nil
}

// Delete removes extension configs for a WAF (engine + optional challenge) and republishes.
func (s *Server) Delete(extensionName string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	removed := 0
	for name := range s.resources {
		if name == extensionName || strings.HasPrefix(name, extensionName+"/") {
			delete(s.resources, name)
			removed++
		}
	}
	if removed == 0 {
		return nil
	}
	if err := s.publishLocked(); err != nil {
		return err
	}
	s.log.Info("ECDS delete", "name", extensionName, "removed", removed, "version", s.version.Load())
	return nil
}

// Version returns the current snapshot version counter.
func (s *Server) Version() uint64 {
	return s.version.Load()
}

// Has reports whether an extension config is present.
func (s *Server) Has(extensionName string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.resources[extensionName]
	return ok
}

func (s *Server) publishLocked() error {
	ver := s.version.Add(1)
	resources := make([]types.Resource, 0, len(s.resources))
	for _, r := range s.resources {
		resources = append(resources, r)
	}
	snap, err := cachev3.NewSnapshot(fmt.Sprintf("%d", ver), map[resource.Type][]types.Resource{
		resource.ExtensionConfigType: resources,
	})
	if err != nil {
		return fmt.Errorf("new snapshot: %w", err)
	}
	if err := snap.Consistent(); err != nil {
		// Extension-only snapshots are consistent with empty other types.
		// Some go-control-plane versions still validate; ignore empty-map edge cases.
		s.log.V(1).Info("snapshot consistency warning", "err", err)
	}
	if err := s.cache.SetSnapshot(context.Background(), NodeID, snap); err != nil {
		return fmt.Errorf("set snapshot: %w", err)
	}
	return nil
}

// Run starts the gRPC ECDS server on the given bind address (e.g. ":18001").
// It blocks until ctx is cancelled or Serve fails.
func (s *Server) Run(ctx context.Context, bindAddr string) error {
	grpcOptions := make([]grpc.ServerOption, 0, 3)
	grpcOptions = append(grpcOptions,
		grpc.MaxConcurrentStreams(grpcMaxConcurrentStreams),
		grpc.KeepaliveParams(keepalive.ServerParameters{
			Time:    grpcKeepaliveTime,
			Timeout: grpcKeepaliveTimeout,
		}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             grpcKeepaliveMinTime,
			PermitWithoutStream: true,
		}),
	)
	s.grpcServer = grpc.NewServer(grpcOptions...)
	extensionconfigservice.RegisterExtensionConfigDiscoveryServiceServer(s.grpcServer, s.xds)

	lc := net.ListenConfig{}
	lis, err := lc.Listen(ctx, "tcp", bindAddr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", bindAddr, err)
	}

	s.log.Info("ECDS gRPC server listening", "addr", bindAddr)

	errCh := make(chan error, 1)
	go func() {
		errCh <- s.grpcServer.Serve(lis)
	}()

	select {
	case <-ctx.Done():
		s.grpcServer.GracefulStop()
		return nil
	case err := <-errCh:
		return err
	}
}

// Runnable adapts Server to controller-runtime's Runnable interface
// (Start(ctx) error) so it can be registered with the manager.
type Runnable struct {
	Server   *Server
	BindAddr string
}

// Start implements manager.Runnable.
func (r Runnable) Start(ctx context.Context) error {
	return r.Server.Run(ctx, r.BindAddr)
}

// NeedLeaderElection implements manager.LeaderElectionRunnable.
// ECDS must run on every replica so Service load-balancing works.
func (r Runnable) NeedLeaderElection() bool { return false }
