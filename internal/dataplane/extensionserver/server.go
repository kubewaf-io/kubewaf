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

// Package extensionserver implements the Envoy Gateway Extension Server hooks
// that inject ECDS filter stubs and the kubewaf_ecds cluster into generated xDS.
package extensionserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	"github.com/go-logr/logr"
	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"

	egext "github.com/envoyproxy/gateway/proto/extension"
	wafv1beta1 "github.com/kubewaf-io/kubewaf/api/waf/v1beta1"
	"github.com/kubewaf-io/kubewaf/internal/dataplane/config"
	"github.com/kubewaf-io/kubewaf/internal/dataplane/xdsutil"
)

// Server implements envoygateway.extension.EnvoyGatewayExtension.
//
// It keeps an in-memory index of PortableConfigs for EnvoyGateway-provider WAFs
// (updated by the WAF reconciler) and injects ECDS stubs on matching listeners.
type Server struct {
	egext.UnimplementedEnvoyGatewayExtensionServer

	log    logr.Logger
	client client.Client // optional; used when extension_resources are absent
	opts   config.BuildOptions

	mu      sync.RWMutex
	configs map[string]*config.PortableConfig // key: namespace/name

	grpcServer *grpc.Server
}

// New creates an Extension Server. client may be nil (then only the in-memory
// index from Upsert/Delete is used).
func New(log logr.Logger, c client.Client, opts config.BuildOptions) *Server {
	return &Server{
		log:     log.WithName("eg-extension-server"),
		client:  c,
		opts:    opts,
		configs: make(map[string]*config.PortableConfig),
	}
}

// Upsert indexes a portable config for listener matching.
func (s *Server) Upsert(p *config.PortableConfig) {
	if p == nil || p.Provider != wafv1beta1.ProviderEnvoyGateway {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.configs[p.Namespace+"/"+p.Name] = p
	s.log.V(1).Info("indexed WAF for EG hooks", "key", p.Namespace+"/"+p.Name)
}

// Delete removes a portable config from the index.
func (s *Server) Delete(namespace, name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.configs, namespace+"/"+name)
}

// PostHTTPListenerModify injects ECDS filter stubs for WAFs that target this listener's Gateway.
func (s *Server) PostHTTPListenerModify(_ context.Context, req *egext.PostHTTPListenerModifyRequest) (*egext.PostHTTPListenerModifyResponse, error) {
	if req == nil || req.Listener == nil {
		return &egext.PostHTTPListenerModifyResponse{}, nil
	}

	// Prefer WAFs from the in-memory index; also accept extension_resources if EG passes WAF policies.
	matching := s.matchingConfigs(req)

	if len(matching) == 0 {
		return &egext.PostHTTPListenerModifyResponse{Listener: req.Listener}, nil
	}

	modified := proto.Clone(req.Listener).(*listener.Listener)
	if err := injectFilters(modified, matching); err != nil {
		return nil, err
	}
	s.log.Info("injected ECDS filters into listener",
		"listener", req.Listener.GetName(),
		"filters", len(matching),
	)
	return &egext.PostHTTPListenerModifyResponse{Listener: modified}, nil
}

// PostTranslateModify ensures kubewaf_ecds (+ optional wasm code) clusters exist.
//
// Envoy rejects listeners with config_discovery pointing at a missing cluster
// ("ApiConfigSource must have a statically defined non-EDS cluster: 'kubewaf_ecds'").
// We always inject the ECDS STRICT_DNS cluster whenever we have operator defaults
// or indexed WAFs — do not rely solely on PostHTTPListenerModify having run first
// (multi-replica extension server + delta xDS ordering).
func (s *Server) PostTranslateModify(_ context.Context, req *egext.PostTranslateModifyRequest) (*egext.PostTranslateModifyResponse, error) {
	if req == nil {
		return &egext.PostTranslateModifyResponse{}, nil
	}

	s.mu.RLock()
	cfgs := make([]*config.PortableConfig, 0, len(s.configs))
	for _, p := range s.configs {
		cfgs = append(cfgs, p)
	}
	s.mu.RUnlock()

	clusters := make([]*cluster.Cluster, len(req.Clusters))
	copy(clusters, req.Clusters)

	// One shared ECDS gRPC cluster (STRICT_DNS, non-EDS).
	ecdsCluster, err := s.buildECDSCluster(cfgs)
	if err != nil {
		return nil, err
	}
	if ecdsCluster != nil {
		before := len(clusters)
		clusters = xdsutil.EnsureCluster(clusters, ecdsCluster)
		s.log.Info("PostTranslateModify: ensured ECDS cluster",
			"name", ecdsCluster.GetName(),
			"host", ecdsClusterHost(ecdsCluster),
			"added", len(clusters) > before,
			"indexedWAFs", len(cfgs),
			"totalClusters", len(clusters),
		)
	} else {
		s.log.Info("PostTranslateModify: skipped ECDS cluster (no host and no indexed WAFs)",
			"indexedWAFs", len(cfgs),
			"defaultHost", s.opts.DefaultECDSHost,
		)
	}

	// One wasm HTTP-fetch cluster per unique URL host.
	seenWasm := map[string]bool{}
	for _, p := range cfgs {
		urls := []string{p.HTTPURL}
		for _, f := range p.Filters {
			if f.HTTPURL != "" {
				urls = append(urls, f.HTTPURL)
			}
		}
		for _, u := range urls {
			if u == "" || seenWasm[u] {
				continue
			}
			c, err := xdsutil.MakeWasmCodeCluster(u)
			if err != nil {
				s.log.Error(err, "wasm code cluster", "url", u)
			} else {
				clusters = xdsutil.EnsureCluster(clusters, c)
			}
			seenWasm[u] = true
		}
	}

	return &egext.PostTranslateModifyResponse{
		Clusters:  clusters,
		Secrets:   req.Secrets,
		Listeners: req.Listeners,
		Routes:    req.Routes,
	}, nil
}

// buildECDSCluster builds the STRICT_DNS kubewaf_ecds cluster from the first
// indexed WAF, falling back to operator DefaultECDSHost/Port so the cluster is
// present even when this replica's index is empty or still warming.
func (s *Server) buildECDSCluster(cfgs []*config.PortableConfig) (*cluster.Cluster, error) {
	for _, p := range cfgs {
		if p == nil {
			continue
		}
		name := p.ECDSCluster
		if name == "" {
			name = config.DefaultECDSCluster
		}
		host := p.ECDSHost
		port := p.ECDSPort
		if host == "" {
			host = s.opts.DefaultECDSHost
		}
		if port == 0 {
			port = s.opts.DefaultECDSPort
		}
		if port == 0 {
			port = 18001
		}
		if host == "" {
			continue
		}
		return xdsutil.MakeECDSCluster(&config.PortableConfig{
			ECDSCluster: name,
			ECDSHost:    host,
			ECDSPort:    port,
		})
	}

	// No indexed WAF on this replica — still inject from operator defaults so
	// listeners that reference kubewaf_ecds (from another replica's inject) validate.
	host := s.opts.DefaultECDSHost
	port := s.opts.DefaultECDSPort
	if port == 0 {
		port = 18001
	}
	if host == "" {
		return nil, nil
	}
	return xdsutil.MakeECDSCluster(&config.PortableConfig{
		ECDSCluster: config.DefaultECDSCluster,
		ECDSHost:    host,
		ECDSPort:    port,
	})
}

func ecdsClusterHost(c *cluster.Cluster) string {
	if c == nil || c.LoadAssignment == nil {
		return ""
	}
	for _, loc := range c.LoadAssignment.Endpoints {
		for _, ep := range loc.LbEndpoints {
			if e := ep.GetEndpoint(); e != nil {
				if sa := e.GetAddress().GetSocketAddress(); sa != nil {
					return sa.GetAddress()
				}
			}
		}
	}
	return ""
}

// PostRouteModify is a no-op (required by the service interface).
func (s *Server) PostRouteModify(_ context.Context, req *egext.PostRouteModifyRequest) (*egext.PostRouteModifyResponse, error) {
	if req == nil {
		return &egext.PostRouteModifyResponse{}, nil
	}
	return &egext.PostRouteModifyResponse{Route: req.Route}, nil
}

// PostVirtualHostModify is a no-op.
func (s *Server) PostVirtualHostModify(_ context.Context, req *egext.PostVirtualHostModifyRequest) (*egext.PostVirtualHostModifyResponse, error) {
	if req == nil {
		return &egext.PostVirtualHostModifyResponse{}, nil
	}
	return &egext.PostVirtualHostModifyResponse{VirtualHost: req.VirtualHost}, nil
}

// PostClusterModify is a no-op.
func (s *Server) PostClusterModify(_ context.Context, req *egext.PostClusterModifyRequest) (*egext.PostClusterModifyResponse, error) {
	if req == nil {
		return &egext.PostClusterModifyResponse{}, nil
	}
	return &egext.PostClusterModifyResponse{Cluster: req.Cluster}, nil
}

// PostEndpointsModify is a no-op.
func (s *Server) PostEndpointsModify(_ context.Context, req *egext.PostEndpointsModifyRequest) (*egext.PostEndpointsModifyResponse, error) {
	if req == nil {
		return &egext.PostEndpointsModifyResponse{}, nil
	}
	return &egext.PostEndpointsModifyResponse{LoadAssignment: req.LoadAssignment}, nil
}

func (s *Server) matchingConfigs(req *egext.PostHTTPListenerModifyRequest) []*config.PortableConfig {
	// 1) From EG extension policy resources (WAF CRs registered as policyResources).
	var fromPolicy []*config.PortableConfig
	if ctx := req.PostListenerContext; ctx != nil {
		for _, er := range ctx.ExtensionResources {
			if p := portableFromUnstructured(er.UnstructuredBytes, s.opts); p != nil {
				fromPolicy = append(fromPolicy, p)
			}
		}
	}
	if len(fromPolicy) > 0 {
		return fromPolicy
	}

	// 2) From in-memory index: match listener name "ns/gateway/section" against parentRefs.
	gwNS, gwName := parseListenerGateway(req.Listener.GetName())
	if gwName == "" {
		return nil
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*config.PortableConfig
	for _, p := range s.configs {
		if matchesGateway(p, gwNS, gwName) {
			out = append(out, p)
		}
	}
	return out
}

func portableFromUnstructured(raw []byte, opts config.BuildOptions) *config.PortableConfig {
	if len(raw) == 0 {
		return nil
	}
	u := unstructured.Unstructured{}
	if err := u.UnmarshalJSON(raw); err != nil {
		return nil
	}
	if u.GetKind() != "WAF" {
		return nil
	}
	// Re-marshal into typed WAF for BuildFromWAF (rules empty — ECDS already has full config).
	// We only need identity + parentRefs for slot injection; plugin config is served via ECDS.
	b, err := u.MarshalJSON()
	if err != nil {
		return nil
	}
	var waf wafv1beta1.WAF
	if err := json.Unmarshal(b, &waf); err != nil {
		return nil
	}
	p, err := config.BuildFromWAF(&waf, nil, opts)
	if err != nil {
		return nil
	}
	// Force EG provider for policies delivered by EG.
	p.Provider = wafv1beta1.ProviderEnvoyGateway
	return p
}

// parseListenerGateway extracts namespace and gateway name from EG listener names
// of the form "{namespace}/{gateway}/{listenerSection}".
func parseListenerGateway(listenerName string) (ns, name string) {
	parts := strings.Split(listenerName, "/")
	if len(parts) < 2 {
		return "", ""
	}
	return parts[0], parts[1]
}

func matchesGateway(p *config.PortableConfig, gwNS, gwName string) bool {
	// PortableConfig.ParentRefs holds the full WAFSpec (legacy field name).
	refs := p.ParentRefs.EffectivePolicyTargets()
	// targetRef
	if tr := refs.TargetRef; tr != nil {
		if string(tr.Kind) == "Gateway" && string(tr.Name) == gwName {
			// Same-namespace policy attachment (EG requirement).
			return p.Namespace == gwNS || gwNS == ""
		}
		// HTTPRoute targets: inject at gateway level when we cannot resolve the route's parents.
		// v1 applies filter to the whole listener when any WAF in the gateway namespace targets an HTTPRoute.
		if string(tr.Kind) == "HTTPRoute" && p.Namespace == gwNS {
			return true
		}
	}
	for _, tr := range refs.TargetRefs {
		if string(tr.Kind) == "Gateway" && string(tr.Name) == gwName {
			return p.Namespace == gwNS || gwNS == ""
		}
		if string(tr.Kind) == "HTTPRoute" && p.Namespace == gwNS {
			return true
		}
	}
	return false
}

func injectFilters(l *listener.Listener, cfgs []*config.PortableConfig) error {
	// Default filter chain
	if fc := l.GetDefaultFilterChain(); fc != nil {
		if err := injectIntoFilterChain(fc, cfgs); err != nil {
			return err
		}
	}
	for _, fc := range l.GetFilterChains() {
		if err := injectIntoFilterChain(fc, cfgs); err != nil {
			return err
		}
	}
	return nil
}

func injectIntoFilterChain(fc *listener.FilterChain, cfgs []*config.PortableConfig) error {
	for i, f := range fc.Filters {
		if f.GetName() != "envoy.filters.network.http_connection_manager" &&
			!strings.Contains(f.GetName(), "http_connection_manager") {
			// Still try to unpack as HCM by type URL.
		}
		var mgr hcm.HttpConnectionManager
		if tc := f.GetTypedConfig(); tc != nil {
			if err := tc.UnmarshalTo(&mgr); err != nil {
				continue
			}
		} else {
			continue
		}

		// Skip if already injected.
		existing := map[string]bool{}
		for _, hf := range mgr.HttpFilters {
			existing[hf.GetName()] = true
		}

		var toInsert []*hcm.HttpFilter
		for _, p := range cfgs {
			for _, stub := range xdsutil.MakeECDSFilterStubs(p) {
				if existing[stub.GetName()] {
					continue
				}
				toInsert = append(toInsert, stub)
				existing[stub.GetName()] = true
			}
		}
		if len(toInsert) == 0 {
			return nil
		}

		// Insert before router filter.
		newFilters := make([]*hcm.HttpFilter, 0, len(mgr.HttpFilters)+len(toInsert))
		inserted := false
		for _, hf := range mgr.HttpFilters {
			if !inserted && (hf.GetName() == "envoy.filters.http.router" || strings.HasSuffix(hf.GetName(), "router")) {
				newFilters = append(newFilters, toInsert...)
				inserted = true
			}
			newFilters = append(newFilters, hf)
		}
		if !inserted {
			newFilters = append(newFilters, toInsert...)
		}
		mgr.HttpFilters = newFilters

		anyHCM, err := anypb.New(&mgr)
		if err != nil {
			return fmt.Errorf("pack HCM: %w", err)
		}
		fc.Filters[i] = &listener.Filter{
			Name: f.GetName(),
			ConfigType: &listener.Filter_TypedConfig{
				TypedConfig: anyHCM,
			},
		}
		return nil
	}
	return nil
}

// Run starts the Extension Server gRPC listener (blocks until ctx cancelled).
func (s *Server) Run(ctx context.Context, bindAddr string) error {
	var grpcOptions []grpc.ServerOption
	grpcOptions = append(grpcOptions,
		grpc.MaxConcurrentStreams(100000),
		grpc.KeepaliveParams(keepalive.ServerParameters{
			Time:    30 * time.Second,
			Timeout: 5 * time.Second,
		}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             30 * time.Second,
			PermitWithoutStream: true,
		}),
	)
	s.grpcServer = grpc.NewServer(grpcOptions...)
	egext.RegisterEnvoyGatewayExtensionServer(s.grpcServer, s)

	lc := net.ListenConfig{}
	lis, err := lc.Listen(ctx, "tcp", bindAddr)
	if err != nil {
		return fmt.Errorf("listen extension server %s: %w", bindAddr, err)
	}
	s.log.Info("Envoy Gateway extension server listening", "addr", bindAddr)

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
// EG Extension Server must answer hooks from every replica.
func (r Runnable) NeedLeaderElection() bool { return false }

// Ensure unused import of core for filter name checks in edge cases.
var _ = core.ApiVersion_V3
