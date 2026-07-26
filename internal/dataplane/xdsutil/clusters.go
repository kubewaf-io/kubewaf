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

// Package xdsutil builds shared Envoy xDS fragments (clusters, HTTP filter stubs).
package xdsutil

import (
	"time"

	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	endpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	httpv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/upstreams/http/v3"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/kubewaf-io/kubewaf/internal/dataplane/config"
	"github.com/kubewaf-io/kubewaf/internal/dataplane/ecds"
)

// MakeECDSCluster builds the STRICT_DNS cluster Envoy uses to open the ECDS gRPC stream.
func MakeECDSCluster(p *config.PortableConfig) (*cluster.Cluster, error) {
	return strictDNSCluster(p.ECDSCluster, p.ECDSHost, p.ECDSPort, true)
}

// MakeWasmCodeCluster builds the cluster Envoy uses to HTTP-fetch .wasm binaries.
// httpURL may be any module URL; host/port are derived from it. One shared
// cluster is used when all modules share the operator Service host.
func MakeWasmCodeCluster(httpURL string) (*cluster.Cluster, error) {
	host, port, err := ecds.WasmCodeClusterHostPort(httpURL)
	if err != nil {
		return nil, err
	}
	c, err := strictDNSCluster(ecds.WasmCodeCluster, host, port, false)
	if err != nil {
		return nil, err
	}
	if ecds.IsHTTPS(httpURL) {
		tlsAny, err := anypb.New(&tlsv3.UpstreamTlsContext{Sni: host})
		if err != nil {
			return nil, err
		}
		c.TransportSocket = &core.TransportSocket{
			Name:       "envoy.transport_sockets.tls",
			ConfigType: &core.TransportSocket_TypedConfig{TypedConfig: tlsAny},
		}
	}
	return c, nil
}

// MakeWasmCodeClusterFromPortable uses the primary WAF filter URL (compat).
func MakeWasmCodeClusterFromPortable(p *config.PortableConfig) (*cluster.Cluster, error) {
	url := p.HTTPURL
	if url == "" {
		for _, f := range p.Filters {
			if f.HTTPURL != "" {
				url = f.HTTPURL
				break
			}
		}
	}
	return MakeWasmCodeCluster(url)
}

func strictDNSCluster(name, host string, port uint32, http2 bool) (*cluster.Cluster, error) {
	c := &cluster.Cluster{
		Name:           name,
		ConnectTimeout: durationpb.New(2 * time.Second),
		ClusterDiscoveryType: &cluster.Cluster_Type{
			Type: cluster.Cluster_STRICT_DNS,
		},
		LbPolicy: cluster.Cluster_ROUND_ROBIN,
		LoadAssignment: &endpoint.ClusterLoadAssignment{
			ClusterName: name,
			Endpoints: []*endpoint.LocalityLbEndpoints{{
				LbEndpoints: []*endpoint.LbEndpoint{{
					HostIdentifier: &endpoint.LbEndpoint_Endpoint{
						Endpoint: &endpoint.Endpoint{
							Address: &core.Address{
								Address: &core.Address_SocketAddress{
									SocketAddress: &core.SocketAddress{
										Protocol: core.SocketAddress_TCP,
										Address:  host,
										PortSpecifier: &core.SocketAddress_PortValue{
											PortValue: port,
										},
									},
								},
							},
						},
					},
				}},
			}},
		},
	}

	if http2 {
		// ECDS is gRPC (HTTP/2).
		httpOpts := &httpv3.HttpProtocolOptions{
			UpstreamProtocolOptions: &httpv3.HttpProtocolOptions_ExplicitHttpConfig_{
				ExplicitHttpConfig: &httpv3.HttpProtocolOptions_ExplicitHttpConfig{
					ProtocolConfig: &httpv3.HttpProtocolOptions_ExplicitHttpConfig_Http2ProtocolOptions{
						Http2ProtocolOptions: &core.Http2ProtocolOptions{},
					},
				},
			},
		}
		anyOpts, err := anypb.New(httpOpts)
		if err != nil {
			return nil, err
		}
		c.TypedExtensionProtocolOptions = map[string]*anypb.Any{
			"envoy.extensions.upstreams.http.v3.HttpProtocolOptions": anyOpts,
		}
	}
	return c, nil
}

// MakeECDSFilterStub builds an HTTP filter that loads its config from ECDS.
func MakeECDSFilterStub(extensionName, ecdsCluster string) *hcm.HttpFilter {
	return &hcm.HttpFilter{
		Name: extensionName,
		ConfigType: &hcm.HttpFilter_ConfigDiscovery{
			ConfigDiscovery: &core.ExtensionConfigSource{
				ConfigSource: &core.ConfigSource{
					ResourceApiVersion: core.ApiVersion_V3,
					ConfigSourceSpecifier: &core.ConfigSource_ApiConfigSource{
						ApiConfigSource: &core.ApiConfigSource{
							ApiType:             core.ApiConfigSource_GRPC,
							TransportApiVersion: core.ApiVersion_V3,
							GrpcServices: []*core.GrpcService{{
								TargetSpecifier: &core.GrpcService_EnvoyGrpc_{
									EnvoyGrpc: &core.GrpcService_EnvoyGrpc{
										ClusterName: ecdsCluster,
									},
								},
							}},
							SetNodeOnFirstMessageOnly: true,
						},
					},
				},
				TypeUrls: []string{
					"type.googleapis.com/envoy.extensions.filters.http.wasm.v3.Wasm",
				},
			},
		},
	}
}

// MakeECDSFilterStubs returns ordered stubs for every filter in p (challenge then WAF).
func MakeECDSFilterStubs(p *config.PortableConfig) []*hcm.HttpFilter {
	if p == nil {
		return nil
	}
	if len(p.Filters) == 0 {
		return []*hcm.HttpFilter{MakeECDSFilterStub(p.ExtensionName, p.ECDSCluster)}
	}
	out := make([]*hcm.HttpFilter, 0, len(p.Filters))
	for _, f := range p.Filters {
		out = append(out, MakeECDSFilterStub(f.ExtensionName, p.ECDSCluster))
	}
	return out
}

// EnsureCluster appends cluster if no existing cluster has the same name.
func EnsureCluster(clusters []*cluster.Cluster, add *cluster.Cluster) []*cluster.Cluster {
	if add == nil {
		return clusters
	}
	for _, c := range clusters {
		if c.GetName() == add.GetName() {
			return clusters
		}
	}
	return append(clusters, add)
}
