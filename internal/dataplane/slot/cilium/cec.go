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

// Package cilium installs CiliumEnvoyConfig slots that attach ECDS
// config_discovery HTTP filters to Cilium Envoy (Gateway + Service L7).
//
// Cilium xDS has no ECDS, so ApiConfigSource requires a bootstrap-static
// kubewaf_ecds cluster (see config/samples/cilium).
package cilium

import (
	"context"
	"fmt"
	"net"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	"github.com/kubewaf-io/kubewaf/internal/dataplane/config"
	"github.com/kubewaf-io/kubewaf/internal/dataplane/ecds"
)

var cecGVK = schema.GroupVersionKind{
	Group:   "cilium.io",
	Version: "v2",
	Kind:    "CiliumEnvoyConfig",
}

// ResourceName returns the CiliumEnvoyConfig name for a WAF.
func ResourceName(wafName string) string {
	return "kubewaf-" + wafName
}

// GatewayServiceName returns the Kubernetes Service name Cilium creates for a Gateway.
// Convention: cilium-gateway-<gateway-name> in the Gateway's namespace.
func GatewayServiceName(gatewayName string) string {
	return "cilium-gateway-" + gatewayName
}

// EnsureCiliumEnvoyConfig creates/updates a CEC that:
//  1. Attaches to one or more Services (app and/or Cilium Gateway Service)
//  2. Defines kubewaf_wasm_code (+ ORIGINAL_DST) clusters
//  3. Installs an HCM Listener with config_discovery stubs before the router
func EnsureCiliumEnvoyConfig(ctx context.Context, c client.Client, owner client.Object, p *config.PortableConfig) error {
	if p == nil {
		return fmt.Errorf("portable config is nil")
	}

	// hostNetwork Envoy often cannot resolve cluster.local; pin wasm fetch to ClusterIP.
	wasmEP := resolveWasmEndpoint(ctx, c, primaryHTTPURL(p))

	cec := &unstructured.Unstructured{}
	cec.SetGroupVersionKind(cecGVK)
	cec.SetNamespace(p.Namespace)
	cec.SetName(ResourceName(p.Name))

	_, err := controllerutil.CreateOrUpdate(ctx, c, cec, func() error {
		if owner != nil {
			apiVersion, kind := "waf.kubewaf.io/v1beta1", "WAF"
			if gvk := owner.GetObjectKind().GroupVersionKind(); gvk.Kind != "" {
				apiVersion = gvk.GroupVersion().String()
				kind = gvk.Kind
			}
			cec.SetOwnerReferences([]metav1.OwnerReference{{
				APIVersion: apiVersion,
				Kind:       kind,
				Name:       owner.GetName(),
				UID:        owner.GetUID(),
				Controller: boolPtr(true),
			}})
		}
		labels := cec.GetLabels()
		if labels == nil {
			labels = map[string]string{}
		}
		labels["app.kubernetes.io/managed-by"] = "kubewaf"
		labels["kubewaf.io/waf"] = p.Name
		cec.SetLabels(labels)

		spec := map[string]any{
			"services":  buildServices(p),
			"resources": buildResources(p, wasmEP),
		}
		return unstructured.SetNestedMap(cec.Object, spec, "spec")
	})
	return err
}

// DeleteCiliumEnvoyConfig removes the CEC if present.
// Missing object or missing Cilium CRDs (NoKindMatch) are treated as success so
// Envoy Gateway / Istio-only clusters can finish WAF deletion.
func DeleteCiliumEnvoyConfig(ctx context.Context, c client.Client, namespace, wafName string) error {
	cec := &unstructured.Unstructured{}
	cec.SetGroupVersionKind(cecGVK)
	cec.SetNamespace(namespace)
	cec.SetName(ResourceName(wafName))
	err := c.Delete(ctx, cec)
	if err == nil || apierrors.IsNotFound(err) || meta.IsNoMatchError(err) {
		return nil
	}
	return err
}

// GetNamespacedName returns the CEC key for status reporting.
func GetNamespacedName(namespace, wafName string) types.NamespacedName {
	return types.NamespacedName{Namespace: namespace, Name: ResourceName(wafName)}
}

// buildServices lists Kubernetes Services that should be redirected through Envoy
// with this CEC. Always includes the configured app service; when the WAF targets
// a Gateway, also includes the Cilium-managed gateway Service so filters apply on
// the Gateway listener path.
func buildServices(p *config.PortableConfig) []any {
	svcName := p.CiliumServiceName
	if svcName == "" {
		svcName = p.Name
	}
	svcNS := p.CiliumServiceNamespace
	if svcNS == "" {
		svcNS = p.Namespace
	}

	seen := map[string]struct{}{}
	var out []any
	add := func(name, ns string) {
		key := ns + "/" + name
		if _, ok := seen[key]; ok || name == "" {
			return
		}
		seen[key] = struct{}{}
		out = append(out, map[string]any{
			"name":      name,
			"namespace": ns,
		})
	}

	// Prefer Gateway Service first so L7 filter attaches to ingress traffic.
	for _, gw := range gatewayTargets(p) {
		add(GatewayServiceName(gw.name), gw.namespace)
	}
	add(svcName, svcNS)
	return out
}

type gwRef struct {
	name, namespace string
}

func gatewayTargets(p *config.PortableConfig) []gwRef {
	var out []gwRef
	// PolicyTargets is the resolved attachment surface from BuildFromWAF.
	// TargetRef is LocalPolicyTargetReference — same namespace as the WAF.
	targets := p.PolicyTargets
	add := func(name string) {
		if name == "" {
			return
		}
		out = append(out, gwRef{name: name, namespace: p.Namespace})
	}
	//nolint:staticcheck // SA1019: TargetRef compat
	if tr := targets.TargetRef; tr != nil && tr.Kind == "Gateway" {
		add(string(tr.Name))
	}
	for _, tr := range targets.TargetRefs {
		if tr.Kind == "Gateway" {
			add(string(tr.Name))
		}
	}
	return out
}

// wasmEndpoint is the Envoy upstream used to HTTP-fetch .wasm binaries.
type wasmEndpoint struct {
	host  string
	port  uint32
	https bool
	// static is true when host is a literal IP (preferred for hostNetwork Envoy).
	static bool
}

// resolveWasmEndpoint maps a wasm HTTP URL to a cluster endpoint reachable from
// Cilium's hostNetwork Envoy. That Envoy often cannot resolve cluster.local DNS,
// so we resolve the hostname here in the operator (in-cluster DNS works) and
// emit a STATIC cluster with the resulting IP (typically the Service ClusterIP).
//
// We deliberately avoid client.Get(Service): that would start a Service informer
// and requires list/watch RBAC the operator may not have.
func resolveWasmEndpoint(ctx context.Context, _ client.Client, httpURL string) wasmEndpoint {
	if httpURL == "" {
		return wasmEndpoint{}
	}
	host, port, err := ecds.WasmCodeClusterHostPort(httpURL)
	if err != nil {
		return wasmEndpoint{}
	}
	ep := wasmEndpoint{host: host, port: port, https: ecds.IsHTTPS(httpURL)}
	if ip := net.ParseIP(host); ip != nil {
		ep.static = true
		return ep
	}
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil || len(ips) == 0 {
		return ep
	}
	// Prefer IPv4 for Envoy STATIC clusters in dual-stack kind clusters.
	for _, a := range ips {
		if v4 := a.IP.To4(); v4 != nil {
			ep.host = v4.String()
			ep.static = true
			return ep
		}
	}
	ep.host = ips[0].IP.String()
	ep.static = true
	return ep
}

func buildResources(p *config.PortableConfig, wasmEP wasmEndpoint) []any {
	var resources []any

	// One kubewaf_wasm_code cluster (Envoy requires a single named cluster for
	// RemoteDataSource HTTP fetch). Prefer ClusterIP for hostNetwork Cilium Envoy.
	if wasmEP.host == "" && primaryHTTPURL(p) != "" {
		// Fallback for unit tests without a client.
		if host, port, err := ecds.WasmCodeClusterHostPort(primaryHTTPURL(p)); err == nil {
			wasmEP = wasmEndpoint{host: host, port: port, https: ecds.IsHTTPS(primaryHTTPURL(p))}
		}
	}
	if wasmEP.host != "" {
		resources = append(resources, wasmCodeClusterResource(wasmEP))
	}

	// Backend for service-mode L7 (non-gateway): preserve original destination.
	resources = append(resources, originalDstClusterResource())

	hasGW := len(gatewayTargets(p)) > 0
	if hasGW {
		// Explicit EDS cluster for the app Service (Cilium fills endpoints).
		// Required because route cluster refs are namespaced to this CEC and
		// cannot use the gateway CEC's demo:httpbin:80 cluster.
		resources = append(resources, backendServiceClusterResource(p))
		// Single listener for Gateway (and any other selected Services).
		// Do NOT also emit a service-mode ORIGINAL_DST listener: Cilium applies
		// all CEC listeners to selected services, and ORIGINAL_DST breaks
		// Gateway traffic (original dest is the gateway, not the backend).
		resources = append(resources, gatewayListenerResource(p))
		return resources
	}
	// Service-only mode: ORIGINAL_DST preserves the real backend.
	resources = append(resources, serviceListenerResource(p))
	resources = append(resources, serviceRouteResource(p))

	return resources
}

// backendServiceClusterResource defines a Cilium EDS cluster for ns:name:port.
func backendServiceClusterResource(p *config.PortableConfig) map[string]any {
	svcName := p.CiliumServiceName
	if svcName == "" {
		svcName = p.Name
	}
	svcNS := p.CiliumServiceNamespace
	if svcNS == "" {
		svcNS = p.Namespace
	}
	// Cluster name form used in routes: "namespace:name:port"
	// EDS service name form used by Cilium: "namespace/name:port"
	clusterName := fmt.Sprintf("%s:%s:%d", svcNS, svcName, 80)
	edsName := fmt.Sprintf("%s/%s:%d", svcNS, svcName, 80)
	return map[string]any{
		"@type":           "type.googleapis.com/envoy.config.cluster.v3.Cluster",
		"name":            clusterName,
		"type":            "EDS",
		"connect_timeout": "5s",
		"lb_policy":       "ROUND_ROBIN",
		"eds_cluster_config": map[string]any{
			"service_name": edsName,
		},
		"typed_extension_protocol_options": map[string]any{
			"envoy.extensions.upstreams.http.v3.HttpProtocolOptions": map[string]any{
				"@type": "type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions",
				"use_downstream_protocol_config": map[string]any{
					"http_protocol_options":  map[string]any{},
					"http2_protocol_options": map[string]any{},
				},
			},
		},
	}
}

func primaryHTTPURL(p *config.PortableConfig) string {
	if p == nil {
		return ""
	}
	for _, f := range p.Filters {
		if f.HTTPURL != "" {
			return f.HTTPURL
		}
	}
	return p.HTTPURL
}

func portableFilters(p *config.PortableConfig) []config.PortableFilter {
	if p == nil {
		return nil
	}
	if len(p.Filters) > 0 {
		return p.Filters
	}
	// Compat: single WAF filter from top-level fields.
	if p.HTTPURL == "" && p.ExtensionName == "" {
		return nil
	}
	return []config.PortableFilter{{
		ExtensionName: p.ExtensionName,
		Role:          config.FilterRoleWAF,
		WasmName:      p.WasmName,
		RootID:        p.RootID,
		HTTPURL:       p.HTTPURL,
		SHA256:        p.SHA256,
		PluginJSON:    p.PluginJSON,
	}}
}

func wasmCodeClusterResource(ep wasmEndpoint) map[string]any {
	// STATIC + ClusterIP: Cilium Envoy is hostNetwork and cannot resolve cluster DNS.
	// STRICT_DNS only when we still have a hostname (non-k8s or lookup failed).
	clusterType := "STRICT_DNS"
	if ep.static || net.ParseIP(ep.host) != nil {
		clusterType = "STATIC"
	}
	wasmCluster := map[string]any{
		"@type":           "type.googleapis.com/envoy.config.cluster.v3.Cluster",
		"name":            ecds.WasmCodeCluster,
		"type":            clusterType,
		"connect_timeout": "5s",
		"lb_policy":       "ROUND_ROBIN",
		"load_assignment": map[string]any{
			"cluster_name": ecds.WasmCodeCluster,
			"endpoints": []any{
				map[string]any{
					"lb_endpoints": []any{
						map[string]any{
							"endpoint": map[string]any{
								"address": map[string]any{
									"socket_address": map[string]any{
										"address":    ep.host,
										"port_value": int64(ep.port),
									},
								},
							},
						},
					},
				},
			},
		},
	}
	if ep.https {
		// SNI needs a hostname; when using ClusterIP fall back to a generic SNI.
		sni := ep.host
		if net.ParseIP(sni) != nil {
			sni = "kubewaf-wasm"
		}
		wasmCluster["transport_socket"] = map[string]any{
			"name": "envoy.transport_sockets.tls",
			"typed_config": map[string]any{
				"@type": "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext",
				"sni":   sni,
			},
		}
	}
	return wasmCluster
}

func originalDstClusterResource() map[string]any {
	return map[string]any{
		"@type":            "type.googleapis.com/envoy.config.cluster.v3.Cluster",
		"name":             "kubewaf_original_dst",
		"type":             "ORIGINAL_DST",
		"lb_policy":        "CLUSTER_PROVIDED",
		"cleanup_interval": "1s",
		"typed_extension_protocol_options": map[string]any{
			"envoy.extensions.upstreams.http.v3.HttpProtocolOptions": map[string]any{
				"@type": "type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions",
				"use_downstream_protocol_config": map[string]any{
					"http_protocol_options":  map[string]any{},
					"http2_protocol_options": map[string]any{},
				},
			},
		},
	}
}

// backendServiceCluster is Cilium's auto service cluster name "ns:name:port".
// Cilium rewrites references inside RouteConfiguration within the same CEC.
func backendServiceCluster(p *config.PortableConfig) string {
	svcName := p.CiliumServiceName
	if svcName == "" {
		svcName = p.Name
	}
	svcNS := p.CiliumServiceNamespace
	if svcNS == "" {
		svcNS = p.Namespace
	}
	// Default HTTP port for e2e / typical apps; Gateway HTTPRoute backends are :80.
	return fmt.Sprintf("%s:%s:%d", svcNS, svcName, 80)
}

func httpFilters(p *config.PortableConfig) []any {
	// Same config_discovery stub as Istio; kubewaf_ecds must be bootstrap-static.
	cluster := ecdsClusterName(p)
	var filters []any
	for _, f := range portableFilters(p) {
		name := f.ExtensionName
		if name == "" {
			name = f.WasmName
		}
		if name == "" {
			continue
		}
		filters = append(filters, ecdsHTTPFilter(name, cluster))
	}
	filters = append(filters, map[string]any{
		"name": "envoy.filters.http.router",
		"typed_config": map[string]any{
			"@type": "type.googleapis.com/envoy.extensions.filters.http.router.v3.Router",
		},
	})
	return filters
}

func hcmAccessLogs(p *config.PortableConfig) []any {
	// Cilium 1.19 protojson rejects OpenTelemetryAccessLogConfig
	// (`unknown field "grpc_service"` / `"stat_prefix"`) and then
	// withdraws the whole CEC listener — traffic bypasses the WAF.
	// TelemetrySink for Cilium is the remesh STATIC kubewaf_otel cluster,
	// not an HCM access logger. Keep this nil until Cilium can parse the type.
	_ = p
	return nil
}

func withAccessLog(tc map[string]any, p *config.PortableConfig) map[string]any {
	if logs := hcmAccessLogs(p); len(logs) > 0 {
		tc["access_log"] = logs
	}
	return tc
}

func ecdsClusterName(p *config.PortableConfig) string {
	if p != nil && p.ECDSCluster != "" {
		return p.ECDSCluster
	}
	return config.DefaultECDSCluster
}

// ecdsHTTPFilter is the EG/Istio ECDS stub (ApiConfigSource → kubewaf_ecds).
func ecdsHTTPFilter(extensionName, ecdsCluster string) map[string]any {
	if ecdsCluster == "" {
		ecdsCluster = config.DefaultECDSCluster
	}
	return map[string]any{
		"name": extensionName,
		"config_discovery": map[string]any{
			"config_source": map[string]any{
				"resource_api_version": "V3",
				"api_config_source": map[string]any{
					"api_type":                       "GRPC",
					"transport_api_version":          "V3",
					"set_node_on_first_message_only": true,
					"grpc_services": []any{
						map[string]any{
							"envoy_grpc": map[string]any{
								"cluster_name": ecdsCluster,
							},
						},
					},
				},
			},
			"type_urls": []any{
				"type.googleapis.com/envoy.extensions.filters.http.wasm.v3.Wasm",
			},
		},
	}
}

// gatewayListenerResource is the L7 listener Cilium attaches when our CEC selects
// the Gateway Service. Cilium namespaces listeners, so this does not patch the
// gateway CEC's listener — it becomes the active L7 path for that Service.
// Use an inline route_config to the app Service (Cilium auto cluster ns:name:port)
// rather than RDS to the gateway CEC's listener-insecure (different name prefix).
func gatewayListenerResource(p *config.PortableConfig) map[string]any {
	backend := backendServiceCluster(p)
	return map[string]any{
		"@type": "type.googleapis.com/envoy.config.listener.v3.Listener",
		"name":  "listener",
		"filter_chains": []any{
			map[string]any{
				"filter_chain_match": map[string]any{
					"transport_protocol": "raw_buffer",
				},
				"filters": []any{
					map[string]any{
						"name": "envoy.filters.network.http_connection_manager",
						"typed_config": withAccessLog(map[string]any{
							"@type":              "type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager",
							"stat_prefix":        "kubewaf-gateway",
							"use_remote_address": true,
							"route_config": map[string]any{
								"name": "kubewaf-gateway-route",
								"virtual_hosts": []any{
									map[string]any{
										"name":    "kubewaf-gateway",
										"domains": []any{"*"},
										"routes": []any{
											map[string]any{
												"match": map[string]any{"prefix": "/"},
												"route": map[string]any{
													"cluster": backend,
												},
											},
										},
									},
								},
							},
							"http_filters": httpFilters(p),
							"upgrade_configs": []any{
								map[string]any{"upgrade_type": "websocket"},
							},
						}, p),
					},
				},
			},
		},
		"listener_filters": []any{
			map[string]any{
				"name": "envoy.filters.listener.tls_inspector",
				"typed_config": map[string]any{
					"@type": "type.googleapis.com/envoy.extensions.filters.listener.tls_inspector.v3.TlsInspector",
				},
			},
		},
	}
}

// serviceListenerResource handles L7 for the app Service (ORIGINAL_DST backend).
func serviceListenerResource(p *config.PortableConfig) map[string]any {
	return map[string]any{
		"@type": "type.googleapis.com/envoy.config.listener.v3.Listener",
		"name":  "kubewaf-" + p.Name + "-listener",
		"filter_chains": []any{
			map[string]any{
				"filters": []any{
					map[string]any{
						"name": "envoy.filters.network.http_connection_manager",
						"typed_config": withAccessLog(map[string]any{
							"@type":       "type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager",
							"stat_prefix": "kubewaf-" + p.Name,
							"rds": map[string]any{
								"route_config_name": "kubewaf-" + p.Name + "-route",
							},
							"http_filters": httpFilters(p),
						}, p),
					},
				},
			},
		},
	}
}

func serviceRouteResource(p *config.PortableConfig) map[string]any {
	return map[string]any{
		"@type": "type.googleapis.com/envoy.config.route.v3.RouteConfiguration",
		"name":  "kubewaf-" + p.Name + "-route",
		"virtual_hosts": []any{
			map[string]any{
				"name":    "kubewaf-backend",
				"domains": []any{"*"},
				"routes": []any{
					map[string]any{
						"match": map[string]any{
							"prefix": "/",
						},
						"route": map[string]any{
							"cluster": "kubewaf_original_dst",
						},
					},
				},
			},
		},
	}
}

func boolPtr(b bool) *bool { return &b }
