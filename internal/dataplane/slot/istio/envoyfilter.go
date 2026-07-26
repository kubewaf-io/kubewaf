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

// Package istio installs EnvoyFilter slots that point Istio gateways at kubeWAF ECDS.
package istio

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	"github.com/kubewaf-io/kubewaf/internal/dataplane/config"
	"github.com/kubewaf-io/kubewaf/internal/dataplane/ecds"
)

var envoyFilterGVK = schema.GroupVersionKind{
	Group:   "networking.istio.io",
	Version: "v1alpha3",
	Kind:    "EnvoyFilter",
}

// ResourceName returns the EnvoyFilter name for a WAF.
func ResourceName(wafName string) string {
	return "kubewaf-" + wafName
}

// EnsureEnvoyFilter creates or updates an EnvoyFilter that:
//  1. Adds the kubewaf_ecds (and wasm code) clusters
//  2. Inserts an HTTP filter with config_discovery pointing at ECDS
func EnsureEnvoyFilter(ctx context.Context, c client.Client, owner client.Object, p *config.PortableConfig) error {
	if p == nil {
		return fmt.Errorf("portable config is nil")
	}

	ef := &unstructured.Unstructured{}
	ef.SetGroupVersionKind(envoyFilterGVK)
	ef.SetNamespace(p.Namespace)
	ef.SetName(ResourceName(p.Name))

	_, err := controllerutil.CreateOrUpdate(ctx, c, ef, func() error {
		if owner != nil {
			// Manual owner ref — EnvoyFilter is unstructured and may not be in the scheme.
			apiVersion, kind := "waf.kubewaf.io/v1beta1", "WAF"
			if gvk := owner.GetObjectKind().GroupVersionKind(); gvk.Kind != "" {
				apiVersion = gvk.GroupVersion().String()
				kind = gvk.Kind
			}
			ef.SetOwnerReferences([]metav1.OwnerReference{{
				APIVersion: apiVersion,
				Kind:       kind,
				Name:       owner.GetName(),
				UID:        owner.GetUID(),
				Controller: boolPtr(true),
			}})
		}
		labels := ef.GetLabels()
		if labels == nil {
			labels = map[string]string{}
		}
		labels["app.kubernetes.io/managed-by"] = "kubewaf"
		labels["kubewaf.io/waf"] = p.Name
		ef.SetLabels(labels)

		spec, err := buildSpec(p)
		if err != nil {
			return err
		}
		return unstructured.SetNestedMap(ef.Object, spec, "spec")
	})
	return err
}

func boolPtr(b bool) *bool { return &b }

// DeleteEnvoyFilter removes the EnvoyFilter for a WAF if present.
func DeleteEnvoyFilter(ctx context.Context, c client.Client, namespace, wafName string) error {
	ef := &unstructured.Unstructured{}
	ef.SetGroupVersionKind(envoyFilterGVK)
	ef.SetNamespace(namespace)
	ef.SetName(ResourceName(wafName))
	err := c.Delete(ctx, ef)
	if errors.IsNotFound(err) {
		return nil
	}
	return err
}

// GetNamespacedName returns the EnvoyFilter key for status reporting.
func GetNamespacedName(namespace, wafName string) types.NamespacedName {
	return types.NamespacedName{Namespace: namespace, Name: ResourceName(wafName)}
}

func buildSpec(p *config.PortableConfig) (map[string]any, error) {
	selector := p.IstioWorkloadSelector
	if len(selector) == 0 {
		selector = map[string]string{"istio": "ingressgateway"}
	}
	ctxName := p.IstioContext
	if ctxName == "" {
		ctxName = "GATEWAY"
	}

	// Workload selector as map[string]any for unstructured.
	selAny := map[string]any{}
	for k, v := range selector {
		selAny[k] = v
	}

	patches := []any{
		// Cluster: ECDS gRPC
		map[string]any{
			"applyTo": "CLUSTER",
			"match": map[string]any{
				"context": ctxName,
			},
			"patch": map[string]any{
				"operation": "ADD",
				"value":     ecdsClusterValue(p),
			},
		},
	}

	// HTTP filters: challenge then WAF (INSERT_BEFORE router; later patches sit closer to router).
	// Insert WAF first, then challenge, so final order is challenge → WAF → router.
	filterNames := []string{p.ExtensionName}
	if len(p.Filters) > 0 {
		filterNames = nil
		for _, f := range p.Filters {
			filterNames = append(filterNames, f.ExtensionName)
		}
	}
	// Reverse so first filter ends up furthest from router (first in chain).
	for i := len(filterNames) - 1; i >= 0; i-- {
		patches = append(patches, map[string]any{
			"applyTo": "HTTP_FILTER",
			"match": map[string]any{
				"context": ctxName,
				"listener": map[string]any{
					"filterChain": map[string]any{
						"filter": map[string]any{
							"name": "envoy.filters.network.http_connection_manager",
							"subFilter": map[string]any{
								"name": "envoy.filters.http.router",
							},
						},
					},
				},
			},
			"patch": map[string]any{
				"operation": "INSERT_BEFORE",
				"value":     ecdsFilterValueNamed(p, filterNames[i]),
			},
		})
	}

	httpURL := p.HTTPURL
	for _, f := range p.Filters {
		if f.HTTPURL != "" {
			httpURL = f.HTTPURL
			break
		}
	}
	if httpURL != "" {
		wasmCluster, err := wasmCodeClusterValueURL(httpURL)
		if err == nil {
			patches = append([]any{
				map[string]any{
					"applyTo": "CLUSTER",
					"match": map[string]any{
						"context": ctxName,
					},
					"patch": map[string]any{
						"operation": "ADD",
						"value":     wasmCluster,
					},
				},
			}, patches...)
		}
	}

	return map[string]any{
		"workloadSelector": map[string]any{
			"labels": selAny,
		},
		"configPatches": patches,
		// Priority so kubeWAF filters apply in a predictable order when multiple EnvoyFilters exist.
		"priority": int64(10),
	}, nil
}

func ecdsClusterValue(p *config.PortableConfig) map[string]any {
	return map[string]any{
		"name":            p.ECDSCluster,
		"type":            "STRICT_DNS",
		"connect_timeout": "2s",
		"lb_policy":       "ROUND_ROBIN",
		"typed_extension_protocol_options": map[string]any{
			"envoy.extensions.upstreams.http.v3.HttpProtocolOptions": map[string]any{
				"@type": "type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions",
				"explicit_http_config": map[string]any{
					"http2_protocol_options": map[string]any{},
				},
			},
		},
		"load_assignment": map[string]any{
			"cluster_name": p.ECDSCluster,
			"endpoints": []any{
				map[string]any{
					"lb_endpoints": []any{
						map[string]any{
							"endpoint": map[string]any{
								"address": map[string]any{
									"socket_address": map[string]any{
										"address":    p.ECDSHost,
										"port_value": int64(p.ECDSPort),
									},
								},
							},
						},
					},
				},
			},
		},
	}
}

func ecdsFilterValueNamed(p *config.PortableConfig, extensionName string) map[string]any {
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
								"cluster_name": p.ECDSCluster,
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

func wasmCodeClusterValueURL(httpURL string) (map[string]any, error) {
	host, port, err := ecds.WasmCodeClusterHostPort(httpURL)
	if err != nil {
		return nil, err
	}
	val := map[string]any{
		"name":            ecds.WasmCodeCluster,
		"type":            "STRICT_DNS",
		"connect_timeout": "2s",
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
										"address":    host,
										"port_value": int64(port),
									},
								},
							},
						},
					},
				},
			},
		},
	}
	if ecds.IsHTTPS(httpURL) {
		val["transport_socket"] = map[string]any{
			"name": "envoy.transport_sockets.tls",
			"typed_config": map[string]any{
				"@type": "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext",
				"sni":   host,
			},
		}
	}
	return val, nil
}
