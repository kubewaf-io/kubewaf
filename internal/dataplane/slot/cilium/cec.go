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

// Package cilium installs CiliumEnvoyConfig slots that point Cilium Envoy at kubeWAF ECDS.
package cilium

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

var cecGVK = schema.GroupVersionKind{
	Group:   "cilium.io",
	Version: "v2",
	Kind:    "CiliumEnvoyConfig",
}

// ResourceName returns the CiliumEnvoyConfig name for a WAF.
func ResourceName(wafName string) string {
	return "kubewaf-" + wafName
}

// EnsureCiliumEnvoyConfig creates/updates a CEC that:
//  1. Attaches to a Service (for Cilium L7 proxy selection)
//  2. Defines the kubewaf_ecds (+ wasm code) clusters for Envoy
//
// Full HTTP filter injection into Cilium-managed listeners depends on the
// cluster's Cilium Envoy build supporting Wasm/ECDS. The CEC still provides a
// stable, reviewable slot resource for GitOps and e2e.
func EnsureCiliumEnvoyConfig(ctx context.Context, c client.Client, owner client.Object, p *config.PortableConfig) error {
	if p == nil {
		return fmt.Errorf("portable config is nil")
	}

	svcName := p.CiliumServiceName
	if svcName == "" {
		svcName = p.Name
	}
	svcNS := p.CiliumServiceNamespace
	if svcNS == "" {
		svcNS = p.Namespace
	}

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
			"services": []any{
				map[string]any{
					"name":      svcName,
					"namespace": svcNS,
				},
			},
			"resources": buildResources(p),
		}
		return unstructured.SetNestedMap(cec.Object, spec, "spec")
	})
	return err
}

// DeleteCiliumEnvoyConfig removes the CEC if present.
func DeleteCiliumEnvoyConfig(ctx context.Context, c client.Client, namespace, wafName string) error {
	cec := &unstructured.Unstructured{}
	cec.SetGroupVersionKind(cecGVK)
	cec.SetNamespace(namespace)
	cec.SetName(ResourceName(wafName))
	err := c.Delete(ctx, cec)
	if errors.IsNotFound(err) {
		return nil
	}
	return err
}

// GetNamespacedName returns the CEC key for status reporting.
func GetNamespacedName(namespace, wafName string) types.NamespacedName {
	return types.NamespacedName{Namespace: namespace, Name: ResourceName(wafName)}
}

func buildResources(p *config.PortableConfig) []any {
	resources := []any{
		map[string]any{
			"@type":           "type.googleapis.com/envoy.config.cluster.v3.Cluster",
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
		},
	}

	if p.HTTPURL != "" {
		if host, port, err := ecds.WasmCodeClusterHostPort(p.HTTPURL); err == nil {
			wasmCluster := map[string]any{
				"@type":           "type.googleapis.com/envoy.config.cluster.v3.Cluster",
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
			if ecds.IsHTTPS(p.HTTPURL) {
				wasmCluster["transport_socket"] = map[string]any{
					"name": "envoy.transport_sockets.tls",
					"typed_config": map[string]any{
						"@type": "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext",
						"sni":   host,
					},
				}
			}
			resources = append(resources, wasmCluster)
		}
	}

	// Metadata resource documenting the ECDS filter name for operators / e2e.
	// Cilium listener merge of config_discovery filters is version-dependent;
	// clusters above enable Envoy to reach kubeWAF once a filter slot is present.
	resources = append(resources, map[string]any{
		"@type": "type.googleapis.com/envoy.config.core.v3.TypedExtensionConfig",
		"name":  p.ExtensionName,
		"typed_config": map[string]any{
			"@type": "type.googleapis.com/envoy.extensions.filters.http.wasm.v3.Wasm",
			"config": map[string]any{
				"name":    p.WasmName,
				"root_id": p.RootID,
				// Configuration is delivered live via ECDS for the filter named ExtensionName.
				// This CEC entry documents attachment; runtime config comes from kubeWAF ECDS.
				"configuration": map[string]any{
					"@type": "type.googleapis.com/google.protobuf.StringValue",
					"value": fmt.Sprintf(`{"kubewaf_ecds_resource":%q,"note":"runtime directives served via ECDS"}`, p.ExtensionName),
				},
			},
		},
	})

	return resources
}

func boolPtr(b bool) *bool { return &b }
