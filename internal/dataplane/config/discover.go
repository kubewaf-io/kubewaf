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

package config

import (
	"context"
	"fmt"
	"strings"

	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"

	wafv1beta1 "github.com/kubewaf-io/kubewaf/api/waf/v1beta1"
)

// DiscoveryResult is the outcome of auto-detecting the data-plane provider.
type DiscoveryResult struct {
	// Provider is never Auto; it is a concrete type.
	Provider wafv1beta1.ProviderType
	// Reason is a short human-readable explanation for status/logs.
	Reason string

	// CiliumServiceName/Namespace are filled when Provider=Cilium and the WAF
	// did not set provider.cilium.serviceName (from target Service or HTTPRoute).
	CiliumServiceName      string
	CiliumServiceNamespace string
}

// NeedsProviderDiscovery reports whether the WAF left provider type empty or Auto.
func NeedsProviderDiscovery(waf *wafv1beta1.WAF) bool {
	if waf == nil {
		return true
	}
	p := waf.Spec.Provider
	if p == nil {
		return true
	}
	switch p.Type {
	case "", wafv1beta1.ProviderAuto:
		return true
	default:
		return false
	}
}

// ProviderFromControllerName maps a GatewayClass.spec.controllerName to a
// kubeWAF ProviderType. Unknown controllers return ("", false).
func ProviderFromControllerName(controllerName string) (wafv1beta1.ProviderType, bool) {
	c := strings.ToLower(strings.TrimSpace(controllerName))
	if c == "" {
		return "", false
	}
	switch {
	case strings.Contains(c, "envoyproxy.io"),
		strings.Contains(c, "gateway.envoyproxy.io"):
		return wafv1beta1.ProviderEnvoyGateway, true
	case strings.Contains(c, "istio.io"),
		strings.HasPrefix(c, "istio/"):
		return wafv1beta1.ProviderIstio, true
	case strings.Contains(c, "cilium"),
		strings.Contains(c, "io.cilium"):
		return wafv1beta1.ProviderCilium, true
	default:
		return "", false
	}
}

// DiscoverProvider selects a concrete data-plane provider when the WAF uses
// Auto / empty provider.type.
//
// Order of preference:
//  1. GatewayClass.controllerName of a targeted Gateway (most accurate)
//  2. Which platform CRDs are installed (EnvoyFilter, CiliumEnvoyConfig, EG)
//  3. DefaultProvider (EnvoyGateway)
//
// When Cilium is selected, also best-effort fills Cilium service attachment
// from a target Service or HTTPRoute backends.
func DiscoverProvider(ctx context.Context, c client.Reader, waf *wafv1beta1.WAF) (DiscoveryResult, error) {
	if waf == nil {
		return DiscoveryResult{Provider: DefaultProvider, Reason: "nil waf"}, nil
	}
	if c == nil {
		return DiscoveryResult{Provider: DefaultProvider, Reason: "no client; using default"}, nil
	}

	// 1) From targeted Gateway → GatewayClass.
	if prov, reason, ok := discoverFromTargetedGateways(ctx, c, waf); ok {
		res := DiscoveryResult{Provider: prov, Reason: reason}
		fillCiliumService(ctx, c, waf, &res)
		return res, nil
	}

	// 2) From installed platform CRDs / APIs.
	if prov, reason, ok := discoverFromInstalledAPIs(ctx, c); ok {
		res := DiscoveryResult{Provider: prov, Reason: reason}
		fillCiliumService(ctx, c, waf, &res)
		return res, nil
	}

	// 3) Default.
	res := DiscoveryResult{
		Provider: DefaultProvider,
		Reason:   "no GatewayClass or platform CRDs detected; default " + string(DefaultProvider),
	}
	fillCiliumService(ctx, c, waf, &res)
	return res, nil
}

func discoverFromTargetedGateways(ctx context.Context, c client.Reader, waf *wafv1beta1.WAF) (wafv1beta1.ProviderType, string, bool) {
	targets := waf.Spec.EffectivePolicyTargets()
	var gws []struct{ name, ns string }

	add := func(kind, name, ns string) {
		if kind != "Gateway" || name == "" {
			return
		}
		if ns == "" {
			ns = waf.Namespace
		}
		gws = append(gws, struct{ name, ns string }{name, ns})
	}

	//nolint:staticcheck // SA1019: TargetRef compat
	if tr := targets.TargetRef; tr != nil {
		add(string(tr.Kind), string(tr.Name), waf.Namespace)
	}
	//nolint:staticcheck // SA1019: TargetRef compat
	for _, tr := range targets.TargetRefs {
		ns := waf.Namespace
		// LocalPolicyTargetReference has no namespace; stay same-ns.
		add(string(tr.Kind), string(tr.Name), ns)
	}

	var chosen wafv1beta1.ProviderType
	var chosenReason string
	for _, g := range gws {
		var gw gwapiv1.Gateway
		if err := c.Get(ctx, client.ObjectKey{Namespace: g.ns, Name: g.name}, &gw); err != nil {
			continue
		}
		className := string(gw.Spec.GatewayClassName)
		if className == "" {
			continue
		}
		// Prefer GatewayClass.controllerName (authoritative implementation id).
		var gc gwapiv1.GatewayClass
		if err := c.Get(ctx, client.ObjectKey{Name: className}, &gc); err == nil {
			ctrlName := string(gc.Spec.ControllerName)
			if p, ok := ProviderFromControllerName(ctrlName); ok {
				reason := fmt.Sprintf(
					"targetRef Gateway %s/%s → GatewayClass %q → controller %q",
					g.ns, g.name, className, ctrlName,
				)
				if chosen == "" {
					chosen = p
					chosenReason = reason
					continue
				}
				if chosen != p {
					// Conflicting gateways: keep first successful detection.
					return chosen, chosenReason + " (first of multiple targets)", true
				}
				continue
			}
		}
		// Fallback: GatewayClass name heuristics (cilium / istio / eg).
		if p, ok := providerFromGatewayClassName(className); ok {
			reason := fmt.Sprintf(
				"targetRef Gateway %s/%s → gatewayClassName %q",
				g.ns, g.name, className,
			)
			if chosen == "" {
				chosen = p
				chosenReason = reason
			}
		}
	}
	if chosen != "" {
		return chosen, chosenReason, true
	}
	return "", "", false
}

func providerFromGatewayClassName(name string) (wafv1beta1.ProviderType, bool) {
	n := strings.ToLower(name)
	switch {
	case strings.Contains(n, "cilium"):
		return wafv1beta1.ProviderCilium, true
	case strings.Contains(n, "istio"):
		return wafv1beta1.ProviderIstio, true
	case n == "eg", strings.Contains(n, "envoy"), strings.Contains(n, "envoy-gateway"):
		return wafv1beta1.ProviderEnvoyGateway, true
	default:
		return "", false
	}
}

func discoverFromInstalledAPIs(ctx context.Context, c client.Reader) (wafv1beta1.ProviderType, string, bool) {
	// Prefer unique signals. When several are present, Envoy Gateway wins
	// (operator always runs the EG extension server); operators with only
	// Istio/Cilium get those via CRD presence alone.
	hasEG := apiAvailable(ctx, c, schema.GroupVersionKind{
		Group: "gateway.envoyproxy.io", Version: "v1alpha1", Kind: "EnvoyProxy",
	}) || apiAvailable(ctx, c, schema.GroupVersionKind{
		Group: "gateway.envoyproxy.io", Version: "v1alpha1", Kind: "ClientTrafficPolicy",
	})
	hasIstio := apiAvailable(ctx, c, schema.GroupVersionKind{
		Group: "networking.istio.io", Version: "v1alpha3", Kind: "EnvoyFilter",
	}) || apiAvailable(ctx, c, schema.GroupVersionKind{
		Group: "networking.istio.io", Version: "v1beta1", Kind: "EnvoyFilter",
	})
	hasCilium := apiAvailable(ctx, c, schema.GroupVersionKind{
		Group: "cilium.io", Version: "v2", Kind: "CiliumEnvoyConfig",
	})

	// Single-provider clusters.
	n := 0
	if hasEG {
		n++
	}
	if hasIstio {
		n++
	}
	if hasCilium {
		n++
	}
	if n == 1 {
		switch {
		case hasEG:
			return wafv1beta1.ProviderEnvoyGateway, "detected Envoy Gateway APIs", true
		case hasIstio:
			return wafv1beta1.ProviderIstio, "detected Istio EnvoyFilter API", true
		case hasCilium:
			return wafv1beta1.ProviderCilium, "detected CiliumEnvoyConfig API", true
		}
	}
	if n > 1 {
		// Multiple platforms: prefer EG if present, else Istio, else Cilium.
		if hasEG {
			return wafv1beta1.ProviderEnvoyGateway, "multiple platforms installed; preferring Envoy Gateway", true
		}
		if hasIstio {
			return wafv1beta1.ProviderIstio, "multiple platforms installed; preferring Istio", true
		}
		return wafv1beta1.ProviderCilium, "multiple platforms installed; preferring Cilium", true
	}
	return "", "", false
}

func apiAvailable(ctx context.Context, c client.Reader, gvk schema.GroupVersionKind) bool {
	list := &unstructured.UnstructuredList{}
	list.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   gvk.Group,
		Version: gvk.Version,
		Kind:    gvk.Kind + "List",
	})
	// Prefer Limit if the reader supports it; otherwise plain List.
	err := c.List(ctx, list, client.Limit(1))
	if err == nil {
		return true
	}
	if meta.IsNoMatchError(err) {
		return false
	}
	// Permission or other transient errors: treat as unavailable for discovery.
	return false
}

func fillCiliumService(ctx context.Context, c client.Reader, waf *wafv1beta1.WAF, res *DiscoveryResult) {
	if res.Provider != wafv1beta1.ProviderCilium {
		return
	}
	// Explicit config wins.
	if p := waf.Spec.Provider; p != nil && p.Cilium != nil {
		if p.Cilium.ServiceName != "" {
			res.CiliumServiceName = p.Cilium.ServiceName
			res.CiliumServiceNamespace = p.Cilium.ServiceNamespace
			if res.CiliumServiceNamespace == "" {
				res.CiliumServiceNamespace = waf.Namespace
			}
			return
		}
	}

	// TargetRef Kind=Service.
	targets := waf.Spec.EffectivePolicyTargets()
	//nolint:staticcheck // SA1019: TargetRef compat
	if tr := targets.TargetRef; tr != nil && tr.Kind == "Service" {
		res.CiliumServiceName = string(tr.Name)
		res.CiliumServiceNamespace = waf.Namespace
		return
	}
	//nolint:staticcheck // SA1019: TargetRef compat
	for _, tr := range targets.TargetRefs {
		if tr.Kind == "Service" {
			res.CiliumServiceName = string(tr.Name)
			res.CiliumServiceNamespace = waf.Namespace
			return
		}
	}

	// HTTPRoute backends for targeted Gateways.
	if name, ns, ok := discoverBackendServiceFromHTTPRoutes(ctx, c, waf); ok {
		res.CiliumServiceName = name
		res.CiliumServiceNamespace = ns
	}
}

func discoverBackendServiceFromHTTPRoutes(ctx context.Context, c client.Reader, waf *wafv1beta1.WAF) (name, ns string, ok bool) {
	gwNames := map[string]struct{}{}
	targets := waf.Spec.EffectivePolicyTargets()
	//nolint:staticcheck // SA1019: TargetRef compat
	if tr := targets.TargetRef; tr != nil && tr.Kind == "Gateway" {
		gwNames[string(tr.Name)] = struct{}{}
	}
	//nolint:staticcheck // SA1019: TargetRef compat
	for _, tr := range targets.TargetRefs {
		if tr.Kind == "Gateway" {
			gwNames[string(tr.Name)] = struct{}{}
		}
	}
	if len(gwNames) == 0 {
		return "", "", false
	}

	var routes gwapiv1.HTTPRouteList
	if err := c.List(ctx, &routes, client.InNamespace(waf.Namespace)); err != nil {
		return "", "", false
	}
	for i := range routes.Items {
		rt := &routes.Items[i]
		if !httpRouteParentsGateway(rt, gwNames, waf.Namespace) {
			continue
		}
		if n, nns, found := firstServiceBackend(rt, waf.Namespace); found {
			return n, nns, true
		}
	}
	return "", "", false
}

func httpRouteParentsGateway(rt *gwapiv1.HTTPRoute, gwNames map[string]struct{}, _ string) bool {
	for _, p := range rt.Spec.ParentRefs {
		kind := "Gateway"
		if p.Kind != nil {
			kind = string(*p.Kind)
		}
		if kind != "Gateway" {
			continue
		}
		if _, ok := gwNames[string(p.Name)]; ok {
			return true
		}
	}
	return false
}

func firstServiceBackend(rt *gwapiv1.HTTPRoute, defaultNS string) (name, ns string, ok bool) {
	for _, rule := range rt.Spec.Rules {
		for _, b := range rule.BackendRefs {
			kind := "Service"
			if b.Kind != nil {
				kind = string(*b.Kind)
			}
			if kind != "Service" {
				continue
			}
			ns = defaultNS
			if b.Namespace != nil && *b.Namespace != "" {
				ns = string(*b.Namespace)
			}
			return string(b.Name), ns, true
		}
	}
	return "", "", false
}

// ApplyDiscovery merges discovery into BuildOptions used by BuildFromWAF.
func ApplyDiscovery(opts *BuildOptions, d DiscoveryResult) {
	if opts == nil {
		return
	}
	opts.DetectedProvider = d.Provider
	opts.DetectedProviderReason = d.Reason
	if d.CiliumServiceName != "" {
		opts.DetectedCiliumServiceName = d.CiliumServiceName
		opts.DetectedCiliumServiceNamespace = d.CiliumServiceNamespace
	}
}
