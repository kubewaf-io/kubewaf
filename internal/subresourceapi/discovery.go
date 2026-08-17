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

package subresourceapi

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	subv1alpha1 "github.com/kubewaf-io/kubewaf/api/subresources/v1alpha1"
)

// ProbeSubresourceVerbs are RBAC verbs registered for pass-through methods.
var ProbeSubresourceVerbs = []string{"get", "create", "update", "patch", "delete"}

// GetSubresourceVerbs is the verb set for GET-only WAF subresources.
var GetSubresourceVerbs = []string{"get"}

// DiscoveryFlags controls which aggregated resources are advertised.
type DiscoveryFlags struct {
	Probes     bool
	Directives bool
	Query      bool
}

// DefaultDiscoveryFlags advertises every v1 capability (unit tests / full server).
var DefaultDiscoveryFlags = DiscoveryFlags{Probes: true, Directives: true, Query: true}

// APIGroupDocument returns GET /apis/subresources.kubewaf.io payload.
func APIGroupDocument() *metav1.APIGroup {
	gv := metav1.GroupVersionForDiscovery{
		GroupVersion: subv1alpha1.Group + "/" + subv1alpha1.Version,
		Version:      subv1alpha1.Version,
	}
	return &metav1.APIGroup{
		TypeMeta: metav1.TypeMeta{
			Kind:       "APIGroup",
			APIVersion: "v1",
		},
		Name:             subv1alpha1.Group,
		Versions:         []metav1.GroupVersionForDiscovery{gv},
		PreferredVersion: gv,
	}
}

// APIResourceListDocument returns GET /apis/subresources.kubewaf.io/v1alpha1 payload.
func APIResourceListDocument() *metav1.APIResourceList {
	return APIResourceListDocumentWith(DefaultDiscoveryFlags)
}

// APIResourceListDocumentWith returns discovery for the enabled capabilities.
func APIResourceListDocumentWith(flags DiscoveryFlags) *metav1.APIResourceList {
	// Parent entries exist only so slash-form subresources can be discovered.
	// Keep SingularName empty and never set shortNames so kubectl continues to
	// resolve `ruleset` / `secrule` / `waf` to the CRD groups.
	resources := []metav1.APIResource{
		{
			Name:         subv1alpha1.ResourceSecRules,
			SingularName: "",
			Namespaced:   true,
			Kind:         "SecRuleProbeParent",
			Verbs:        []string{},
		},
		{
			Name:         subv1alpha1.ResourceRuleSets,
			SingularName: "",
			Namespaced:   true,
			Kind:         "RuleSetProbeParent",
			Verbs:        []string{},
		},
		{
			Name:         subv1alpha1.ResourceWAFs,
			SingularName: "",
			Namespaced:   true,
			Kind:         "WAFProbeParent",
			Verbs:        []string{},
		},
	}
	if flags.Probes {
		resources = append(resources,
			metav1.APIResource{
				Name:         subv1alpha1.ResourceSecRuleProbes,
				SingularName: "",
				Namespaced:   true,
				Kind:         "Probe",
				Verbs:        append([]string(nil), ProbeSubresourceVerbs...),
			},
			metav1.APIResource{
				Name:         subv1alpha1.ResourceRuleSetProbes,
				SingularName: "",
				Namespaced:   true,
				Kind:         "Probe",
				Verbs:        append([]string(nil), ProbeSubresourceVerbs...),
			},
			metav1.APIResource{
				Name:         subv1alpha1.ResourceWAFProbes,
				SingularName: "",
				Namespaced:   true,
				Kind:         "Probe",
				Verbs:        append([]string(nil), ProbeSubresourceVerbs...),
			},
		)
	}
	if flags.Directives {
		resources = append(resources, metav1.APIResource{
			Name:         subv1alpha1.ResourceWAFDirectives,
			SingularName: "",
			Namespaced:   true,
			Kind:         "WAFDirectives",
			Verbs:        append([]string(nil), GetSubresourceVerbs...),
		})
	}
	if flags.Query {
		resources = append(resources,
			metav1.APIResource{
				Name:         subv1alpha1.ResourceWAFMetrics,
				SingularName: "",
				Namespaced:   true,
				Kind:         "WAFMetrics",
				Verbs:        append([]string(nil), GetSubresourceVerbs...),
			},
			metav1.APIResource{
				Name:         subv1alpha1.ResourceWAFTraces,
				SingularName: "",
				Namespaced:   true,
				Kind:         "WAFTraces",
				Verbs:        append([]string(nil), GetSubresourceVerbs...),
			},
			metav1.APIResource{
				Name:         subv1alpha1.ResourceClusterMetrics,
				SingularName: "",
				Namespaced:   false,
				Kind:         "WAFClusterMetrics",
				Verbs:        append([]string(nil), GetSubresourceVerbs...),
			},
		)
	}
	return &metav1.APIResourceList{
		TypeMeta: metav1.TypeMeta{
			Kind:       "APIResourceList",
			APIVersion: "v1",
		},
		GroupVersion: subv1alpha1.Group + "/" + subv1alpha1.Version,
		APIResources: resources,
	}
}

// MinimalOpenAPIV2 is a stub OpenAPI 2.0 document for aggregation tooling (K31).
func MinimalOpenAPIV2() map[string]any {
	return map[string]any{
		"swagger": "2.0",
		"info": map[string]any{
			"title":   "subresources.kubewaf.io",
			"version": subv1alpha1.Version,
		},
		"paths": map[string]any{},
	}
}

// MinimalOpenAPIV3 is a best-effort stub for k8s ≥1.32 (K31).
func MinimalOpenAPIV3() map[string]any {
	return map[string]any{
		"openapi": "3.0.0",
		"info": map[string]any{
			"title":   "subresources.kubewaf.io",
			"version": subv1alpha1.Version,
		},
		"paths": map[string]any{},
	}
}
