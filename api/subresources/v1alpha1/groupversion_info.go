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

// Package v1alpha1 holds Probe result types for the aggregated
// subresources.kubewaf.io API group. These types are response-shaped only;
// there is no user-facing ProbeSpec request envelope (pass-through HTTP is K32).
//
// +kubebuilder:object:generate=true
// +groupName=subresources.kubewaf.io
package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

const (
	// Group is the aggregated API group for object-scoped capabilities.
	Group = "subresources.kubewaf.io"
	// Version is the API version for probe result types.
	Version = "v1alpha1"

	// Discovery / RBAC names (slash form = subresource).
	ResourceSecRules       = "secrules"
	ResourceSecRuleProbes  = "secrules/probes"
	ResourceRuleSets       = "rulesets"
	ResourceRuleSetProbes  = "rulesets/probes"
	ResourceWAFs           = "wafs"
	ResourceWAFProbes      = "wafs/probes"
	ResourceWAFDirectives  = "wafs/directives"
	ResourceWAFMetrics     = "wafs/metrics"
	ResourceWAFTraces      = "wafs/traces"
	ResourceClusterMetrics = "clustermetrics"
)

var (
	// GroupVersion is group version used to register these objects.
	GroupVersion = schema.GroupVersion{Group: Group, Version: Version}

	// SchemeBuilder is used to add go types to the GroupVersionKind scheme.
	SchemeBuilder = runtime.NewSchemeBuilder(addKnownTypes)

	// AddToScheme adds the types in this group-version to the given scheme.
	AddToScheme = SchemeBuilder.AddToScheme
)

func addKnownTypes(scheme *runtime.Scheme) error {
	scheme.AddKnownTypes(GroupVersion,
		&Probe{},
	)
	metav1.AddToGroupVersion(scheme, GroupVersion)
	return nil
}
