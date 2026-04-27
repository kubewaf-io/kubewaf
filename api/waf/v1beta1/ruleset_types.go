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

package v1beta1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// +kubebuilder:validation:XValidation:rule="has(self.selector) || has(self.name)",message="name or selector required"
// +kubebuilder:validation:XValidation:rule="!(has(self.selector) && has(self.name))",message="name and selector are mutually exclusive"
type RuleRef struct {
	// Kind specifies the type of resource being referenced.
	// Supported: "SecRule", "SecAction", "RuleSet", "ConfigMap".
	// Note: non-RuleSet owners (e.g. WAFInstance) may ONLY reference "RuleSet"
	// (enforced in internal/references/resolver.go; future webhook planned).
	Kind string `json:"kind,omitempty"`

	// Name is the name of the referenced resource (SecRule/SecAction/RuleSet).
	// +optional
	Name string `json:"name,omitempty"`

	// Namespace of the referenced resource.
	// Defaults to the namespace of the referencing object if omitted.
	// +optional
	Namespace string `json:"namespace,omitempty"`

	Version string `json:"version,omitempty"`

	Group string `json:"group,omitempty"`

	// Selector selects resources by labels. If set, Name is ignored.
	// +optional
	Selector *metav1.LabelSelector `json:"selector,omitempty"`
}

// RuleSetSpec defines the desired state of RuleSet.
// A RuleSet aggregates multiple SecRule and SecAction resources into a cohesive
// WAF policy that can be attached to gateways, ingresses or other resources.
type RuleSetSpec struct {
	// RuleRefs lists the individual security rules and actions to include in this set.
	// At least one of name or selector must be specified.
	// +optional
	RuleRefs []RuleRef `json:"ruleRefs,omitempty"`

	// AllowedRules controls from which namespaces the referenced rules may be selected.
	// +kubebuilder:default={from: Same}
	// +optional
	AllowedRules RuleNamespaces `json:"allowedRules,omitempty"`
}

// RuleNamespaces controls from which namespaces SecRules and SecActions may be
// referenced by this RuleSet. This follows the same pattern as Gateway API's
// namespace selection.
type RuleNamespaces struct {
	// From indicates how to select namespaces for referenced rules.
	// +optional
	// +kubebuilder:default=Same
	// +kubebuilder:validation:Enum=All;Selector;Same
	From *gatewayv1.FromNamespaces `json:"from,omitempty"`

	// Selector must be specified when From is set to "Selector". Only resources
	// in namespaces matching this selector will be allowed.
	// This field is ignored for other values of From.
	//
	// +optional
	Selector *metav1.LabelSelector `json:"selector,omitempty"`
}

// RuleSetStatus defines the observed state of RuleSet.
type RuleSetStatus struct {
	// Conditions represent the current state of the RuleSet resource.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// RuleRefs tracks the status of each referenced rule.
	RuleRefs []RuleRefStatus `json:"ruleRefs,omitempty"`
}

// RuleRefStatus contains the observed status for a referenced rule or action.
type RuleRefStatus struct {
	Kind      string `json:"kind,omitempty"`
	Name      string `json:"name,omitempty"`
	Namespace string `json:"namespace,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// RuleSet is the Schema for the rulesets API
type RuleSet struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the desired state of RuleSet
	// +required
	Spec RuleSetSpec `json:"spec"`

	// status defines the observed state of RuleSet
	// +optional
	Status RuleSetStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// RuleSetList contains a list of RuleSet
type RuleSetList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []RuleSet `json:"items"`
}

func init() {
	SchemeBuilder.Register(&RuleSet{}, &RuleSetList{})
}
