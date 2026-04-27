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
	envoygatewayv1alpha1 "github.com/envoyproxy/gateway/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// WAFEnvoyGatewaySpec defines the desired state of WAFEnvoyGateway.
// It attaches WAF policies (via RuleSets) to Envoy Gateway using the
// Gateway API policy attachment mechanism (PolicyTargetReferences).
//
// RuleSetRefs are resolved using the shared internal/references2.RuleRefResolver
// (recursive flattening of RuleSets, namespace policies via RuleNamespaces,
// automatic back-references via finalizers + status.RuleSetRefs on SecLang
// targets, ReferencesResolved condition). Direct SecRule/SecAction references
// from non-RuleSet owners are disallowed.
//
// When CRSEnable=true, the OWASP Core Rule Set (CRS) is automatically
// included alongside user RuleSets.
type WAFEnvoyGatewaySpec struct {
	// ParentRefs specifies the target resources (typically Gateways or
	// GatewayClasses) to which this WAF policy should be attached.
	// Follows Envoy Gateway policy attachment semantics.
	// +optional
	ParentRefs envoygatewayv1alpha1.PolicyTargetReferences `json:"parentRefs,omitempty"`

	// RuleSetRefs references RuleSets (or other RuleSets recursively).
	// Resolution, back-references, and status conditions are handled
	// automatically by the shared RuleRefResolver.
	// +optional
	RuleSetRefs []RuleRef `json:"ruleRefs,omitempty"`

	// CRSEnable enables the OWASP Core Rule Set (v4.x recommended).
	// When true, CRS rules are merged with those from RuleSetRefs.
	// +optional
	// +kubebuilder:default=false
	CRSEnable bool `json:"crsEnable,omitempty"`

	// LogLevel controls verbosity of the Envoy WAF filter logs.
	// Common values: 0=off, 1=error, 2=warn, 3=info, 4=debug (up to 7).
	// +optional
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=7
	// +kubebuilder:default=2
	LogLevel int `json:"logLevel,omitempty"`
}

// WAFEnvoyGatewayStatus defines the observed state of WAFEnvoyGateway.
// It follows Kubernetes API conventions for status (see
// https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/api-conventions.md#typical-status-properties).
//
// The controller sets standard conditions including:
// - ReferencesResolved: whether all RuleSetRefs were successfully resolved.
// - Ready/Available: overall health of the WAF policy attachment.
type WAFEnvoyGatewayStatus struct {
	// Conditions represent the current state of the WAFEnvoyGateway resource.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:path=wafenvoygateways,scope=Namespaced,categories=waf;security;gateway,shortName=wafeg

// WAFEnvoyGateway is the Schema for the wafenvoygateways API
type WAFEnvoyGateway struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the desired state of WAFEnvoyGateway.
	// See WAFEnvoyGatewaySpec for details on policy attachment, RuleSet
	// resolution (with CRS support), and logging configuration.
	// +required
	Spec WAFEnvoyGatewaySpec `json:"spec"`

	// status defines the observed state of WAFEnvoyGateway
	// +optional
	Status WAFEnvoyGatewayStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// WAFEnvoyGatewayList contains a list of WAFEnvoyGateway
type WAFEnvoyGatewayList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []WAFEnvoyGateway `json:"items"`
}

func init() {
	SchemeBuilder.Register(&WAFEnvoyGateway{}, &WAFEnvoyGatewayList{})
}
