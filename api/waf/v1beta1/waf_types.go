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

// WAFSpec defines the desired state of WAF.
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
//
// CorazaProxyWasmImage allows overriding the Wasm module image (default:
// ghcr.io/corazawaf/coraza-proxy-wasm:0.6.0).
type WAFSpec struct {
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
	// +kubebuilder:default=7
	LogLevel int `json:"logLevel,omitempty"`

	// CorazaProxyWasmImage specifies the OCI image (including tag) for the
	// coraza-proxy-wasm module loaded by Envoy Gateway's Wasm filter.
	// This makes the previously hardcoded ghcr.io/corazawaf/coraza-proxy-wasm:0.6.0
	// fully customizable while preserving the original as default.
	// +optional
	// +kubebuilder:default="ghcr.io/corazawaf/coraza-proxy-wasm:0.6.0"
	CorazaProxyWasmImage string `json:"corazaProxyWasmImage,omitempty"`

	// Metrics configures observability for the Coraza WASM filter.
	// Allows controlling metric names, extra labels on interruption metrics,
	// and whether to include high-cardinality rule_id labels.
	// +optional
	Metrics *WAFMetrics `json:"metrics,omitempty"`
}

// WAFMetrics configures how metrics from the coraza-proxy-wasm filter are emitted.
type WAFMetrics struct {
	// Name sets the logical name / VM ID of the Wasm filter inside Envoy.
	// This influences metric prefixes (e.g. wasm.<name>.*).
	// If unset, the controller uses "kubewaf.io".
	// +optional
	Name *string `json:"name,omitempty"`

	// RootID matches the root_id expected by the Wasm module for stats/context.
	// +optional
	RootID *string `json:"rootID,omitempty"`

	// ExtraLabels are key/value pairs passed to coraza-proxy-wasm.
	// They will be attached to waf_filter_tx_interruptions metrics.
	// Example: { "team": "payments", "env": "prod", "gateway": "external" }
	// +optional
	ExtraLabels map[string]string `json:"extraLabels,omitempty"`

	// IncludeRuleID controls whether the specific `rule_id` label is included
	// on waf_filter_tx_interruptions metrics.
	// Disabling this significantly reduces cardinality in high-traffic environments.
	// Default: true
	// +optional
	// +kubebuilder:default=true
	IncludeRuleID *bool `json:"includeRuleID,omitempty"`

	// EnableStats enables the core WAF metrics (tx total + interruptions).
	// Default: true
	// +optional
	// +kubebuilder:default=true
	EnableStats *bool `json:"enableStats,omitempty"`
}

// WAFStatus defines the observed state of WAF.
// It follows Kubernetes API conventions for status (see
// https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/api-conventions.md#typical-status-properties).
//
// The controller sets standard conditions including:
// - ReferencesResolved: whether all RuleSetRefs were successfully resolved.
// - Ready/Available: overall health of the WAF policy attachment.
type WAFStatus struct {
	// Conditions represent the current state of the WAF resource.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:path=wafs,scope=Namespaced,categories=waf;security;gateway,shortName=waf

// WAF is the Schema for the wafs API
type WAF struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the desired state of WAF.
	// See WAFSpec for details on policy attachment, RuleSet
	// resolution (with CRS support), and logging configuration.
	// +required
	Spec WAFSpec `json:"spec"`

	// status defines the observed state of WAF
	// +optional
	Status WAFStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// WAFList contains a list of WAF
type WAFList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []WAF `json:"items"`
}
