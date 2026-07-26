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
//
// +kubebuilder:validation:XValidation:rule="!has(self.crs) || self.crsEnable",message="crs tuning requires crsEnable=true"
type WAFSpec struct {
	// ParentRefs specifies the target resources (typically Gateways or
	// GatewayClasses) to which this WAF policy should be attached.
	// Follows Envoy Gateway policy attachment semantics (targetRef/targetRefs).
	// +optional
	ParentRefs envoygatewayv1alpha1.PolicyTargetReferences `json:"parentRefs,omitempty"`

	// Provider selects the data-plane control plane that will receive the ECDS
	// filter slot (Envoy Gateway Extension Server hooks, or Istio EnvoyFilter).
	// Rule/plugin configuration is always pushed over gRPC ECDS regardless of provider.
	// +optional
	Provider *WAFProvider `json:"provider,omitempty"`

	// Engine selects the Proxy-Wasm WAF implementation that evaluates SecLang rules.
	// Coraza (default) uses coraza-proxy-wasm; ModSecurity uses the in-tree
	// modsecurity-proxy-wasm module (embedded CRS, same directives_map JSON shape).
	// +optional
	// +kubebuilder:default=Coraza
	// +kubebuilder:validation:Enum=Coraza;ModSecurity
	Engine EngineType `json:"engine,omitempty"`

	// Challenge optionally installs a Proof-of-Work browser challenge filter
	// (pow-proxy-wasm / challenge-proxy-wasm) *before* the WAF filter in the chain.
	// +optional
	Challenge *ChallengeSpec `json:"challenge,omitempty"`

	// RuleSetRefs references RuleSets (or other RuleSets recursively).
	// Resolution, back-references, and status conditions are handled
	// automatically by the shared RuleRefResolver.
	// +optional
	RuleSetRefs []RuleRef `json:"ruleRefs,omitempty"`

	// CRSEnable enables the OWASP Core Rule Set (v4.x recommended).
	// When true, CRS rules are merged with those from RuleSetRefs.
	// For engine=ModSecurity, CRS is embedded in the wasm binary and loaded via
	// virtual includes (Include @owasp_crs/*.conf).
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

	// WasmHTTP is the HTTP(S) URL where Envoy fetches the WAF engine .wasm binary.
	// When empty, the operator default for the selected engine is used
	// (typically the operator-hosted multi-module wasm server).
	// +optional
	WasmHTTP string `json:"wasmHTTP,omitempty"`

	// WasmSHA256 is the expected SHA-256 of the WAF engine .wasm binary.
	// +optional
	WasmSHA256 string `json:"wasmSHA256,omitempty"`

	// WasmImage is an optional OCI image reference for documentation / future fetchers.
	// +optional
	WasmImage string `json:"wasmImage,omitempty"`

	// CorazaProxyWasmImage is deprecated: use engine=Coraza + wasmImage.
	// Kept for backward compatibility.
	// +optional
	// +kubebuilder:default="ghcr.io/corazawaf/coraza-proxy-wasm:0.6.0"
	CorazaProxyWasmImage string `json:"corazaProxyWasmImage,omitempty"`

	// CorazaProxyWasmHTTP is deprecated: use wasmHTTP (or engine defaults).
	// +optional
	CorazaProxyWasmHTTP string `json:"corazaProxyWasmHTTP,omitempty"`

	// CorazaProxyWasmSHA256 is deprecated: use wasmSHA256.
	// +optional
	CorazaProxyWasmSHA256 string `json:"corazaProxyWasmSHA256,omitempty"`

	// Metrics configures observability labels for the WAF WASM filter.
	// +optional
	Metrics *WAFMetrics `json:"metrics,omitempty"`

	// CRS contains declarative tuning knobs for the OWASP Core Rule Set.
	// Only has effect when CRSEnable is true.
	// +optional
	CRS *CRSTuning `json:"crs,omitempty"`
}

// EngineType selects the Proxy-Wasm WAF implementation.
// +kubebuilder:validation:Enum=Coraza;ModSecurity
type EngineType string

const (
	// EngineCoraza is the default Go-based Coraza proxy-wasm filter.
	EngineCoraza EngineType = "Coraza"
	// EngineModSecurity is the C++ ModSecurity proxy-wasm filter
	// (modsecurity-proxy-wasm in this monorepo).
	EngineModSecurity EngineType = "ModSecurity"
)

// ChallengeSpec configures the optional pow-proxy-wasm challenge filter.
type ChallengeSpec struct {
	// Enabled installs the challenge filter when true.
	// +optional
	// +kubebuilder:default=true
	Enabled *bool `json:"enabled,omitempty"`

	// Secret is the HMAC secret shared across all Envoy replicas (required in production).
	// Prefer referencing a Secret key via SecretRef when available; plaintext is supported for dev.
	// +optional
	Secret string `json:"secret,omitempty"`

	// SecretRef references a Kubernetes Secret key holding the HMAC secret.
	// +optional
	SecretRef *SecretKeyRef `json:"secretRef,omitempty"`

	// BaseDifficulty is the default PoW difficulty (leading zero bits). Default 18.
	// +optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=32
	// +kubebuilder:default=18
	BaseDifficulty *int `json:"baseDifficulty,omitempty"`

	// MinDifficulty lower bound for adaptive difficulty.
	// +optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=32
	MinDifficulty *int `json:"minDifficulty,omitempty"`

	// MaxDifficulty upper bound for adaptive difficulty.
	// +optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=32
	MaxDifficulty *int `json:"maxDifficulty,omitempty"`

	// Header is an optional response header name to inject after pass.
	// +optional
	Header string `json:"header,omitempty"`

	// HeaderValue is the value for Header.
	// +optional
	HeaderValue string `json:"headerValue,omitempty"`

	// WasmHTTP overrides the challenge module download URL.
	// +optional
	WasmHTTP string `json:"wasmHTTP,omitempty"`

	// WasmSHA256 pins the challenge module binary.
	// +optional
	WasmSHA256 string `json:"wasmSHA256,omitempty"`
}

// SecretKeyRef points at a key in a Secret in the same namespace as the WAF.
type SecretKeyRef struct {
	// Name of the Secret.
	// +kubebuilder:validation:Required
	Name string `json:"name"`
	// Key within the Secret data map.
	// +kubebuilder:validation:Required
	Key string `json:"key"`
}

// ProviderType identifies a data-plane control plane.
// +kubebuilder:validation:Enum=Auto;EnvoyGateway;Istio;Cilium
type ProviderType string

const (
	// ProviderAuto defaults to EnvoyGateway (auto-detection may improve later).
	ProviderAuto ProviderType = "Auto"
	// ProviderEnvoyGateway uses the EG Extension Server to inject ECDS slots.
	ProviderEnvoyGateway ProviderType = "EnvoyGateway"
	// ProviderIstio uses an EnvoyFilter to inject ECDS slots.
	ProviderIstio ProviderType = "Istio"
	// ProviderCilium uses a CiliumEnvoyConfig to inject ECDS slots.
	ProviderCilium ProviderType = "Cilium"
)

// WAFProvider configures which control plane installs the ECDS filter slot.
type WAFProvider struct {
	// Type selects EnvoyGateway, Istio, Cilium, or Auto (default EnvoyGateway).
	// +optional
	// +kubebuilder:default=Auto
	Type ProviderType `json:"type,omitempty"`

	// ECDSCluster is the Envoy cluster name used to open the ECDS gRPC stream.
	// +optional
	// +kubebuilder:default=kubewaf_ecds
	ECDSCluster string `json:"ecdsCluster,omitempty"`

	// ECDSService is host:port of the kubeWAF ECDS gRPC Service
	// (e.g. kubewaf-ecds.kubewaf-system.svc.cluster.local:18001).
	// +optional
	ECDSService string `json:"ecdsService,omitempty"`

	// Istio holds Istio-specific slot settings (only used when Type=Istio).
	// +optional
	Istio *IstioProvider `json:"istio,omitempty"`

	// Cilium holds Cilium-specific slot settings (only used when Type=Cilium).
	// +optional
	Cilium *CiliumProvider `json:"cilium,omitempty"`
}

// IstioProvider configures the EnvoyFilter workload selector / context.
type IstioProvider struct {
	// WorkloadSelector labels for the EnvoyFilter (default: istio=ingressgateway).
	// +optional
	WorkloadSelector map[string]string `json:"workloadSelector,omitempty"`

	// Context is the Istio EnvoyFilter match context (GATEWAY, SIDECAR_INBOUND, ...).
	// +optional
	// +kubebuilder:default=GATEWAY
	Context string `json:"context,omitempty"`
}

// CiliumProvider configures the CiliumEnvoyConfig service attachment.
type CiliumProvider struct {
	// ServiceName is the Kubernetes Service the CEC attaches to (same namespace as the WAF
	// unless ServiceNamespace is set). When empty, falls back to the WAF name.
	// +optional
	ServiceName string `json:"serviceName,omitempty"`

	// ServiceNamespace defaults to the WAF namespace.
	// +optional
	ServiceNamespace string `json:"serviceNamespace,omitempty"`
}

// CRSTuning holds declarative overrides for OWASP CRS behavior.
// These map 1:1 onto CRS tx.* variables (via a single early SecAction)
// and the standard removal / target-update directives.
// See IDEAS.md §4 for the detailed PoC rationale and ordering constraints.
type CRSTuning struct {
	// ParanoiaLevel sets both tx.detection_paranoia_level and
	// tx.blocking_paranoia_level (values 1-4).
	// Higher levels activate more rules (including many PL2/PL3/PL4 rules)
	// at the cost of increased false positive risk.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=4
	// +optional
	ParanoiaLevel *int `json:"paranoiaLevel,omitempty"`

	// InboundAnomalyThreshold overrides tx.inbound_anomaly_score_threshold.
	// Requests whose accumulated anomaly score meets or exceeds this value
	// are blocked (when SecRuleEngine is On).
	// +kubebuilder:validation:Minimum=0
	// +optional
	InboundAnomalyThreshold *int `json:"inboundAnomalyThreshold,omitempty"`

	// OutboundAnomalyThreshold overrides tx.outbound_anomaly_score_threshold.
	// +optional
	OutboundAnomalyThreshold *int `json:"outboundAnomalyThreshold,omitempty"`

	// RemoveByID emits SecRuleRemoveById for each listed CRS rule ID.
	// The rules are dropped entirely for this WAF attachment.
	// +optional
	RemoveByID []int `json:"removeById,omitempty"`

	// RemoveByTag emits SecRuleRemoveByTag for each listed tag.
	// Example tag: "attack-sqli".
	// +optional
	RemoveByTag []string `json:"removeByTag,omitempty"`

	// UpdateTargetByID emits SecRuleUpdateTargetById directives.
	// This keeps the rule but removes specific variables from its inspection
	// (the classic surgical false-positive exclusion).
	// +optional
	UpdateTargetByID []TargetExclusion `json:"updateTargetById,omitempty"`
}

// TargetExclusion represents a single SecRuleUpdateTargetById tuning operation.
type TargetExclusion struct {
	// ID is the numeric CRS rule identifier to modify (e.g. 942100).
	// +kubebuilder:validation:Required
	ID int `json:"id"`

	// RemoveTargets are the variable specifications to remove.
	// Examples: "ARGS:csrf_token", "REQUEST_COOKIES:sessionid", "ARGS_GET".
	// Each will be prefixed with "!" in the generated directive.
	// +kubebuilder:validation:MinItems=1
	RemoveTargets []string `json:"removeTargets"`
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

	// Provider is the resolved data-plane provider (EnvoyGateway, Istio, or Cilium).
	// +optional
	Provider ProviderType `json:"provider,omitempty"`

	// Engine is the resolved WAF Proxy-Wasm implementation (Coraza or ModSecurity).
	// +optional
	Engine EngineType `json:"engine,omitempty"`

	// ChallengeEnabled reports whether the PoW challenge filter is installed.
	// +optional
	ChallengeEnabled bool `json:"challengeEnabled,omitempty"`

	// ECDSResourceName is the primary WAF ECDS extension config name.
	// +optional
	ECDSResourceName string `json:"ecdsResourceName,omitempty"`

	// ECDSVersion is the snapshot version counter last published for this WAF.
	// +optional
	ECDSVersion uint64 `json:"ecdsVersion,omitempty"`

	// SlotKind is the platform slot resource kind (e.g. EnvoyFilter, or
	// "ExtensionServer" when EG hooks own the slot).
	// +optional
	SlotKind string `json:"slotKind,omitempty"`

	// SlotName is the platform slot resource name when one is created.
	// +optional
	SlotName string `json:"slotName,omitempty"`
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
