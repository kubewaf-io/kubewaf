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
// included from the engine (Path A: Include @owasp_crs). Prefer Path B for
// GitOps: crsEnable=false + RuleSet of structured SecRules, with optional
// CRS tuning via spec.crs (paranoia, thresholds, exclusions) without includes.
//
// The WAF engine is ModSecurity (modsecurity-proxy-wasm), loaded from the
// operator image (paths under /wasm, also via KO_DATA_PATH).
type WAFSpec struct {
	// PolicyTargetReferences attaches this WAF to Gateway API resources.
	// Inlined so JSON/YAML expose top-level targetRef / targetRefs — required by
	// Envoy Gateway extensionManager.policyResources (it rejects nested parentRefs).
	// Example:
	//   spec:
	//     targetRef:
	//       group: gateway.networking.k8s.io
	//       kind: Gateway
	//       name: demo-gateway
	envoygatewayv1alpha1.PolicyTargetReferences `json:",inline"`

	// ParentRefs is the legacy nested attachment form (spec.parentRefs.targetRef).
	// Prefer top-level targetRef/targetRefs. When only parentRefs is set,
	// EffectivePolicyTargets() still resolves attachment.
	// +optional
	ParentRefs *envoygatewayv1alpha1.PolicyTargetReferences `json:"parentRefs,omitempty"`

	// Provider selects the data-plane control plane that will receive the filter
	// slot (Envoy Gateway Extension Server, Istio EnvoyFilter, or CiliumEnvoyConfig).
	// When omitted or type=Auto, the operator discovers the provider from the
	// targeted Gateway's GatewayClass.controllerName, then from installed
	// platform CRDs (Envoy Gateway / Istio / Cilium). Status.provider reports
	// the resolved value. Rule/plugin configuration is always pushed over gRPC
	// ECDS regardless of provider.
	// +optional
	Provider *WAFProvider `json:"provider,omitempty"`

	// Challenge optionally installs a Proof-of-Work browser challenge filter
	// (pow-proxy-wasm / challenge-proxy-wasm) *before* the WAF filter in the chain.
	// +optional
	Challenge *ChallengeSpec `json:"challenge,omitempty"`

	// RuleSetRefs references RuleSets (or other RuleSets recursively).
	// Resolution, back-references, and status conditions are handled
	// automatically by the shared RuleRefResolver.
	// +optional
	RuleSetRefs []RuleRef `json:"ruleRefs,omitempty"`

	// CRSEnable enables Path A: load OWASP CRS from the engine via virtual includes
	// (Include @crs-setup-conf + Include @owasp_crs/*.conf).
	// Prefer Path B for kube-native CRS: leave false and attach a RuleSet of
	// structured SecRules (config/samples/crs/, optimized-rulesets). Use spec.crs
	// for paranoia / thresholds / exclusions with either path.
	// +optional
	// +kubebuilder:default=false
	CRSEnable bool `json:"crsEnable,omitempty"`

	// Mode selects blocking vs observe-only engine behaviour.
	// Blocking (default) emits SecRuleEngine On; DetectionOnly emits SecRuleEngine DetectionOnly
	// for safe CRS / rule rollouts without denying traffic.
	// +optional
	// +kubebuilder:default=Blocking
	// +kubebuilder:validation:Enum=Blocking;DetectionOnly
	Mode WAFMode `json:"mode,omitempty"`

	// LogLevel controls verbosity of the Envoy WAF filter logs.
	// Common values: 0=off, 1=error, 2=warn, 3=info, 4=debug (up to 7).
	// Default is 1 (error) so production clusters are not flooded; set higher for debug.
	// +optional
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=7
	// +kubebuilder:default=1
	LogLevel int `json:"logLevel,omitempty"`

	// Metrics configures observability labels for the WAF WASM filter.
	// +optional
	Metrics *WAFMetrics `json:"metrics,omitempty"`

	// Telemetry is opt-in managed observability policy (mode, sample/redact).
	// Published on the ECDS plugin snapshot so Wasm can annotate requests.
	// The OTLP destination is Envoy cluster kubewaf_otel (bootstrap/slot inject),
	// not this field. There is no telemetry.otel client block.
	// +optional
	Telemetry *WAFTelemetry `json:"telemetry,omitempty"`

	// Block configures client-visible deny local-replies (ModSecurity engine).
	// Defaults are product-neutral: message "Forbidden", marker header "x-blocked".
	// Enable addRequestIDHeader to echo the request id on deny responses.
	// +optional
	Block *WAFBlock `json:"block,omitempty"`

	// CRS contains declarative tuning knobs for the OWASP Core Rule Set
	// (paranoia levels, anomaly thresholds, remove-by-id/tag, update-target).
	// Applies with either Path A (crsEnable) or Path B (structured RuleSets only).
	// Setup setvars are emitted before CRS/user rules; exclusions after the
	// engine include (Path A) or after RuleSet SecLang (Path B).
	// +optional
	CRS *CRSTuning `json:"crs,omitempty"`

	// PhraseListPolicy controls publish behavior when a custom @pmFromFile /
	// @ipMatchFromFile basename cannot be resolved to a Ready PhraseList or
	// IPList in the WAF namespace. Data-files injection is always enabled.
	// +optional
	// +kubebuilder:default=FailClosed
	// +kubebuilder:validation:Enum=FailClosed;IgnoreUnknown
	PhraseListPolicy PhraseListPolicy `json:"phraseListPolicy,omitempty"`
}

// PhraseListPolicy controls missing custom PhraseList/IPList handling on ModSecurity Path B.
// +kubebuilder:validation:Enum=FailClosed;IgnoreUnknown
type PhraseListPolicy string

const (
	// PhraseListPolicyFailClosed refuses ECDS publish when a custom list is missing.
	PhraseListPolicyFailClosed PhraseListPolicy = "FailClosed"
	// PhraseListPolicyIgnoreUnknown drops SecLang lines for unresolved custom basenames.
	PhraseListPolicyIgnoreUnknown PhraseListPolicy = "IgnoreUnknown"
)

// EffectivePolicyTargets returns the Gateway API attachment targets for this WAF.
// Prefers inlined targetRef/targetRefs (EG-compatible); falls back to legacy parentRefs.
func (s *WAFSpec) EffectivePolicyTargets() envoygatewayv1alpha1.PolicyTargetReferences {
	if s == nil {
		return envoygatewayv1alpha1.PolicyTargetReferences{}
	}
	//nolint:staticcheck // SA1019: TargetRef retained for Gateway API / EG compatibility
	if s.TargetRef != nil || len(s.TargetRefs) > 0 {
		return s.PolicyTargetReferences
	}
	if s.ParentRefs != nil {
		return *s.ParentRefs
	}
	return s.PolicyTargetReferences
}

// EngineType identifies the WAF Proxy-Wasm implementation.
type EngineType string

const (
	// EngineModSecurity is the ModSecurity proxy-wasm filter
	// (modsecurity-proxy-wasm in this monorepo).
	EngineModSecurity EngineType = "ModSecurity"
)

// WAFMode controls SecRuleEngine (blocking vs detection-only).
// +kubebuilder:validation:Enum=Blocking;DetectionOnly
type WAFMode string

const (
	// WAFModeBlocking denies requests when rules interrupt (SecRuleEngine On).
	WAFModeBlocking WAFMode = "Blocking"
	// WAFModeDetectionOnly logs / scores only (SecRuleEngine DetectionOnly).
	WAFModeDetectionOnly WAFMode = "DetectionOnly"
)

// ChallengeSpec configures the optional pow-proxy-wasm challenge filter.
//
// By default the operator generates and manages a Kubernetes Secret holding the
// HMAC key (stable across reconciles, owned by the WAF). You do not need to set
// Secret or SecretRef unless you want to bring your own key.
type ChallengeSpec struct {
	// Enabled installs the challenge filter when true.
	// +optional
	// +kubebuilder:default=true
	Enabled *bool `json:"enabled,omitempty"`

	// Secret is an optional plaintext HMAC override (dev / break-glass).
	// When empty, the operator uses SecretRef or auto-generates a managed Secret.
	// +optional
	Secret string `json:"secret,omitempty"`

	// SecretRef optionally references a user-managed Secret key for the HMAC.
	// When set (and Secret is empty), that key is used instead of the
	// operator-managed Secret.
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
	// ProviderAuto discovers the data plane (GatewayClass / installed CRDs).
	// Falls back to EnvoyGateway when nothing is detected.
	ProviderAuto ProviderType = "Auto"
	// ProviderEnvoyGateway uses the EG Extension Server to inject ECDS slots.
	ProviderEnvoyGateway ProviderType = "EnvoyGateway"
	// ProviderIstio uses an EnvoyFilter to inject ECDS slots.
	ProviderIstio ProviderType = "Istio"
	// ProviderCilium uses a CiliumEnvoyConfig to inject ECDS slots.
	ProviderCilium ProviderType = "Cilium"
)

// WAFProvider configures which control plane installs the filter slot.
type WAFProvider struct {
	// Type selects EnvoyGateway, Istio, Cilium, or Auto.
	// Auto (default when omitted) discovers from GatewayClass.controllerName
	// of targeted Gateways, then from installed CRDs.
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

// WAFBlock configures client-visible deny local-replies for the WAF engine
// (currently honored by ModSecurity / modsecurity-proxy-wasm).
//
// The operator maps these fields into the engine plugin JSON `block` object:
//   - Message → block.message
//   - AddBlockedHeader / BlockedHeader → block.blocked_header
//   - AddRequestIDHeader / RequestIDHeader → block.add_request_id_header / block.request_id_header
//
// Client-facing values stay product-neutral by default (no vendor names).
type WAFBlock struct {
	// Message is the local-reply details string shown to clients on deny.
	// Default: "Forbidden"
	// +optional
	// +kubebuilder:default="Forbidden"
	Message string `json:"message,omitempty"`

	// AddBlockedHeader controls whether deny responses include a blocked marker header.
	// Default: true
	// +optional
	// +kubebuilder:default=true
	AddBlockedHeader *bool `json:"addBlockedHeader,omitempty"`

	// BlockedHeader is the name of the blocked marker header on deny responses.
	// Default: "x-blocked". Only applied when AddBlockedHeader is true.
	// Set AddBlockedHeader to false to omit the header entirely.
	// +optional
	// +kubebuilder:default="x-blocked"
	// +kubebuilder:validation:MaxLength=256
	// +kubebuilder:validation:Pattern=`^[A-Za-z0-9!#$%&'*+.^_|~-]+$`
	BlockedHeader string `json:"blockedHeader,omitempty"`

	// AddRequestIDHeader controls whether deny responses include the correlated request id.
	// Default: false
	// +optional
	// +kubebuilder:default=false
	AddRequestIDHeader *bool `json:"addRequestIDHeader,omitempty"`

	// RequestIDHeader is the response header name for the request id on deny responses.
	// Default: "x-request-id". Only applied when AddRequestIDHeader is true.
	// +optional
	// +kubebuilder:default="x-request-id"
	// +kubebuilder:validation:MaxLength=256
	// +kubebuilder:validation:Pattern=`^[A-Za-z0-9!#$%&'*+.^_|~-]+$`
	RequestIDHeader string `json:"requestIDHeader,omitempty"`
}

// WAFMetrics configures observability for the WAF Proxy-Wasm filter
// (modsecurity-proxy-wasm or coraza-proxy-wasm).
//
// The operator maps these fields into the engine plugin JSON:
//   - ExtraLabels → extra metric_labels (reserved identity keys written after)
//   - IncludeRuleID → metrics.per_rule_id / metrics_per_rule_id
//   - EnableStats → metrics.enabled
type WAFMetrics struct {
	// Name sets the logical name / VM ID of the Wasm filter inside Envoy.
	// This influences metric prefixes (e.g. wasm.<name>.*).
	// If unset, the controller uses the engine default (e.g. kubewaf.modsecurity).
	// +optional
	Name *string `json:"name,omitempty"`

	// RootID matches the root_id expected by the Wasm module for stats/context.
	// +optional
	RootID *string `json:"rootID,omitempty"`

	// ExtraLabels are additional name-embedding keys on WAF filter metrics
	// (modsecurity_proxy_wasm.* / kubewaf_waf.*).
	// ExtraLabels are copied first; reserved identity keys (waf_namespace,
	// waf_name, engine, owner) are written after and collisions are dropped.
	// Example: { "team": "payments", "env": "prod", "gateway": "external" }
	// +optional
	ExtraLabels map[string]string `json:"extraLabels,omitempty"`

	// IncludeRuleID controls whether per-rule_id series are emitted
	// (tx interruptions and rule matches). Disabling reduces cardinality.
	// Default: true
	// +optional
	// +kubebuilder:default=true
	IncludeRuleID *bool `json:"includeRuleID,omitempty"`

	// EnableStats enables the core WAF ABI metrics (tx total, allowed, interruptions,
	// rule matches). Default: true.
	// When false the managed catalog has no series for this WAF; traces can still
	// export when telemetry.mode=Managed.
	// +optional
	// +kubebuilder:default=true
	EnableStats *bool `json:"enableStats,omitempty"`
}

// TelemetryMode selects whether this WAF annotates requests for managed export.
// +kubebuilder:validation:Enum=None;Managed
type TelemetryMode string

const (
	// TelemetryModeNone is the default: Wasm does not set export metadata.
	TelemetryModeNone TelemetryMode = "None"
	// TelemetryModeManaged annotates sampled requests so Envoy OTel access logs fire.
	TelemetryModeManaged TelemetryMode = "Managed"
)

// WAFTelemetry is policy-only (mode, sample/redact). It does not configure an
// OTLP client; Envoy exporters target cluster kubewaf_otel.
type WAFTelemetry struct {
	// Mode is None (default) or Managed.
	// +optional
	// +kubebuilder:default=None
	// +kubebuilder:validation:Enum=None;Managed
	Mode TelemetryMode `json:"mode,omitempty"`

	// Traces is the security-trace sampling and redact policy.
	// +optional
	Traces *WAFTelemetryTraces `json:"traces,omitempty"`
}

// WAFTelemetryTraces controls Wasm annotation of security traces.
type WAFTelemetryTraces struct {
	// Enabled exports security traces when Mode is Managed.
	// When unset, Helm profile defaults apply (lite=false, full=true).
	// +optional
	Enabled *bool `json:"enabled,omitempty"`

	// SampleRate is the sample probability for non-disruptive matches (0.0–1.0).
	// +optional
	// +kubebuilder:validation:Pattern=`^(0(\.[0-9]+)?|1(\.0+)?)$`
	SampleRate string `json:"sampleRate,omitempty"`

	// SampleDisruptive is the sample probability for interrupts (default 1.0).
	// +optional
	// +kubebuilder:validation:Pattern=`^(0(\.[0-9]+)?|1(\.0+)?)$`
	SampleDisruptive string `json:"sampleDisruptive,omitempty"`

	// Redact omits client.address from export metadata. Default true.
	// +optional
	Redact *bool `json:"redact,omitempty"`

	// IncludeMatchData includes waf.match.data on the span. Default false.
	// +optional
	IncludeMatchData *bool `json:"includeMatchData,omitempty"`
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
	// Always set on Ready: either from Auto discovery or from explicit spec.provider.type.
	// +optional
	Provider ProviderType `json:"provider,omitempty"`

	// ProviderDetection explains how status.provider was chosen.
	// For Auto/empty spec.provider this is the discovery chain, e.g.
	//   targetRef Gateway demo/gw → GatewayClass "cilium" → controller "io.cilium/gateway-controller"
	// When the user set provider.type explicitly: "explicit (spec.provider.type)".
	// +optional
	ProviderDetection string `json:"providerDetection,omitempty"`

	// Engine is the WAF Proxy-Wasm implementation (ModSecurity).
	// +optional
	Engine EngineType `json:"engine,omitempty"`

	// Mode is the effective rule engine mode (Blocking or DetectionOnly).
	// +optional
	Mode WAFMode `json:"mode,omitempty"`

	// ChallengeEnabled reports whether the PoW challenge filter is installed.
	// +optional
	ChallengeEnabled bool `json:"challengeEnabled,omitempty"`

	// ChallengeSecretName is the Kubernetes Secret used for the challenge HMAC
	// (operator-managed name, or the SecretRef name when configured).
	// +optional
	ChallengeSecretName string `json:"challengeSecretName,omitempty"`

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

	// RulesLoaded is the number of SecRule objects resolved into this WAF.
	// +optional
	RulesLoaded int32 `json:"rulesLoaded,omitempty"`

	// ActionsLoaded is the number of SecAction objects resolved into this WAF.
	// +optional
	ActionsLoaded int32 `json:"actionsLoaded,omitempty"`

	// DirectivesCount is the number of SecLang directive lines pushed over ECDS
	// (engine setup + includes + user rules).
	// +optional
	DirectivesCount int32 `json:"directivesCount,omitempty"`

	// RenderedDirectives is the SecLang config last published to the data plane.
	// Large payloads are truncated (see RenderedDirectivesTruncated).
	// +optional
	RenderedDirectives string `json:"renderedDirectives,omitempty"`

	// RenderedDirectivesTruncated is true when RenderedDirectives was size-capped.
	// +optional
	RenderedDirectivesTruncated bool `json:"renderedDirectivesTruncated,omitempty"`

	// DataFilesCount is the number of basenames injected into plugin data_files.
	// +optional
	DataFilesCount int32 `json:"dataFilesCount,omitempty"`

	// DataFilesRawBytes is the total uncompressed injected body size.
	// +optional
	DataFilesRawBytes int64 `json:"dataFilesRawBytes,omitempty"`

	// DataFilesContentHash is sha256 over sorted "basename\0body" pairs.
	// +optional
	DataFilesContentHash string `json:"dataFilesContentHash,omitempty"`

	// RuleRefs is a capped leaf list of SecRule/SecAction membership after Resolve
	// (selectors are expanded). Max 256 leaves.
	// +optional
	RuleRefs []RuleRefStatus `json:"ruleRefs,omitempty"`

	// RuleRefsTruncated is true when RuleRefs omitted some resolved leaves.
	// +optional
	RuleRefsTruncated bool `json:"ruleRefsTruncated,omitempty"`

	// RuleRefsOmitted is the count of resolved leaves not written to RuleRefs.
	// +optional
	RuleRefsOmitted int32 `json:"ruleRefsOmitted,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:path=wafs,scope=Namespaced,categories=waf;security;gateway,shortName=waf
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Provider",type=string,JSONPath=`.status.provider`
// +kubebuilder:printcolumn:name="Engine",type=string,JSONPath=`.status.engine`
// +kubebuilder:printcolumn:name="Mode",type=string,JSONPath=`.status.mode`
// +kubebuilder:printcolumn:name="Rules",type=integer,JSONPath=`.status.rulesLoaded`
// +kubebuilder:printcolumn:name="CRS",type=boolean,JSONPath=`.spec.crsEnable`
// +kubebuilder:printcolumn:name="Telemetry",type=string,JSONPath=`.spec.telemetry.mode`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

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
