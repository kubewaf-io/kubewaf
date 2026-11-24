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

package v1alpha1

import (
	seclangv1alpha1 "github.com/kubewaf-io/kubewaf/api/seclang/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// Protection attaches the embedded CRS, optional custom rules, and a local
// rate limit to a Gateway or HTTPRoute. It does not create SecRule objects.
// The controller compiles a SecLang bundle and calls the same provider as SecPolicy.
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:path=protections,scope=Namespaced,shortName=prot,categories=waf;security
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Mode",type=string,JSONPath=`.spec.mode`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
// +kubebuilder:validation:XValidation:rule="self.spec.targetRefs.all(t, t.group == 'gateway.networking.k8s.io' && t.kind in ['Gateway', 'HTTPRoute'])",message="targetRefs must be a Gateway or HTTPRoute in gateway.networking.k8s.io"
// +kubebuilder:validation:XValidation:rule="!has(self.spec.customRules) || self.spec.customRules.all(r, (has(r.name) && size(r.name) > 0 && !has(r.selector)) || ((!has(r.name) || size(r.name) == 0) && has(r.selector)))",message="each custom rule selector sets name or selector, not both"
// +kubebuilder:validation:XValidation:rule="!has(self.spec.rateLimit) || self.spec.rateLimit.all(r, r.targetRef.group == 'gateway.networking.k8s.io' && r.targetRef.kind == 'HTTPRoute')",message="rateLimit targetRef must be an HTTPRoute"
type Protection struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ProtectionSpec   `json:"spec"`
	Status ProtectionStatus `json:"status,omitempty"`
}

// ProtectionSpec is the developer-facing attachment.
type ProtectionSpec struct {
	// TargetRefs attach to a Gateway or an HTTPRoute in this namespace.
	// An HTTPRoute Protection overrides a Gateway Protection for that route.
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=16
	TargetRefs []gatewayv1.LocalPolicyTargetReference `json:"targetRefs"`

	// Mode maps to SecRuleEngine. Blocking is On. DetectionOnly does not deny.
	// +optional
	// +kubebuilder:default=Blocking
	// +kubebuilder:validation:Enum=Blocking;DetectionOnly
	Mode string `json:"mode,omitempty"`

	// Inspection maps to the Coraza module mode.
	// +optional
	// +kubebuilder:default=RequestOnly
	// +kubebuilder:validation:Enum=RequestOnly;Full
	Inspection string `json:"inspection,omitempty"`

	// RequestBodyAccess emits SecRequestBodyAccess.
	// +optional
	// +kubebuilder:default=true
	RequestBodyAccess *bool `json:"requestBodyAccess,omitempty"`

	// ResponseBodyAccess emits SecResponseBodyAccess.
	// +optional
	// +kubebuilder:default=false
	ResponseBodyAccess *bool `json:"responseBodyAccess,omitempty"`

	// CRS tunes the embedded ruleset. The two CRS includes are always emitted.
	// A Protection that does not want CRS is a SecPolicy.
	// +optional
	CRS *CRSSpec `json:"crs,omitempty"`

	// CustomRules selects SecRule, SecAction, and Include objects in this namespace.
	// They are appended after the CRS include.
	// +optional
	// +kubebuilder:validation:MaxItems=64
	CustomRules []seclangv1alpha1.RuleSelector `json:"customRules,omitempty"`

	// PostDirectives are extra SecLang lines after the generated exclusions.
	// +optional
	// +kubebuilder:validation:MaxItems=64
	PostDirectives []string `json:"postDirectives,omitempty"`

	// RateLimit creates one local Envoy Gateway BackendTrafficPolicy per entry.
	// It is not a SecLang collection. Deleting the Protection deletes those policies.
	// +optional
	// +kubebuilder:validation:MaxItems=16
	RateLimit []RateLimit `json:"rateLimit,omitempty"`

	// ModuleName is the dynamicModules[].name the platform registered.
	// +optional
	// +kubebuilder:default=composer
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$`
	ModuleName string `json:"moduleName,omitempty"`
}

// CRSSpec is the phase-2 CRS preset.
type CRSSpec struct {
	// Paranoia sets tx.blocking_paranoia_level and tx.detection_paranoia_level.
	// +optional
	// +kubebuilder:default=1
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=4
	Paranoia int32 `json:"paranoia,omitempty"`

	// InboundAnomalyThreshold sets tx.inbound_anomaly_score_threshold.
	// +optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=100000
	InboundAnomalyThreshold *int32 `json:"inboundAnomalyThreshold,omitempty"`

	// OutboundAnomalyThreshold sets tx.outbound_anomaly_score_threshold.
	// +optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=100000
	OutboundAnomalyThreshold *int32 `json:"outboundAnomalyThreshold,omitempty"`

	// RemoveIDs emits SecRuleRemoveById after the CRS include.
	// +optional
	// +kubebuilder:validation:MaxItems=64
	RemoveIDs []int32 `json:"removeIds,omitempty"`

	// RemoveTags emits SecRuleRemoveByTag after the CRS include.
	// +optional
	// +kubebuilder:validation:MaxItems=64
	RemoveTags []string `json:"removeTags,omitempty"`

	// UpdateTargets emits SecRuleUpdateTargetById after the CRS include.
	// +optional
	// +kubebuilder:validation:MaxItems=64
	UpdateTargets []TargetUpdate `json:"updateTargets,omitempty"`
}

// TargetUpdate removes variables from one CRS rule.
type TargetUpdate struct {
	// +kubebuilder:validation:Minimum=1
	ID int32 `json:"id"`
	// Remove is a list of targets, for example ARGS:password. The compiler adds the ! prefix.
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=32
	Remove []string `json:"remove"`
}

// RateLimit is one local BackendTrafficPolicy.
type RateLimit struct {
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	Name string `json:"name"`
	// TargetRef is the HTTPRoute this limit applies to.
	TargetRef gatewayv1.LocalPolicyTargetReference `json:"targetRef"`
	// +kubebuilder:validation:Minimum=1
	Requests int32 `json:"requests"`
	// +optional
	// +kubebuilder:default=Second
	// +kubebuilder:validation:Enum=Second;Minute;Hour;Day
	Unit string `json:"unit,omitempty"`
}

// ProtectionStatus matches SecPolicy's attachment conditions.
type ProtectionStatus struct {
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
	// +optional
	SecLangHash string `json:"secLangHash,omitempty"`
	// +optional
	RulesLoaded int32 `json:"rulesLoaded,omitempty"`
	// +optional
	ActionsLoaded int32 `json:"actionsLoaded,omitempty"`
	// +optional
	IncludesLoaded int32 `json:"includesLoaded,omitempty"`
	// +optional
	EnvoyExtensionPolicyName string `json:"envoyExtensionPolicyName,omitempty"`
	// +optional
	ConfigMapName string `json:"configMapName,omitempty"`
	// +optional
	ConfigMapNamespace string `json:"configMapNamespace,omitempty"`
	// +optional
	GatewayName string `json:"gatewayName,omitempty"`
	// +optional
	EnvoyProxyNamespace string `json:"envoyProxyNamespace,omitempty"`
	// +optional
	EnvoyProxyName string `json:"envoyProxyName,omitempty"`
	// +optional
	EngineImage string `json:"engineImage,omitempty"`
	// +optional
	CRSVersion string `json:"crsVersion,omitempty"`
	// RateLimitPolicies are the BackendTrafficPolicy names this object owns.
	// +optional
	RateLimitPolicies []string `json:"rateLimitPolicies,omitempty"`
}

// +kubebuilder:object:root=true
type ProtectionList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Protection `json:"items"`
}

// ObjectName is the bundle and EnvoyExtensionPolicy identity for a Protection.
// The p- prefix keeps it distinct from a SecPolicy of the same metadata name.
func ObjectName(name string) string { return "p-" + name }

// RateLimitPolicyName is the BackendTrafficPolicy name for one rate limit entry.
func RateLimitPolicyName(protection, limit string) string {
	return "kubewaf-ratelimit-" + protection + "-" + limit
}
