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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// SecPolicy binds SecRule, SecAction, and Include objects to a Gateway or HTTPRoute.
// It does not create an EnvoyProxy and it does not patch a Gateway.
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:path=secpolicies,scope=Namespaced,shortName=sp,categories=waf;security
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
// +kubebuilder:validation:XValidation:rule="self.spec.targetRefs.all(t, t.group == 'gateway.networking.k8s.io' && t.kind in ['Gateway', 'HTTPRoute'])",message="targetRefs must be a Gateway or HTTPRoute in gateway.networking.k8s.io"
// +kubebuilder:validation:XValidation:rule="self.spec.rules.all(r, (has(r.name) && size(r.name) > 0 && !has(r.selector)) || ((!has(r.name) || size(r.name) == 0) && has(r.selector)))",message="each rule selector sets name or selector, not both"
// +kubebuilder:validation:XValidation:rule="!has(self.spec.dataFiles) || self.spec.dataFiles.all(f, (has(f.content) && !has(f.configMapRef)) || ((!has(f.content) || size(f.content) == 0) && has(f.configMapRef)))",message="each data file sets content or configMapRef, not both"
// +kubebuilder:validation:XValidation:rule="!has(self.spec.defaultActions) || self.spec.defaultActions.all(a, self.spec.defaultActions.filter(b, b.phase == a.phase).size() == 1)",message="defaultActions phases must be unique"
type SecPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   SecPolicySpec   `json:"spec"`
	Status SecPolicyStatus `json:"status,omitempty"`
}

// SecPolicySpec is the attachment.
type SecPolicySpec struct {
	// TargetRefs attach to a Gateway or an HTTPRoute in this namespace.
	// EnvoyExtensionPolicy is same-namespace, and so is this policy.
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=16
	TargetRefs []gatewayv1.LocalPolicyTargetReference `json:"targetRefs"`

	// Rules selects SecRule, SecAction, and Include objects in this namespace.
	// Each entry is a name or a label selector.
	// +kubebuilder:validation:MinItems=1
	Rules []RuleSelector `json:"rules"`

	// Engine maps to SecRuleEngine.
	// +optional
	// +kubebuilder:default=On
	// +kubebuilder:validation:Enum=On;DetectionOnly;Off
	Engine string `json:"engine,omitempty"`

	// Inspection maps to the Coraza module mode.
	// RequestOnly evaluates phases 1 and 2. Full also evaluates 3, 4, and 5.
	// +optional
	// +kubebuilder:default=RequestOnly
	// +kubebuilder:validation:Enum=RequestOnly;Full
	Inspection string `json:"inspection,omitempty"`

	// RequestBodyAccess emits SecRequestBodyAccess.
	// +optional
	// +kubebuilder:default=true
	RequestBodyAccess *bool `json:"requestBodyAccess,omitempty"`

	// ResponseBodyAccess emits SecResponseBodyAccess.
	// Default false. Full inspection still needs this for phase 4.
	// +optional
	// +kubebuilder:default=false
	ResponseBodyAccess *bool `json:"responseBodyAccess,omitempty"`

	// DataFiles are bodies for @pmFromFile and @ipMatchFromFile.
	// +optional
	// +kubebuilder:validation:MaxItems=32
	DataFiles []DataFile `json:"dataFiles,omitempty"`

	// DefaultActions emits one SecDefaultAction per phase, before user rules.
	// Leave empty to keep the module and CRS defaults.
	// +optional
	DefaultActions []DefaultAction `json:"defaultActions,omitempty"`

	// PostDirectives are SecLang lines written at the end of the after file.
	// Intended for SecRuleRemoveById, SecRuleRemoveByTag, SecRuleUpdateTargetById.
	// +optional
	// +kubebuilder:validation:MaxItems=64
	PostDirectives []string `json:"postDirectives,omitempty"`

	// ModuleName is the dynamicModules[].name the platform registered.
	// The EnvoyExtensionPolicy references this name. It does not register the module.
	// +optional
	// +kubebuilder:default=composer
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$`
	ModuleName string `json:"moduleName,omitempty"`
}

// RuleSelector picks objects in the policy namespace.
type RuleSelector struct {
	// +kubebuilder:validation:Enum=SecRule;SecAction;Include
	Kind string `json:"kind"`
	// Name and Selector are mutually exclusive. One is required.
	// +optional
	Name string `json:"name,omitempty"`
	// +optional
	Selector *metav1.LabelSelector `json:"selector,omitempty"`
}

// DataFile is one @pmFromFile or @ipMatchFromFile body.
type DataFile struct {
	// +kubebuilder:validation:Pattern=`^[A-Za-z0-9][A-Za-z0-9._-]*\.data$`
	// +kubebuilder:validation:MaxLength=128
	Name string `json:"name"`
	// Content and ConfigMapRef are mutually exclusive.
	// +optional
	Content string `json:"content,omitempty"`
	// +optional
	ConfigMapRef *ConfigMapKeyRef `json:"configMapRef,omitempty"`
}

// DefaultAction is one SecDefaultAction phase.
type DefaultAction struct {
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=5
	Phase int `json:"phase"`
	// Actions is a raw SecLang action list, for example "log,auditlog,deny,status:403".
	Actions string `json:"actions"`
}

// SecPolicyStatus is the attachment result. The reconciler is not part of M1.
type SecPolicyStatus struct {
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
}

// +kubebuilder:object:root=true
type SecPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SecPolicy `json:"items"`
}
