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

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// Placement selects which file a SecPolicy writes the object into.
// BeforeCRS is included first. AfterCRS is included second.
// CRS itself is an Include object, not a boolean on the policy.
type Placement string

const (
	PlacementBeforeCRS Placement = "BeforeCRS"
	PlacementAfterCRS  Placement = "AfterCRS"
)

// SecRule is one SecRule directive, or one chain of them, plus an optional SecMarker.
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:path=secrules,scope=Namespaced,shortName=sr,categories=waf;security
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="ID",type=integer,JSONPath=`.spec.metadata.id`
// +kubebuilder:printcolumn:name="Phase",type=integer,JSONPath=`.spec.metadata.phase`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
type SecRule struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   SecRuleSpec   `json:"spec"`
	Status SecLangStatus `json:"status,omitempty"`
}

// SecRuleSpec is one logical SecRule.
// +kubebuilder:validation:XValidation:rule="(size(self.chain) < 2 || !has(self.chain[1].actions) || !has(self.chain[1].actions.disruptive)) && (size(self.chain) < 3 || !has(self.chain[2].actions) || !has(self.chain[2].actions.disruptive)) && (size(self.chain) < 4 || !has(self.chain[3].actions) || !has(self.chain[3].actions.disruptive)) && (size(self.chain) < 5 || !has(self.chain[4].actions) || !has(self.chain[4].actions.disruptive)) && (size(self.chain) < 6 || !has(self.chain[5].actions) || !has(self.chain[5].actions.disruptive)) && (size(self.chain) < 7 || !has(self.chain[6].actions) || !has(self.chain[6].actions.disruptive)) && (size(self.chain) < 8 || !has(self.chain[7].actions) || !has(self.chain[7].actions.disruptive)) && (size(self.chain) < 9 || !has(self.chain[8].actions) || !has(self.chain[8].actions.disruptive)) && (size(self.chain) < 10 || !has(self.chain[9].actions) || !has(self.chain[9].actions.disruptive)) && (size(self.chain) < 11 || !has(self.chain[10].actions) || !has(self.chain[10].actions.disruptive)) && (size(self.chain) < 12 || !has(self.chain[11].actions) || !has(self.chain[11].actions.disruptive)) && (size(self.chain) < 13 || !has(self.chain[12].actions) || !has(self.chain[12].actions.disruptive)) && (size(self.chain) < 14 || !has(self.chain[13].actions) || !has(self.chain[13].actions.disruptive)) && (size(self.chain) < 15 || !has(self.chain[14].actions) || !has(self.chain[14].actions.disruptive)) && (size(self.chain) < 16 || !has(self.chain[15].actions) || !has(self.chain[15].actions.disruptive))",message="only the first chain link may set a disruptive action"
// +kubebuilder:validation:XValidation:rule="self.chain.all(l, l.targets.all(t, !(has(t.exclude) && t.exclude && has(t.count) && t.count)))",message="exclude and count cannot both be set on one target"
// +kubebuilder:validation:XValidation:rule="self.chain.all(l, !has(l.actions) || !has(l.actions.flow) || l.actions.flow.all(f, f.type != 'chain'))",message="chain is emitted from the chain list, not from a flow action"
type SecRuleSpec struct {
	// Order is the sort key inside a SecPolicy. Lower runs first.
	// Ties break by object name. Zero is a real value.
	// +optional
	// +kubebuilder:default=1000
	Order int32 `json:"order,omitempty"`

	// Placement selects which file the policy writes this rule into.
	// BeforeCRS is for setup overrides. AfterCRS is the default and is where custom detections belong.
	// +optional
	// +kubebuilder:default=AfterCRS
	// +kubebuilder:validation:Enum=BeforeCRS;AfterCRS
	Placement Placement `json:"placement,omitempty"`

	// MarkerAfter emits a SecMarker line after this rule. skipAfter targets it.
	// +optional
	// +kubebuilder:validation:Pattern=`^[A-Za-z_][A-Za-z0-9_-]*$`
	// +kubebuilder:validation:MaxLength=64
	MarkerAfter string `json:"markerAfter,omitempty"`

	// Metadata is the SecLang metadata actions. id and phase are required.
	Metadata Metadata `json:"metadata"`

	// Chain is one or more links. Link 0 is the SecRule. Later links are
	// emitted with the chain action on the previous link.
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=16
	Chain []ChainLink `json:"chain"`
}

// Metadata maps onto SecLang metadata actions.
// id and phase are emitted first. The rest follow in the canonical order.
type Metadata struct {
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=2147483647
	ID int `json:"id"`

	// Phase is 1 request headers, 2 request body, 3 response headers,
	// 4 response body, 5 logging.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=5
	Phase int `json:"phase"`

	// +optional
	// +kubebuilder:validation:MaxLength=2048
	Message string `json:"message,omitempty"`
	// +optional
	// +kubebuilder:validation:Pattern=`^([0-7]|EMERGENCY|ALERT|CRITICAL|ERROR|WARNING|NOTICE|INFO|DEBUG)$`
	Severity string `json:"severity,omitempty"`
	// +optional
	// +kubebuilder:validation:MaxItems=32
	Tags []string `json:"tags,omitempty"`
	// +optional
	Revision string `json:"revision,omitempty"`
	// +optional
	Version string `json:"version,omitempty"`
	// +optional
	Maturity string `json:"maturity,omitempty"`
	// +optional
	Accuracy string `json:"accuracy,omitempty"`
}

// ChainLink is one SecRule line in a chain.
type ChainLink struct {
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=32
	Targets []Target `json:"targets"`

	Operator Operator `json:"operator"`

	// +optional
	// +kubebuilder:validation:MaxItems=16
	Transformations []Transformation `json:"transformations,omitempty"`

	// Actions on link 0 may include one disruptive action.
	// Later links must leave Disruptive empty. The chain action is not set here.
	// +optional
	Actions *Actions `json:"actions,omitempty"`
}

// Target is one SecLang variable or collection expression.
// Emission: [!][&]NAME[:selector]
type Target struct {
	Name VariableName `json:"name"`
	// +optional
	Selector string `json:"selector,omitempty"`
	// +optional
	Exclude bool `json:"exclude,omitempty"`
	// +optional
	Count bool `json:"count,omitempty"`
}

// +kubebuilder:validation:XValidation:rule="(self.name in ['unconditionalMatch','detectSQLi','detectXSS','validateUrlEncoding','validateUtf8Encoding','geoLookup'] && (!has(self.value) || size(self.value) == 0)) || self.name in ['verifyCPF','verifySSN','verifySVNR'] || (!(self.name in ['unconditionalMatch','detectSQLi','detectXSS','validateUrlEncoding','validateUtf8Encoding','geoLookup','verifyCPF','verifySSN','verifySVNR']) && has(self.value) && size(self.value) > 0)",message="operator value is required or forbidden based on the operator"
type Operator struct {
	// Negate emits !@name.
	// +optional
	Negate bool         `json:"negate,omitempty"`
	Name   OperatorName `json:"name"`
	// +optional
	// +kubebuilder:validation:MaxLength=4096
	Value string `json:"value,omitempty"`
}

// Actions is the SecLang action list minus metadata (those are Metadata)
// and minus chain (the chain structure emits that).
// +kubebuilder:validation:XValidation:rule="!has(self.flow) || self.flow.all(f, f.type != 'chain')",message="chain is emitted from the chain list, not from a flow action"
// +kubebuilder:validation:XValidation:rule="!has(self.nonDisruptive) || self.nonDisruptive.all(a, (a.type in ['auditlog','capture','log','multiMatch','noauditlog','nolog','sanitiseMatched','sanitizeMatched'] && (!has(a.value) || size(a.value) == 0)) || a.type in ['sanitiseMatchedBytes','sanitizeMatchedBytes'] || (a.type in ['append','prepend','ctl','deprecatevar','exec','expirevar','initcol','logdata','sanitiseArg','sanitizeArg','sanitiseRequestHeader','sanitizeRequestHeader','sanitiseResponseHeader','sanitizeResponseHeader','setenv','setrsc','setsid','setuid','setvar'] && has(a.value) && size(a.value) > 0))",message="action value does not match the action type"
type Actions struct {
	// +optional
	Disruptive *DisruptiveAction `json:"disruptive,omitempty"`
	// +optional
	// +kubebuilder:validation:MaxItems=8
	Flow []FlowAction `json:"flow,omitempty"`
	// +optional
	// +kubebuilder:validation:MaxItems=8
	Data []DataAction `json:"data,omitempty"`
	// +optional
	// +kubebuilder:validation:MaxItems=32
	NonDisruptive []NonDisruptiveAction `json:"nonDisruptive,omitempty"`
}

// +kubebuilder:validation:XValidation:rule="(self.type in ['deny','drop','block','pass'] && (!has(self.value) || size(self.value) == 0)) || (self.type == 'allow' && (!has(self.value) || size(self.value) == 0 || self.value == 'phase' || self.value == 'request')) || (self.type == 'pause' && has(self.value) && self.value.matches('^[0-9]+$')) || (self.type in ['proxy','redirect'] && has(self.value) && size(self.value) > 0)",message="disruptive action value does not match the action type"
type DisruptiveAction struct {
	Type DisruptiveActionType `json:"type"`
	// Value is the argument: allow:phase, allow:request, pause:<ms>,
	// proxy:<url>, redirect:<url>. Empty for deny, drop, block, pass.
	// +optional
	// +kubebuilder:validation:MaxLength=2048
	Value string `json:"value,omitempty"`
}

// +kubebuilder:validation:XValidation:rule="(self.type == 'skip' && self.value.matches('^[1-9][0-9]*$')) || (self.type == 'skipAfter' && self.value.matches('^[A-Za-z_][A-Za-z0-9_-]*$')) || self.type == 'chain'",message="skip takes a positive integer and skipAfter takes a marker name"
type FlowAction struct {
	// chain is rejected. skip and skipAfter are the accepted types.
	Type FlowActionType `json:"type"`
	// +kubebuilder:validation:MaxLength=64
	Value string `json:"value"`
}

// +kubebuilder:validation:XValidation:rule="(self.type == 'status' && self.value.matches('^[1-5][0-9]{2}$')) || (self.type == 'xmlns' && self.value.matches('^[^=]+=.+$'))",message="status takes an HTTP code and xmlns takes prefix=url"
type DataAction struct {
	Type DataActionType `json:"type"`
	// +optional
	// +kubebuilder:validation:MaxLength=512
	Value string `json:"value,omitempty"`
}

type NonDisruptiveAction struct {
	Type NonDisruptiveActionType `json:"type"`
	// +optional
	// +kubebuilder:validation:MaxLength=2048
	Value string `json:"value,omitempty"`
}

// SecAction is an unconditional SecAction directive.
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:path=secactions,scope=Namespaced,shortName=sa,categories=waf;security
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="ID",type=integer,JSONPath=`.spec.metadata.id`
// +kubebuilder:printcolumn:name="Phase",type=integer,JSONPath=`.spec.metadata.phase`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
// +kubebuilder:validation:XValidation:rule="!has(self.spec.actions) || !has(self.spec.actions.flow) || self.spec.actions.flow.all(f, f.type != 'chain')",message="chain is not valid on SecAction"
type SecAction struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   SecActionSpec `json:"spec"`
	Status SecLangStatus `json:"status,omitempty"`
}

// SecActionSpec is one unconditional SecAction.
type SecActionSpec struct {
	// +optional
	// +kubebuilder:default=100
	Order int32 `json:"order,omitempty"`
	// +optional
	// +kubebuilder:default=AfterCRS
	// +kubebuilder:validation:Enum=BeforeCRS;AfterCRS
	Placement Placement `json:"placement,omitempty"`
	// +optional
	// +kubebuilder:validation:Pattern=`^[A-Za-z_][A-Za-z0-9_-]*$`
	// +kubebuilder:validation:MaxLength=64
	MarkerAfter string   `json:"markerAfter,omitempty"`
	Metadata    Metadata `json:"metadata"`
	// +optional
	Transformations []Transformation `json:"transformations,omitempty"`
	// +optional
	Actions *Actions `json:"actions,omitempty"`
}

// Include is one SecLang Include directive.
// The kind is Include, not SecInclude, because the directive is Include.
// SecRule and SecAction are named after their directives the same way.
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:path=includes,scope=Namespaced,shortName=inc,categories=waf;security
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Placement",type=string,JSONPath=`.spec.placement`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
// +kubebuilder:validation:XValidation:rule="(has(self.spec.virtualPath) && size(self.spec.virtualPath) > 0 && !has(self.spec.configMapRef)) || ((!has(self.spec.virtualPath) || size(self.spec.virtualPath) == 0) && has(self.spec.configMapRef))",message="set exactly one of virtualPath or configMapRef"
type Include struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   IncludeSpec   `json:"spec"`
	Status SecLangStatus `json:"status,omitempty"`
}

// IncludeSpec is one Include.
// A virtual path is a module-embedded file such as @crs-setup.conf or @owasp_crs/*.conf.
// A ConfigMap key is copied onto the kubewaf-seclang mount and included by absolute path.
// A glob is legal only on a virtual path.
type IncludeSpec struct {
	// +optional
	// +kubebuilder:default=1000
	Order int32 `json:"order,omitempty"`
	// +optional
	// +kubebuilder:default=AfterCRS
	// +kubebuilder:validation:Enum=BeforeCRS;AfterCRS
	Placement Placement `json:"placement,omitempty"`
	// +optional
	// +kubebuilder:validation:Pattern=`^[A-Za-z_][A-Za-z0-9_-]*$`
	// +kubebuilder:validation:MaxLength=64
	MarkerAfter string `json:"markerAfter,omitempty"`

	// VirtualPath is a module-embedded path. It must start with @.
	// One * glob is allowed, as in @owasp_crs/*.conf.
	// +optional
	// +kubebuilder:validation:Pattern=`^@[A-Za-z0-9][A-Za-z0-9._/-]*(\*[A-Za-z0-9._/-]*)?$`
	// +kubebuilder:validation:MaxLength=256
	VirtualPath string `json:"virtualPath,omitempty"`

	// ConfigMapRef selects SecLang file content. The key cannot contain a glob.
	// +optional
	ConfigMapRef *ConfigMapKeyRef `json:"configMapRef,omitempty"`
}

// ConfigMapKeyRef names a key in a ConfigMap in the same namespace.
type ConfigMapKeyRef struct {
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Name string `json:"name"`
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[A-Za-z0-9][A-Za-z0-9._-]*$`
	Key string `json:"key"`
}

// SecLangStatus is the compiled text of one object.
type SecLangStatus struct {
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
	// SecLang is the rendered directive text, including a trailing SecMarker line.
	// +optional
	SecLang string `json:"secLang,omitempty"`
}

// +kubebuilder:object:root=true
type SecRuleList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SecRule `json:"items"`
}

// +kubebuilder:object:root=true
type SecActionList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SecAction `json:"items"`
}

// +kubebuilder:object:root=true
type IncludeList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Include `json:"items"`
}
