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
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// SecRuleSpec defines the desired state of SecRule.
//
// Preferred shape is one logical rule per CR:
//
//	spec.metadata + spec.match[] + spec.actions [+ order / markerAfter]
//
// Legacy multi-rule bags (spec.secLangRules) remain supported for bulk CRS
// samples; new custom rules should use the single-rule form.
type SecRuleSpec struct {
	// Order is a relative sort key when a RuleSet expands many SecRules
	// (e.g. label selector). Lower values run earlier. Zero means unset
	// (fallback to status.ruleId / object name at assembly time).
	// +optional
	Order int32 `json:"order,omitempty"`

	// MarkerAfter emits `SecMarker <name>` after this rule's SecLang output.
	// Use as the target of skipAfter flow actions on earlier rules.
	// Preferred over legacy secLangRules[].secMarker.
	// +optional
	MarkerAfter string `json:"markerAfter,omitempty"`

	// Metadata identifies the single rule (id optional → SecRuleIDPool).
	// Used with match[] (canonical one-rule-per-CR form).
	// +optional
	Metadata *SecRuleMetadata `json:"metadata,omitempty"`

	// Match is the condition chain for the rule.
	//   - length 1 → single SecRule
	//   - length N → ModSecurity chain (AND across N SecRule links)
	// Each entry is one chain link (variables/collections + operator + transforms).
	// Intermediate links may set Match[i].Actions; the final link falls back to
	// Spec.Actions when its Actions field is empty.
	// +optional
	Match []Match `json:"match,omitempty"`

	// Actions specify what to do when the rule (or final chain link) matches.
	// +optional
	Actions *SecRuleActions `json:"actions,omitempty"`

	// SecRules is the legacy multi-rule bag (one CR, many SecLang rules).
	// Prefer one CR per logical rule using metadata + match[] above.
	// When Match or top-level Metadata is set, SecRules is ignored by the converter.
	// +optional
	SecRules []SecLangSecRule `json:"secLangRules,omitempty"`
}

// Match is one link in a SecRule condition chain (AND).
// Index 0 is the parent SecRule; further entries are chain continuations.
type Match struct {
	// Variables to evaluate in this condition.
	Variables []Variable `json:"variables,omitempty" yaml:"variables,omitempty"`

	// Collections to evaluate (specialized variable groups).
	Collections []Collection `json:"collections,omitempty" yaml:"collections,omitempty"`

	// Operator defines the comparison to perform on the variable value(s).
	Operator Operator `json:"operator,omitempty" yaml:"operator,omitempty"`

	// Transformations to apply before operator evaluation.
	// +optional
	Transformations []Transformation `json:"transformations,omitempty" yaml:"transformations,omitempty"`

	// AlwaysMatch is used for SecAction-style unconditional rules.
	AlwaysMatch bool `json:"always-match,omitempty" yaml:"always-match,omitempty"`

	// Script is the path for Lua or other script-based conditions (advanced).
	Script string `json:"script,omitempty" yaml:"script,omitempty"`

	// Actions for this chain link only (optional).
	// Parent/intermediate links often set capture/setvar here; the last link
	// uses Spec.Actions when this is nil.
	// +optional
	Actions *SecRuleActions `json:"actions,omitempty" yaml:"actions,omitempty"`
}

// ToCondition projects Match into the shared Condition type.
func (m Match) ToCondition() Condition {
	return Condition{
		Variables:       m.Variables,
		Collections:     m.Collections,
		Operator:        m.Operator,
		Transformations: m.Transformations,
		AlwaysMatch:     m.AlwaysMatch,
		Script:          m.Script,
	}
}

// IsSingleRuleForm reports whether this Spec uses the canonical one-rule shape.
func (s SecRuleSpec) IsSingleRuleForm() bool {
	return s.Metadata != nil || len(s.Match) > 0 || (s.Actions != nil && len(s.SecRules) == 0)
}

// SecLangSecRule represents a single ModSecurity/Coraza SecRule in structured form
// inside the legacy secLangRules[] bag.
// Prefer Spec.Metadata + Spec.Match for new rules.
type SecLangSecRule struct {
	// Metadata holds identification, phase, severity, message and other rule metadata.
	Metadata *SecRuleMetadata `json:"metadata,omitempty" yaml:"metadata,omitempty"`

	// Conditions define when the rule should trigger (the "if" part of the rule).
	Conditions []Condition `json:"conditions,omitempty"`

	// Actions specify what to do when the rule matches.
	Actions *SecRuleActions `json:"actions,omitempty" yaml:"actions,omitempty"`

	// ChainedRule indicates if this is part of a chained rule set (legacy hint).
	// Prefer flow chain action or the match[] form.
	ChainedRule bool `json:"chainedRule,omitempty"`

	// SecMarker is a label that can be used with skipAfter actions.
	// Emitted after this rule. Prefer Spec.MarkerAfter on the single-rule form.
	SecMarker string `json:"secMarker,omitempty"`
}

type ChainableDirective struct {
	// Name of the directive that can be chained.
	Name string `json:"name"`
	// Kind of the chainable item.
	Kind string `json:"kind"`
}

// SecRuleStatus defines the observed state of SecRule.
type SecRuleStatus struct {
	// Conditions represent the current state of the SecRule resource.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// SecRuleString contains the rendered SecLang rule string.
	SecRuleString string `json:"secRuleString,omitempty" yaml:"secRuleString"`

	// RuleID is the primary effective rule id for this CR.
	// Used for labels and tooling; multi-rule CRs also populate AssignedIDs.
	// +optional
	RuleID int `json:"ruleId,omitempty"`

	// IDSource is how the primary RuleID was chosen: Spec, Auto, or Mixed.
	// +optional
	IDSource string `json:"idSource,omitempty"`

	// AssignedIDs is the effective id for each logical rule entry after reconcile.
	// Single-rule form: length 1. Legacy multi-rule: one id per secLangRules[i].
	// +optional
	AssignedIDs []int `json:"assignedIds,omitempty"`

	// RuleSetRefs tracks which RuleSets reference this SecRule.
	// +optional
	RuleSetRefs []RuleSetRef `json:"ruleSetRefs,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="RuleID",type=integer,JSONPath=`.status.ruleId`
// +kubebuilder:printcolumn:name="IDSource",type=string,JSONPath=`.status.idSource`
// +kubebuilder:printcolumn:name="Order",type=integer,JSONPath=`.spec.order`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// SecRule is the Schema for the secrules API.
// Prefer one logical ModSecurity SecRule per CR (spec.metadata + spec.match[]).
//
// metadata.id may be omitted; the controller then allocates from SecRuleIDPool and
// mirrors tags onto labels (seclang.kubewaf.io/tag.*).
// +kubebuilder:resource:path=secrules,scope=Namespaced,categories=waf;security,shortName=sr
type SecRule struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is the standard object metadata.
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the desired state of SecRule.
	// +required
	Spec SecRuleSpec `json:"spec"`

	// status defines the observed state of SecRule.
	// +optional
	Status SecRuleStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// SecRuleList contains a list of SecRule
type SecRuleList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []SecRule `json:"items"`
}

func (s *SecRule) AddRuleSetRef(r client.Object) bool {
	for _, ruleRef := range s.Status.RuleSetRefs {
		if ruleRef.Name == r.GetName() && ruleRef.Namespace == r.GetNamespace() && ruleRef.Kind == r.GetObjectKind().GroupVersionKind().Kind {
			return false
		}
	}
	ruleSetRef := RuleSetRef{
		Kind:      r.GetObjectKind().GroupVersionKind().Kind,
		Name:      r.GetName(),
		Namespace: r.GetNamespace(),
	}
	s.Status.RuleSetRefs = append(s.Status.RuleSetRefs, ruleSetRef)
	return true
}

func (s *SecRule) GetSecLangRule() string {
	return s.Status.SecRuleString
}
