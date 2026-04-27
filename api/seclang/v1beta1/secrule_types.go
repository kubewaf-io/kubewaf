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
type SecRuleSpec struct {
	// SecRules contains the list of SecLang rules that define the WAF behavior.
	// +optional
	SecRules []SecLangSecRule `json:"secLangRules,omitempty"`
}

// SecLangSecRule represents a single ModSecurity/Coraza SecRule in structured form.
// It consists of metadata, conditions (variables + operator), and actions.
type SecLangSecRule struct {
	// Metadata holds identification, phase, severity, message and other rule metadata.
	Metadata *SecRuleMetadata `json:"metadata,omitempty" yaml:"metadata,omitempty"`

	// Conditions define when the rule should trigger (the "if" part of the rule).
	Conditions []Condition `json:"conditions,omitempty"`

	// Actions specify what to do when the rule matches.
	Actions *SecRuleActions `json:"actions,omitempty" yaml:"actions,omitempty"`

	// ChainedRule indicates if this is part of a chained rule set.
	ChainedRule bool `json:"chainedRule,omitempty"`

	// SecMarker is a label that can be used with skipAfter actions.
	// It will be emitted after this rule.
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

	// RuleSetRefs tracks which RuleSets reference this SecRule.
	// +optional
	RuleSetRefs []RuleSetRef `json:"ruleSetRefs,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`

// SecRule is the Schema for the secrules API.
// SecRule represents a single ModSecurity/Coraza security rule in Kubernetes.
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

func init() {
	SchemeBuilder.Register(&SecRule{}, &SecRuleList{})
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
