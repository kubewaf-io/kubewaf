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

// SecActionSpec defines the desired state of SecAction.
// SecActions are like SecRules but without a condition (always match).
type SecActionSpec struct {
	// Metadata holds phase, comment and other identification for the SecAction.
	Metadata *SecRuleMetadata `json:"metadata,omitempty" yaml:"metadata,omitempty"`

	// Embedded actions to apply unconditionally.
	SecRuleActions `json:",inline"`

	// Transformations to apply before other processing.
	// +optional
	Transformations []Transformation `json:"transformations,omitempty" yaml:"transformations,omitempty"`
}

// SecActionStatus defines the observed state of SecAction.
type SecActionStatus struct {
	// Conditions represent the current state of the SecAction resource.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// SecRuleString contains the rendered SecLang string for this action.
	SecRuleString string `json:"secRuleString,omitempty" yaml:"secRuleString"`

	// RuleSetRefs tracks which RuleSets reference this SecAction.
	// +optional
	RuleSetRefs []RuleSetRef `json:"ruleSetRefs,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:path=secactions,scope=Namespaced,categories=waf;security,shortName=sa

// SecAction is the Schema for the secactions API.
// SecAction defines an unconditional action (like a global SecAction) in the WAF.
type SecAction struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is the standard object metadata.
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the desired state of SecAction.
	// +required
	Spec SecActionSpec `json:"spec"`

	// status defines the observed state of SecAction.
	// +optional
	Status SecActionStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// SecActionList contains a list of SecAction
type SecActionList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []SecAction `json:"items"`
}

func init() {
	SchemeBuilder.Register(&SecAction{}, &SecActionList{})
}

// AddRuleSetRef implements SecLang.
func (s *SecAction) AddRuleSetRef(r client.Object) bool {
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

// GetSecLangRule implements SecLang.
func (s *SecAction) GetSecLangRule() string {
	return s.Status.SecRuleString
}
