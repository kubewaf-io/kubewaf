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

const (
	// GroupName is the only group a rule reference may name.
	GroupName = "seclang.kubewaf.io"

	KindRuleSet        = "RuleSet"
	KindClusterRuleSet = "ClusterRuleSet"
	KindSecRule        = "SecRule"
	KindSecAction      = "SecAction"
	KindInclude        = "Include"
)

// ObjectRef is one ordered entry in RuleSet.spec.ruleRefs or SecPolicy.spec.ruleSetRefs.
// Group and kind are an allow-list. There is no apiVersion or version.
// Exactly one of name or selector is set.
// A selector is evaluated only in the containing object's own namespace, so it
// cannot set namespace and a ClusterRuleSet cannot use one.
// Namespace on a named ref defaults to the referrer's namespace. It is required
// when a ClusterRuleSet names a namespaced kind, and it must be empty for a
// ClusterRuleSet target.
type ObjectRef struct {
	// +kubebuilder:validation:Enum=seclang.kubewaf.io
	Group string `json:"group"`

	// +kubebuilder:validation:Enum=RuleSet;ClusterRuleSet;SecRule;SecAction;Include
	Kind string `json:"kind"`

	// Name and Selector are mutually exclusive.
	// +optional
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	Name string `json:"name,omitempty"`

	// Selector matches labels in the containing object's namespace only.
	// +optional
	Selector *metav1.LabelSelector `json:"selector,omitempty"`

	// Namespace is the target namespace for a named namespaced object.
	// Empty means the referrer's namespace. ClusterRuleSet targets leave it empty.
	// +optional
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	Namespace string `json:"namespace,omitempty"`
}

// RuleSet is an ordered list of rule references in one namespace.
// References compose: a base set, a java set that includes base, and a
// java-frontend set that includes java. Each hop is resolved on its own.
// A cross-namespace name requires a gateway.networking.k8s.io/v1 ReferenceGrant
// in the target namespace whose from matches this RuleSet. The operator does
// not install that CRD.
// +kubebuilder:object:root=true
// +kubebuilder:resource:path=rulesets,scope=Namespaced,shortName=rs,categories=waf;security
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
// +kubebuilder:validation:XValidation:rule="self.spec.ruleRefs.all(r, (has(r.name) && size(r.name) > 0 && !has(r.selector)) || ((!has(r.name) || size(r.name) == 0) && has(r.selector)))",message="each ruleRef sets name or selector, not both"
// +kubebuilder:validation:XValidation:rule="self.spec.ruleRefs.all(r, r.kind != 'ClusterRuleSet' || ((!has(r.namespace) || size(r.namespace) == 0) && !has(r.selector)))",message="ClusterRuleSet refs are named and have no namespace"
// +kubebuilder:validation:XValidation:rule="self.spec.ruleRefs.all(r, !has(r.selector) || !has(r.namespace) || size(r.namespace) == 0)",message="a selector stays in this namespace"
type RuleSet struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec RuleSetSpec `json:"spec"`
}

// RuleSetSpec is the ordered reference list.
type RuleSetSpec struct {
	// RuleRefs are expanded in order. Selector matches are ordered by name.
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=64
	RuleRefs []ObjectRef `json:"ruleRefs"`
}

// +kubebuilder:object:root=true
type RuleSetList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []RuleSet `json:"items"`
}

// ClusterRuleSet is a cluster-scoped ordered list of rule references.
// It has no namespace of its own.
//
// A ClusterRuleSet target is named, with an empty namespace, and needs no
// ReferenceGrant: the target is not namespaced.
//
// A namespaced target (RuleSet, SecRule, SecAction, Include) must set namespace
// and must not use a selector. ReferenceGrant.from.namespace is required and
// identifies a namespaced referrer, so no grant can name a ClusterRuleSet
// without inventing a source namespace. Those refs are refused before the
// target is read. Share namespaced rules through a namespaced RuleSet and a
// grant instead.
// +kubebuilder:object:root=true
// +kubebuilder:resource:path=clusterrulesets,scope=Cluster,shortName=clrs,categories=waf;security
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
// +kubebuilder:validation:XValidation:rule="self.spec.ruleRefs.all(r, has(r.name) && size(r.name) > 0 && !has(r.selector))",message="ClusterRuleSet refs are named, not selected"
// +kubebuilder:validation:XValidation:rule="self.spec.ruleRefs.all(r, r.kind == 'ClusterRuleSet' ? (!has(r.namespace) || size(r.namespace) == 0) : (has(r.namespace) && size(r.namespace) > 0))",message="namespaced targets set namespace; ClusterRuleSet targets do not"
type ClusterRuleSet struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec RuleSetSpec `json:"spec"`
}

// +kubebuilder:object:root=true
type ClusterRuleSetList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ClusterRuleSet `json:"items"`
}
