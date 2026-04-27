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
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// WAFInstanceSpec defines the desired state of WAFInstance.
// It references RuleSets (which are recursively flattened to SecRules/SecActions).
// Non-RuleSet objects may only consume RuleSets (enforced by RuleRefResolver;
// future webhook validation planned).
type WAFInstanceSpec struct {
	ParentRefs  []gatewayv1.ParentReference        `json:"parentRefs,omitempty"`
	BackendRefs []gatewayv1.BackendObjectReference `json:"backendRefs,omitempty"`
	// RuleSetRefs references RuleSets using the shared RuleRef type (direct
	// SecRule/SecAction references from non-RuleSet owners are disallowed).
	// Resolution, recursion, back-references, and the ReferencesResolved
	// condition are handled automatically by internal/references2.RuleRefResolver.
	RuleSetRefs []RuleRef `json:"ruleRefs,omitempty"`

	// Workload WorkloadTemplate `json:"workload"`
}

// WAFInstanceStatus defines the observed state of WAFInstance.
type WAFInstanceStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// For Kubernetes API conventions, see:
	// https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/api-conventions.md#typical-status-properties

	// conditions represent the current state of the WAFInstance resource.
	// Each condition has a unique type and reflects the status of a specific aspect of the resource.
	//
	// Standard condition types include:
	// - "Available": the resource is fully functional
	// - "Progressing": the resource is being created or updated
	// - "Degraded": the resource failed to reach or maintain its desired state
	//
	// The status of each condition is one of True, False, or Unknown.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:path=wafinstances,scope=Namespaced,categories=waf;security,shortName=wafinst

// WAFInstance is the Schema for the wafinstances API
type WAFInstance struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the desired state of WAFInstance
	// +required
	Spec WAFInstanceSpec `json:"spec"`

	// status defines the observed state of WAFInstance
	// +optional
	Status WAFInstanceStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// WAFInstanceList contains a list of WAFInstance
type WAFInstanceList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []WAFInstance `json:"items"`
}

func init() {
	SchemeBuilder.Register(&WAFInstance{}, &WAFInstanceList{})
}
