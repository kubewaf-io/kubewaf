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

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// WAFEnvoyGatewaySpec defines the desired state of WAFEnvoyGateway
type WAFEnvoyGatewaySpec struct {
	ParentRefs  envoygatewayv1alpha1.PolicyTargetReferences `json:"parentRefs,omitempty"`
	RuleSetRefs []RuleRef                                   `json:"ruleRefs,omitempty"`
	CRSEnable   bool                                        `json:"crsEnable,omitempty"`
	LogLevel int									`json:"logLevel,omitempty"`
}

// WAFEnvoyGatewayStatus defines the observed state of WAFEnvoyGateway.
type WAFEnvoyGatewayStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// For Kubernetes API conventions, see:
	// https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/api-conventions.md#typical-status-properties

	// conditions represent the current state of the WAFEnvoyGateway resource.
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

// WAFEnvoyGateway is the Schema for the wafenvoygateways API
type WAFEnvoyGateway struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the desired state of WAFEnvoyGateway
	// +required
	Spec WAFEnvoyGatewaySpec `json:"spec"`

	// status defines the observed state of WAFEnvoyGateway
	// +optional
	Status WAFEnvoyGatewayStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// WAFEnvoyGatewayList contains a list of WAFEnvoyGateway
type WAFEnvoyGatewayList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []WAFEnvoyGateway `json:"items"`
}

func init() {
	SchemeBuilder.Register(&WAFEnvoyGateway{}, &WAFEnvoyGatewayList{})
}
