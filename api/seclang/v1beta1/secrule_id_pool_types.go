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
)

// SecRuleIDPoolSpec configures the cluster-wide auto ID range for SecRules
// (and future SecActions) that omit metadata.id.
type SecRuleIDPoolSpec struct {
	// MinID is the first id the pool may allocate (inclusive).
	// Custom rules should use high ids so they do not collide with CRS (typically < 100000).
	// +optional
	// +kubebuilder:default=100000
	// +kubebuilder:validation:Minimum=1
	MinID int `json:"minId,omitempty"`

	// MaxID is the last id the pool may allocate (inclusive).
	// +optional
	// +kubebuilder:default=999999
	// +kubebuilder:validation:Minimum=1
	MaxID int `json:"maxId,omitempty"`
}

// SecRuleIDPoolStatus is the leader-managed allocation cursor.
type SecRuleIDPoolStatus struct {
	// NextID is the next candidate id to try (not necessarily free if objects were deleted).
	// +optional
	NextID int `json:"nextId,omitempty"`

	// LastAllocatedID is the last id successfully granted.
	// +optional
	LastAllocatedID int `json:"lastAllocatedId,omitempty"`

	// AllocatedCount is a monotonic counter of successful allocations (not live occupancy).
	// +optional
	AllocatedCount int64 `json:"allocatedCount,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster,path=secruleidpools,shortName=sridpool,categories=waf;security
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Min",type=integer,JSONPath=`.spec.minId`
// +kubebuilder:printcolumn:name="Max",type=integer,JSONPath=`.spec.maxId`
// +kubebuilder:printcolumn:name="Next",type=integer,JSONPath=`.status.nextId`
// +kubebuilder:printcolumn:name="Last",type=integer,JSONPath=`.status.lastAllocatedId`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// SecRuleIDPool is a cluster-scoped allocator for SecRule metadata ids.
// The operator ensures a singleton named "cluster" with defaults minId=100000.
// Only the leader advances status.nextId.
type SecRuleIDPool struct {
	metav1.TypeMeta `json:",inline"`

	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// +optional
	Spec SecRuleIDPoolSpec `json:"spec,omitempty"`

	// +optional
	Status SecRuleIDPoolStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// SecRuleIDPoolList contains a list of SecRuleIDPool.
type SecRuleIDPoolList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []SecRuleIDPool `json:"items"`
}

// EffectiveMin returns the pool lower bound.
func (p *SecRuleIDPool) EffectiveMin() int {
	if p == nil || p.Spec.MinID <= 0 {
		return DefaultIDPoolMin
	}
	return p.Spec.MinID
}

// EffectiveMax returns the pool upper bound.
func (p *SecRuleIDPool) EffectiveMax() int {
	if p == nil || p.Spec.MaxID <= 0 {
		return DefaultIDPoolMax
	}
	return p.Spec.MaxID
}
