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

// AnnotationAllowCRSOverride is required on PhraseLists that override stock CRS basenames.
const AnnotationAllowCRSOverride = "seclang.kubewaf.io/allow-crs-override"

// LabelPhraseList marks PhraseList resources for chart/kubectl selectors.
const LabelPhraseList = "seclang.kubewaf.io/phrase-list"

// LabelCRSData marks stock OWASP CRS @pmFromFile data packs (not user overrides).
// Pack PhraseLists inject without seclang.kubewaf.io/allow-crs-override.
const LabelCRSData = "seclang.kubewaf.io/crs-data"

// LabelFileName is an optional convenience label (≤63 chars); field index is authoritative.
const LabelFileName = "seclang.kubewaf.io/file-name"

// PhraseListSpec defines the desired state of PhraseList.
// Exactly one of content, configMapRef, or parts must be set.
// Use IPList for @ipMatchFromFile / IP/CIDR lists (not PhraseList).
//
// +kubebuilder:validation:XValidation:rule="[has(self.content), has(self.configMapRef), has(self.parts)].filter(x, x).size() == 1",message="exactly one of content, configMapRef, or parts is required"
type PhraseListSpec struct {
	// FileName is the basename used in SecRule operator.value
	// (e.g. "custom-scanners.data"). Discovery uses a field index, not labels.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[A-Za-z0-9][A-Za-z0-9._-]*\.data$`
	FileName string `json:"fileName"`

	// Content is the raw file body (newline-separated phrase entries, # comments allowed).
	// Mutually exclusive with ConfigMapRef and Parts.
	// +optional
	// +kubebuilder:validation:MaxLength=786432
	Content string `json:"content,omitempty"`

	// ConfigMapRef loads a single key from a ConfigMap in the same namespace.
	// +optional
	ConfigMapRef *PhraseListConfigMapRef `json:"configMapRef,omitempty"`

	// Parts composes multiple same-namespace ConfigMap keys (in order).
	// Composed size ≤ 2 MiB (controller-enforced).
	// +optional
	// +kubebuilder:validation:MaxItems=16
	// +kubebuilder:validation:MinItems=1
	Parts []PhraseListPart `json:"parts,omitempty"`
}

// PhraseListConfigMapRef points at a ConfigMap key in the PhraseList namespace.
type PhraseListConfigMapRef struct {
	// Name of the ConfigMap.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
	// Key within the ConfigMap data map.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Key string `json:"key"`
}

// PhraseListPart is one ConfigMap segment when composing large lists.
type PhraseListPart struct {
	// ConfigMapRef of this part.
	// +kubebuilder:validation:Required
	ConfigMapRef PhraseListConfigMapRef `json:"configMapRef"`
}

// PhraseListStatus defines the observed state of PhraseList.
type PhraseListStatus struct {
	// Conditions represent the current state of the PhraseList.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// SizeBytes is the composed body size.
	// +optional
	SizeBytes int64 `json:"sizeBytes,omitempty"`

	// ContentHash is sha256 hex of the composed body.
	// +optional
	ContentHash string `json:"contentHash,omitempty"`

	// FileName mirrors spec.fileName once Ready (for indexes / UX).
	// +optional
	FileName string `json:"fileName,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:path=phraselists,scope=Namespaced,categories=waf;security,shortName=pl
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="FileName",type=string,JSONPath=`.status.fileName`
// +kubebuilder:printcolumn:name="Size",type=integer,JSONPath=`.status.sizeBytes`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// PhraseList is a namespaced phrase-list body for @pmFromFile / @pmf.
// For IP/CIDR blocklists use IPList with @ipMatchFromFile instead.
type PhraseList struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is standard object metadata.
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the desired state of PhraseList.
	// +required
	Spec PhraseListSpec `json:"spec"`

	// status defines the observed state of PhraseList.
	// +optional
	Status PhraseListStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// PhraseListList contains a list of PhraseList.
type PhraseListList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []PhraseList `json:"items"`
}
