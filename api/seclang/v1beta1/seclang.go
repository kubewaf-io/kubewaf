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
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// SecLang is implemented by SecRule and SecAction to provide common behavior
// for reconciliation and rule string generation.
// +kubebuilder:object:generate=false
type SecLang interface {
	client.Object
	AddRuleSetRef(r client.Object) bool
	GetSecLangRule() string
}

// RuleSetRef identifies a RuleSet that references this SecLang resource.
type RuleSetRef struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	Kind      string `json:"kind"`
	Group     string `json:"group"`
	Version   string `json:"version"`
}

// SecLangActions is implemented by the various action types (DisruptiveAction,
// NonDisruptiveAction, etc.) to provide a common interface.
// +kubebuilder:object:generate=false
type SecLangActions interface {
	GetType() string
	GetValue() string
	GetKind() string
}
