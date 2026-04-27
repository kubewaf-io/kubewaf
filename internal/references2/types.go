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

package references2

import (
	"fmt"

	wafv1beta1 "github.com/buzz-it/kubewaf/api/waf/v1beta1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// ResolvedRuleRef represents a successfully resolved reference, flattened to leaf SecLang rules.
type ResolvedRuleRef struct {
	Kind      string
	Name      string
	Namespace string
	Object    client.Object
}

// ReferenceError wraps errors for a specific RuleRef (used for aggregation).
type ReferenceError struct {
	Index int
	Ref   wafv1beta1.RuleRef
	Err   error
}

func (e ReferenceError) Error() string {
	return fmt.Sprintf("RuleRef[%d] (kind=%s name=%s): %v", e.Index, e.Ref.Kind, e.Ref.Name, e.Err)
}

// RuleRefResolver provides reusable logic for resolving RuleRefs, managing status conditions,
// and automatic back-references.
type RuleRefResolver struct {
	client.Client
	Scheme *runtime.Scheme
}

// NewRuleRefResolver creates a new resolver.
func NewRuleRefResolver(c client.Client, scheme *runtime.Scheme) *RuleRefResolver {
	return &RuleRefResolver{
		Client: c,
		Scheme: scheme,
	}
}
