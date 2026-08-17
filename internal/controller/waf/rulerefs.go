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

package waf

import (
	"sort"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	wafv1beta1 "github.com/kubewaf-io/kubewaf/api/waf/v1beta1"
)

// maxWAFRuleRefs caps status.ruleRefs.
const maxWAFRuleRefs = 256

// leafRuleRefs returns a stable, capped SecRule/SecAction membership list.
func leafRuleRefs(objects []unstructured.Unstructured) (refs []wafv1beta1.RuleRefStatus, omitted int32, truncated bool) {
	leaves := make([]wafv1beta1.RuleRefStatus, 0, len(objects))
	for i := range objects {
		k := objects[i].GetKind()
		if k != "SecRule" && k != "SecAction" {
			continue
		}
		leaves = append(leaves, wafv1beta1.RuleRefStatus{
			Kind:      k,
			Name:      objects[i].GetName(),
			Namespace: objects[i].GetNamespace(),
		})
	}
	sort.Slice(leaves, func(i, j int) bool {
		if leaves[i].Kind != leaves[j].Kind {
			return leaves[i].Kind < leaves[j].Kind
		}
		if leaves[i].Namespace != leaves[j].Namespace {
			return leaves[i].Namespace < leaves[j].Namespace
		}
		return leaves[i].Name < leaves[j].Name
	})
	if len(leaves) > maxWAFRuleRefs {
		return leaves[:maxWAFRuleRefs], int32(len(leaves) - maxWAFRuleRefs), true
	}
	return leaves, 0, false
}
