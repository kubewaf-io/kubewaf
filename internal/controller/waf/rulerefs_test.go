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
	"fmt"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestLeafRuleRefsCapsAndSorts(t *testing.T) {
	objs := []unstructured.Unstructured{
		uObj("RuleSet", "demo", "wrap"),
		uObj("SecRule", "demo", "z-rule"),
		uObj("SecAction", "demo", "a-action"),
		uObj("SecRule", "other", "mid"),
	}
	refs, omitted, truncated := leafRuleRefs(objs)
	if truncated || omitted != 0 {
		t.Fatalf("small set truncated=%v omitted=%d", truncated, omitted)
	}
	if len(refs) != 3 {
		t.Fatalf("want 3 leaves, got %d", len(refs))
	}
	if refs[0].Kind != "SecAction" || refs[0].Name != "a-action" {
		t.Fatalf("first=%+v", refs[0])
	}
	if refs[1].Kind != "SecRule" || refs[1].Namespace != "demo" {
		t.Fatalf("second=%+v", refs[1])
	}

	many := make([]unstructured.Unstructured, 0, 300)
	for i := 0; i < 300; i++ {
		many = append(many, uObj("SecRule", "demo", fmt.Sprintf("r-%04d", i)))
	}
	refs, omitted, truncated = leafRuleRefs(many)
	if !truncated || omitted != 300-maxWAFRuleRefs || len(refs) != maxWAFRuleRefs {
		t.Fatalf("cap: n=%d omitted=%d truncated=%v", len(refs), omitted, truncated)
	}
}

func uObj(kind, ns, name string) unstructured.Unstructured {
	var u unstructured.Unstructured
	u.SetKind(kind)
	u.SetNamespace(ns)
	u.SetName(name)
	return u
}
