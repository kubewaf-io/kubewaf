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

package webhook

import (
	"strings"
	"testing"

	seclangv1alpha1 "github.com/kubewaf-io/kubewaf/api/seclang/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestV1Alpha1SecRuleParse(t *testing.T) {
	v := &SecRuleV1Alpha1{}
	ok := &seclangv1alpha1.SecRule{
		ObjectMeta: metav1.ObjectMeta{Name: "block-sqlmap"},
		Spec: seclangv1alpha1.SecRuleSpec{
			Metadata: seclangv1alpha1.Metadata{ID: 100001, Phase: 1, Message: "scanner"},
			Chain: []seclangv1alpha1.ChainLink{{
				Targets:  []seclangv1alpha1.Target{{Name: seclangv1alpha1.REQUEST_HEADERS, Selector: "User-Agent"}},
				Operator: seclangv1alpha1.Operator{Name: seclangv1alpha1.Rx, Value: "(?i)sqlmap"},
				Actions: &seclangv1alpha1.Actions{
					Disruptive: &seclangv1alpha1.DisruptiveAction{Type: seclangv1alpha1.Deny},
					Data:       []seclangv1alpha1.DataAction{{Type: seclangv1alpha1.Status, Value: "403"}},
				},
			}},
		},
	}
	if _, err := v.ValidateCreate(t.Context(), ok); err != nil {
		t.Fatal(err)
	}
	bad := ok.DeepCopy()
	bad.Spec.Chain[0].Operator.Value = "("
	if _, err := v.ValidateCreate(t.Context(), bad); err == nil {
		t.Fatal("broken regex should fail Coraza parse")
	}
}

func TestV1Alpha1IncludeAndPolicy(t *testing.T) {
	inc := &seclangv1alpha1.Include{
		ObjectMeta: metav1.ObjectMeta{Name: "crs-setup"},
		Spec:       seclangv1alpha1.IncludeSpec{VirtualPath: "@crs-setup.conf"},
	}
	if _, err := (&IncludeV1Alpha1{}).ValidateCreate(t.Context(), inc); err != nil {
		t.Fatal(err)
	}
	glob := inc.DeepCopy()
	glob.Spec.VirtualPath = "@owasp_crs/*.conf"
	if _, err := (&IncludeV1Alpha1{}).ValidateCreate(t.Context(), glob); err != nil {
		t.Fatal(err)
	}
	both := inc.DeepCopy()
	both.Spec.ConfigMapRef = &seclangv1alpha1.ConfigMapKeyRef{Name: "c", Key: "a.conf"}
	if _, err := (&IncludeV1Alpha1{}).ValidateCreate(t.Context(), both); err == nil {
		t.Fatal("two sources")
	}

	policy := &seclangv1alpha1.SecPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "edge"},
		Spec: seclangv1alpha1.SecPolicySpec{
			DefaultActions: []seclangv1alpha1.DefaultAction{{Phase: 1, Actions: "log,auditlog,deny,status:403"}},
			PostDirectives: []string{"SecRuleRemoveById 942100"},
		},
	}
	if _, err := (&SecPolicyV1Alpha1{}).ValidateCreate(t.Context(), policy); err != nil {
		t.Fatal(err)
	}
	policy = policy.DeepCopy()
	policy.Spec.PostDirectives = []string{"NotADirective 1"}
	_, err := (&SecPolicyV1Alpha1{}).ValidateCreate(t.Context(), policy)
	if err == nil || !strings.Contains(err.Error(), "unknown directive") {
		t.Fatalf("post directive: %v", err)
	}
	policy = policy.DeepCopy()
	policy.Spec.PostDirectives = nil
	policy.Spec.DefaultActions = []seclangv1alpha1.DefaultAction{{Phase: 1, Actions: "not-an-action"}}
	if _, err := (&SecPolicyV1Alpha1{}).ValidateCreate(t.Context(), policy); err == nil {
		t.Fatal("bad default action")
	}
}
