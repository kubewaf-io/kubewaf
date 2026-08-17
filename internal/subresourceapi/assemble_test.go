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

package subresourceapi

import (
	"context"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	seclangv1beta1 "github.com/kubewaf-io/kubewaf/api/seclang/v1beta1"
	wafv1beta1 "github.com/kubewaf-io/kubewaf/api/waf/v1beta1"
)

func testScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := seclangv1beta1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	if err := wafv1beta1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	return s
}

func denySecRule(name, ns string, id int, needle string) *seclangv1beta1.SecRule {
	sr := &seclangv1beta1.SecRule{
		TypeMeta:   metav1.TypeMeta{APIVersion: "seclang.kubewaf.io/v1beta1", Kind: "SecRule"},
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: seclangv1beta1.SecRuleSpec{
			Metadata: &seclangv1beta1.SecRuleMetadata{
				OnlyPhaseMetadata: seclangv1beta1.OnlyPhaseMetadata{Phase: "2"},
				Id:                id,
			},
			Match: []seclangv1beta1.Match{{
				Collections: []seclangv1beta1.Collection{{Name: seclangv1beta1.ARGS}},
				Operator:    seclangv1beta1.Operator{Name: seclangv1beta1.Rx, Value: needle},
			}},
			Actions: &seclangv1beta1.SecRuleActions{
				DisruptiveAction: &seclangv1beta1.DisruptiveAction{Type: seclangv1beta1.Deny},
			},
		},
	}
	sr.SetGroupVersionKind(seclangv1beta1.GroupVersion.WithKind("SecRule"))
	return sr
}

func TestAssembleRuleSetIncludesMemberRules(t *testing.T) {
	scheme := testScheme(t)
	sr := denySecRule("block-sqli", "demo", 100001, "union")
	rs := &wafv1beta1.RuleSet{
		TypeMeta:   metav1.TypeMeta{APIVersion: "waf.kubewaf.io/v1beta1", Kind: "RuleSet"},
		ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "demo", UID: "rs-uid"},
		Spec: wafv1beta1.RuleSetSpec{
			RuleRefs: []wafv1beta1.RuleRef{{Kind: "SecRule", Name: "block-sqli"}},
		},
	}
	rs.SetGroupVersionKind(wafv1beta1.GroupVersion.WithKind("RuleSet"))
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(sr, rs).Build()
	s := NewServer(Config{Client: cl, Auth: AuthInsecureDev, SAR: AllowAllSAR{}})

	asm, df, uid, merr := s.assemble(context.Background(), &ProbeRoute{
		ParentKind: ParentRuleSet, Namespace: "demo", Name: "app",
	})
	if merr != nil {
		t.Fatalf("assemble: %+v", merr)
	}
	if uid != "rs-uid" {
		t.Fatalf("uid=%s", uid)
	}
	if df == nil || df.Files == nil {
		t.Fatal("expected data files result")
	}
	if asm.RulesLoaded != 1 {
		t.Fatalf("rulesLoaded=%d", asm.RulesLoaded)
	}
	if !strings.Contains(asm.Directives, "id:100001") {
		t.Fatalf("member rule missing:\n%s", asm.Directives)
	}
	if !strings.Contains(asm.Directives, "id:900990") {
		t.Fatalf("stamp missing:\n%s", asm.Directives)
	}
}

func TestAssembleWAFFlattensRuleSet(t *testing.T) {
	scheme := testScheme(t)
	sr := denySecRule("block-ua", "demo", 100002, "sqlmap")
	rs := &wafv1beta1.RuleSet{
		TypeMeta:   metav1.TypeMeta{APIVersion: "waf.kubewaf.io/v1beta1", Kind: "RuleSet"},
		ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "demo"},
		Spec: wafv1beta1.RuleSetSpec{
			RuleRefs: []wafv1beta1.RuleRef{{Kind: "SecRule", Name: "block-ua"}},
		},
	}
	rs.SetGroupVersionKind(wafv1beta1.GroupVersion.WithKind("RuleSet"))
	waf := &wafv1beta1.WAF{
		TypeMeta:   metav1.TypeMeta{APIVersion: "waf.kubewaf.io/v1beta1", Kind: "WAF"},
		ObjectMeta: metav1.ObjectMeta{Name: "edge", Namespace: "demo", UID: "waf-uid"},
		Spec: wafv1beta1.WAFSpec{
			RuleSetRefs: []wafv1beta1.RuleRef{{Kind: "RuleSet", Name: "app"}},
		},
	}
	waf.SetGroupVersionKind(wafv1beta1.GroupVersion.WithKind("WAF"))
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(sr, rs, waf).Build()
	s := NewServer(Config{Client: cl, Auth: AuthInsecureDev, SAR: AllowAllSAR{}})

	asm, _, uid, merr := s.assemble(context.Background(), &ProbeRoute{
		ParentKind: ParentWAF, Namespace: "demo", Name: "edge",
	})
	if merr != nil {
		t.Fatalf("assemble: %+v", merr)
	}
	if uid != "waf-uid" {
		t.Fatalf("uid=%s", uid)
	}
	if asm.RulesLoaded != 1 || !strings.Contains(asm.Directives, "id:100002") {
		t.Fatalf("flattened rule missing rules=%d\n%s", asm.RulesLoaded, asm.Directives)
	}
}

func TestAssembleWAFRejectsCRSPathA(t *testing.T) {
	scheme := testScheme(t)
	waf := &wafv1beta1.WAF{
		ObjectMeta: metav1.ObjectMeta{Name: "edge", Namespace: "demo"},
		Spec:       wafv1beta1.WAFSpec{CRSEnable: true},
	}
	waf.SetGroupVersionKind(wafv1beta1.GroupVersion.WithKind("WAF"))
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(waf).Build()
	s := NewServer(Config{Client: cl, Auth: AuthInsecureDev, SAR: AllowAllSAR{}})

	_, _, _, merr := s.assemble(context.Background(), &ProbeRoute{
		ParentKind: ParentWAF, Namespace: "demo", Name: "edge",
	})
	if merr == nil || merr.HTTPStatus != 422 || merr.Reason != ReasonCRSPathA {
		t.Fatalf("want 422 CRS Path A, got %+v", merr)
	}
}

func TestAssembleRuleSetMissingMemberIs422(t *testing.T) {
	scheme := testScheme(t)
	rs := &wafv1beta1.RuleSet{
		ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "demo"},
		Spec: wafv1beta1.RuleSetSpec{
			RuleRefs: []wafv1beta1.RuleRef{{Kind: "SecRule", Name: "missing"}},
		},
	}
	rs.SetGroupVersionKind(wafv1beta1.GroupVersion.WithKind("RuleSet"))
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(rs).Build()
	s := NewServer(Config{Client: cl, Auth: AuthInsecureDev, SAR: AllowAllSAR{}})

	_, _, _, merr := s.assemble(context.Background(), &ProbeRoute{
		ParentKind: ParentRuleSet, Namespace: "demo", Name: "app",
	})
	if merr == nil || merr.HTTPStatus != 422 || merr.Reason != ReasonReferencesUnresolved {
		t.Fatalf("want 422 ReferencesUnresolved, got %+v", merr)
	}
}

func TestAssembleEmptyRuleSetIsStampOnly(t *testing.T) {
	scheme := testScheme(t)
	rs := &wafv1beta1.RuleSet{
		ObjectMeta: metav1.ObjectMeta{Name: "empty", Namespace: "demo", UID: "empty-uid"},
	}
	rs.SetGroupVersionKind(wafv1beta1.GroupVersion.WithKind("RuleSet"))
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(rs).Build()
	s := NewServer(Config{Client: cl, Auth: AuthInsecureDev, SAR: AllowAllSAR{}})

	asm, _, _, merr := s.assemble(context.Background(), &ProbeRoute{
		ParentKind: ParentRuleSet, Namespace: "demo", Name: "empty",
	})
	if merr != nil {
		t.Fatalf("assemble: %+v", merr)
	}
	if asm.RulesLoaded != 0 {
		t.Fatalf("rulesLoaded=%d", asm.RulesLoaded)
	}
	if !strings.Contains(asm.Directives, "id:900990") {
		t.Fatalf("stamp missing:\n%s", asm.Directives)
	}
}
