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

package probeassemble

import (
	"errors"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"

	seclangv1beta1 "github.com/kubewaf-io/kubewaf/api/seclang/v1beta1"
	wafv1beta1 "github.com/kubewaf-io/kubewaf/api/waf/v1beta1"
)

func TestDefaultRuleRefs(t *testing.T) {
	refs := DefaultRuleRefs("demo", []wafv1beta1.RuleRef{
		{Kind: "SecRule", Name: "r1"},
		{Kind: "RuleSet", Name: "rs", Namespace: "other"},
		{Kind: "", Name: "implied"},
	})
	if refs[0].Namespace != "demo" || refs[0].Group != groupSeclang || refs[0].Version != versionV1b1 {
		t.Fatalf("secrule defaults: %+v", refs[0])
	}
	if refs[1].Namespace != "other" || refs[1].Group != groupWAF {
		t.Fatalf("ruleset explicit ns: %+v", refs[1])
	}
	if refs[2].Kind != "RuleSet" || refs[2].Group != groupWAF || refs[2].Namespace != "demo" {
		t.Fatalf("empty kind: %+v", refs[2])
	}
}

func TestAssembleResolved_OrdersAndStamps(t *testing.T) {
	late := mustUnstructuredSecRule(t, sampleSecRule("late", 0, 942100, "late"))
	first := mustUnstructuredSecRule(t, sampleSecRule("first", 5, 200, "first"))
	setup := mustUnstructuredSecAction(t, sampleSecAction("setup", 100))

	asm, err := AssembleResolved([]unstructured.Unstructured{late, first, setup}, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if asm.RulesLoaded != 2 || asm.ActionsLoaded != 1 {
		t.Fatalf("counts rules=%d actions=%d", asm.RulesLoaded, asm.ActionsLoaded)
	}
	if !strings.Contains(asm.Directives, "SecRuleEngine On") {
		t.Fatalf("missing preamble: %s", asm.Directives)
	}
	if !strings.Contains(asm.Directives, "id:900990") {
		t.Fatalf("missing Path B stamp: %s", asm.Directives)
	}
	// setup (key 100) after first (order 5), before late (id 942100)
	idxSetup := strings.Index(asm.Directives, "id:100")
	idxFirst := strings.Index(asm.Directives, "id:200")
	idxLate := strings.Index(asm.Directives, "id:942100")
	if idxFirst < 0 || idxSetup < 0 || idxLate < 0 || idxFirst >= idxSetup || idxSetup >= idxLate {
		t.Fatalf("order first/setup/late not found:\n%s", asm.Directives)
	}
}

func TestAssembleResolved_UnresolvedIDs(t *testing.T) {
	sr := sampleSecRule("noid", 0, 0, "x")
	sr.Spec.Metadata.Id = 0
	u := mustUnstructuredSecRule(t, sr)
	_, err := AssembleResolved([]unstructured.Unstructured{u}, true, nil)
	if !errors.Is(err, ErrRuleIDsUnresolved) {
		t.Fatalf("want ErrRuleIDsUnresolved, got %v", err)
	}
}

func TestAssembleResolved_IgnoresRuleSetLeaves(t *testing.T) {
	rs := unstructured.Unstructured{}
	rs.SetAPIVersion("waf.kubewaf.io/v1beta1")
	rs.SetKind("RuleSet")
	rs.SetName("nested")
	sr := mustUnstructuredSecRule(t, sampleSecRule("only", 0, 100001, "hit"))
	asm, err := AssembleResolved([]unstructured.Unstructured{rs, sr}, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if asm.RulesLoaded != 1 || asm.ActionsLoaded != 0 {
		t.Fatalf("counts rules=%d actions=%d", asm.RulesLoaded, asm.ActionsLoaded)
	}
	if !strings.Contains(asm.Directives, "id:100001") {
		t.Fatalf("missing member rule: %s", asm.Directives)
	}
}

func TestAssembleResolved_WAFCRSTuning(t *testing.T) {
	pl := 2
	crs := CRSTuningFromWAF(&wafv1beta1.CRSTuning{
		ParanoiaLevel: &pl,
		RemoveByID:    []int{942100},
	})
	sr := mustUnstructuredSecRule(t, sampleSecRule("r", 0, 100001, "x"))
	asm, err := AssembleResolved([]unstructured.Unstructured{sr}, false, crs)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(asm.Directives, "tx.detection_paranoia_level=2") {
		t.Fatalf("missing crs setup: %s", asm.Directives)
	}
	if !strings.Contains(asm.Directives, "SecRuleRemoveById 942100") {
		t.Fatalf("missing exclusion: %s", asm.Directives)
	}
}

func TestPhraseListPolicyFromWAF(t *testing.T) {
	if PhraseListPolicyFromWAF("") != PhraseListPolicyFailClosed {
		t.Fatal("default")
	}
	if PhraseListPolicyFromWAF(wafv1beta1.PhraseListPolicyIgnoreUnknown) != PhraseListPolicyIgnoreUnknown {
		t.Fatal("ignore")
	}
}

func sampleSecRule(name string, order int32, id int, needle string) *seclangv1beta1.SecRule {
	return &seclangv1beta1.SecRule{
		TypeMeta:   metav1.TypeMeta{APIVersion: "seclang.kubewaf.io/v1beta1", Kind: "SecRule"},
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "ns"},
		Spec: seclangv1beta1.SecRuleSpec{
			Order: order,
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
}

func sampleSecAction(name string, id int) *seclangv1beta1.SecAction {
	return &seclangv1beta1.SecAction{
		TypeMeta:   metav1.TypeMeta{APIVersion: "seclang.kubewaf.io/v1beta1", Kind: "SecAction"},
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "ns"},
		Spec: seclangv1beta1.SecActionSpec{
			Metadata: &seclangv1beta1.SecRuleMetadata{
				OnlyPhaseMetadata: seclangv1beta1.OnlyPhaseMetadata{Phase: "1"},
				Id:                id,
			},
			SecRuleActions: seclangv1beta1.SecRuleActions{
				DisruptiveAction: &seclangv1beta1.DisruptiveAction{Type: seclangv1beta1.Pass},
				NonDisruptive: []seclangv1beta1.NonDisruptiveAction{
					{Type: seclangv1beta1.NoLog},
				},
			},
		},
	}
}

func mustUnstructuredSecRule(t *testing.T, sr *seclangv1beta1.SecRule) unstructured.Unstructured {
	t.Helper()
	m, err := runtime.DefaultUnstructuredConverter.ToUnstructured(sr)
	if err != nil {
		t.Fatal(err)
	}
	u := unstructured.Unstructured{Object: m}
	u.SetAPIVersion("seclang.kubewaf.io/v1beta1")
	u.SetKind("SecRule")
	return u
}

func mustUnstructuredSecAction(t *testing.T, sa *seclangv1beta1.SecAction) unstructured.Unstructured {
	t.Helper()
	m, err := runtime.DefaultUnstructuredConverter.ToUnstructured(sa)
	if err != nil {
		t.Fatal(err)
	}
	u := unstructured.Unstructured{Object: m}
	u.SetAPIVersion("seclang.kubewaf.io/v1beta1")
	u.SetKind("SecAction")
	return u
}
