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

package compile

import (
	"os"
	"strings"
	"testing"

	seclangv1alpha1 "github.com/kubewaf-io/kubewaf/api/seclang/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestEmitPlanExamples(t *testing.T) {
	sqlmap := &seclangv1alpha1.SecRule{
		ObjectMeta: metav1.ObjectMeta{Name: "block-sqlmap"},
		Spec: seclangv1alpha1.SecRuleSpec{
			Order: 10,
			Metadata: seclangv1alpha1.Metadata{
				ID: 100001, Phase: 1, Message: "scanner user-agent", Severity: "CRITICAL",
				Tags: []string{"scanner", "sqlmap"},
			},
			Chain: []seclangv1alpha1.ChainLink{{
				Targets:  []seclangv1alpha1.Target{{Name: seclangv1alpha1.REQUEST_HEADERS, Selector: "User-Agent"}},
				Operator: seclangv1alpha1.Operator{Name: seclangv1alpha1.Rx, Value: "(?i)sqlmap"},
				Actions: &seclangv1alpha1.Actions{
					Disruptive:    &seclangv1alpha1.DisruptiveAction{Type: seclangv1alpha1.Deny},
					Data:          []seclangv1alpha1.DataAction{{Type: seclangv1alpha1.Status, Value: "403"}},
					NonDisruptive: []seclangv1alpha1.NonDisruptiveAction{{Type: seclangv1alpha1.Log}, {Type: seclangv1alpha1.Auditlog}},
				},
			}},
		},
	}
	got, err := EmitRule(sqlmap)
	if err != nil {
		t.Fatal(err)
	}
	want := readGolden(t, "testdata/fixtures/sqlmap.seclang")
	if got != want {
		t.Fatalf("sqlmap\n got %s\nwant %s", got, want)
	}

	chain := &seclangv1alpha1.SecRule{
		ObjectMeta: metav1.ObjectMeta{Name: "post-without-type"},
		Spec: seclangv1alpha1.SecRuleSpec{
			Metadata:    seclangv1alpha1.Metadata{ID: 100010, Phase: 1, Message: "POST missing content type"},
			MarkerAfter: "END_METHOD",
			Chain: []seclangv1alpha1.ChainLink{
				{
					Targets:  []seclangv1alpha1.Target{{Name: seclangv1alpha1.REQUEST_METHOD}},
					Operator: seclangv1alpha1.Operator{Name: seclangv1alpha1.Rx, Value: "^POST$"},
					Actions: &seclangv1alpha1.Actions{
						Disruptive: &seclangv1alpha1.DisruptiveAction{Type: seclangv1alpha1.Deny},
						Data:       []seclangv1alpha1.DataAction{{Type: seclangv1alpha1.Status, Value: "403"}},
					},
				},
				{
					Targets:  []seclangv1alpha1.Target{{Name: seclangv1alpha1.REQUEST_HEADERS, Selector: "Content-Type", Count: true}},
					Operator: seclangv1alpha1.Operator{Name: seclangv1alpha1.Eq, Value: "0"},
				},
			},
		},
	}
	got, err = EmitRule(chain)
	if err != nil {
		t.Fatal(err)
	}
	if got != readGolden(t, "testdata/fixtures/chain.seclang") {
		t.Fatalf("chain\n%s", got)
	}

	action := &seclangv1alpha1.SecAction{
		ObjectMeta: metav1.ObjectMeta{Name: "paranoia-2"},
		Spec: seclangv1alpha1.SecActionSpec{
			Order: 1, Placement: seclangv1alpha1.PlacementBeforeCRS,
			Metadata: seclangv1alpha1.Metadata{ID: 900990, Phase: 1},
			Actions: &seclangv1alpha1.Actions{
				Disruptive: &seclangv1alpha1.DisruptiveAction{Type: seclangv1alpha1.Pass},
				NonDisruptive: []seclangv1alpha1.NonDisruptiveAction{
					{Type: seclangv1alpha1.Nolog},
					{Type: seclangv1alpha1.Setvar, Value: "tx.blocking_paranoia_level=2"},
					{Type: seclangv1alpha1.Setvar, Value: "tx.detection_paranoia_level=2"},
				},
			},
		},
	}
	got, err = EmitAction(action)
	if err != nil {
		t.Fatal(err)
	}
	if got != readGolden(t, "testdata/fixtures/paranoia.seclang") {
		t.Fatalf("action\n%s", got)
	}
}

func TestEmitIncludesAndTargets(t *testing.T) {
	virt, err := EmitInclude(&seclangv1alpha1.Include{ObjectMeta: metav1.ObjectMeta{Name: "crs-setup"}, Spec: seclangv1alpha1.IncludeSpec{VirtualPath: "@crs-setup.conf"}})
	if err != nil {
		t.Fatal(err)
	}
	if virt != readGolden(t, "testdata/fixtures/include-virtual.seclang") {
		t.Fatal(virt)
	}
	glob, err := EmitInclude(&seclangv1alpha1.Include{ObjectMeta: metav1.ObjectMeta{Name: "owasp"}, Spec: seclangv1alpha1.IncludeSpec{VirtualPath: "@owasp_crs/*.conf"}})
	if err != nil {
		t.Fatal(err)
	}
	if glob != readGolden(t, "testdata/fixtures/include-owasp.seclang") {
		t.Fatal(glob)
	}
	cm, err := EmitInclude(&seclangv1alpha1.Include{ObjectMeta: metav1.ObjectMeta{Name: "custom"}, Spec: seclangv1alpha1.IncludeSpec{ConfigMapRef: &seclangv1alpha1.ConfigMapKeyRef{Name: "rules", Key: "custom.conf"}}})
	if err != nil {
		t.Fatal(err)
	}
	if cm != readGolden(t, "testdata/fixtures/include-configmap.seclang") {
		t.Fatal(cm)
	}
	if _, err := EmitInclude(&seclangv1alpha1.Include{Spec: seclangv1alpha1.IncludeSpec{VirtualPath: "@a/*.conf/*/b"}}); err == nil {
		t.Fatal("two globs")
	}
	if _, err := EmitInclude(&seclangv1alpha1.Include{Spec: seclangv1alpha1.IncludeSpec{VirtualPath: "crs-setup.conf"}}); err == nil {
		t.Fatal("missing @")
	}
	if _, err := EmitInclude(&seclangv1alpha1.Include{
		Spec: seclangv1alpha1.IncludeSpec{VirtualPath: "@crs-setup.conf", ConfigMapRef: &seclangv1alpha1.ConfigMapKeyRef{Name: "a", Key: "b"}},
	}); err == nil {
		t.Fatal("both sources")
	}

	cases := []struct {
		name string
		rule seclangv1alpha1.SecRule
		file string
	}{
		{"selector", ruleWithTarget(seclangv1alpha1.Target{Name: seclangv1alpha1.REQUEST_HEADERS, Selector: "User-Agent"}), "target-selector.seclang"},
		{"count", ruleWithTarget(seclangv1alpha1.Target{Name: seclangv1alpha1.ARGS, Count: true}, seclangv1alpha1.Operator{Name: seclangv1alpha1.Eq, Value: "0"}), "target-count.seclang"},
		{"exclude", ruleWithTarget(seclangv1alpha1.Target{Name: seclangv1alpha1.ARGS, Selector: "password", Exclude: true}), "target-exclude.seclang"},
		{"regex", ruleWithTarget(seclangv1alpha1.Target{Name: seclangv1alpha1.ARGS, Selector: "/^id_/", Exclude: true}), "target-regex.seclang"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := EmitRule(&tc.rule)
			if err != nil {
				t.Fatal(err)
			}
			if got != readGolden(t, "testdata/fixtures/"+tc.file) {
				t.Fatalf("got %s", got)
			}
		})
	}
	both := ruleWithTarget(seclangv1alpha1.Target{Name: seclangv1alpha1.ARGS, Exclude: true, Count: true})
	if _, err := EmitRule(&both); err == nil {
		t.Fatal("exclude and count")
	}
}

func TestEmitAliasesAndCtl(t *testing.T) {
	rule := baseRule()
	rule.Spec.Chain[0].Operator.Name = seclangv1alpha1.Pmf
	rule.Spec.Chain[0].Operator.Value = "scanners.data"
	got, err := EmitRule(&rule)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, `"@pmFromFile scanners.data"`) {
		t.Fatal(got)
	}
	rule = baseRule()
	rule.Spec.Chain[0].Transformations = []seclangv1alpha1.Transformation{seclangv1alpha1.NormalizePath}
	got, err = EmitRule(&rule)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "t:normalisePath") || strings.Contains(got, "t:normalizePath") {
		t.Fatal(got)
	}
	rule = baseRule()
	rule.Spec.Chain[0].Actions = &seclangv1alpha1.Actions{NonDisruptive: []seclangv1alpha1.NonDisruptiveAction{{Type: seclangv1alpha1.SanitizeArg, Value: "password"}}}
	got, err = EmitRule(&rule)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "sanitiseArg:password") {
		t.Fatal(got)
	}
	rule = baseRule()
	rule.Spec.Chain[0].Actions = &seclangv1alpha1.Actions{NonDisruptive: []seclangv1alpha1.NonDisruptiveAction{{Type: seclangv1alpha1.Ctl, Value: "notAnAction=On"}}}
	if _, err := EmitRule(&rule); err == nil {
		t.Fatal("bad ctl")
	}
	rule = baseRule()
	rule.Spec.Chain[0].Actions = &seclangv1alpha1.Actions{Flow: []seclangv1alpha1.FlowAction{{Type: seclangv1alpha1.Chain, Value: "1"}}}
	if _, err := EmitRule(&rule); err == nil {
		t.Fatal("user chain")
	}
}

func baseRule() seclangv1alpha1.SecRule {
	return ruleWithTarget(seclangv1alpha1.Target{Name: seclangv1alpha1.REQUEST_URI})
}

func ruleWithTarget(t seclangv1alpha1.Target, op ...seclangv1alpha1.Operator) seclangv1alpha1.SecRule {
	operator := seclangv1alpha1.Operator{Name: seclangv1alpha1.Rx, Value: "x"}
	if len(op) == 1 {
		operator = op[0]
	}
	return seclangv1alpha1.SecRule{
		ObjectMeta: metav1.ObjectMeta{Name: "r"},
		Spec: seclangv1alpha1.SecRuleSpec{
			Metadata: seclangv1alpha1.Metadata{ID: 100001, Phase: 1},
			Chain: []seclangv1alpha1.ChainLink{{
				Targets:  []seclangv1alpha1.Target{t},
				Operator: operator,
				Actions:  &seclangv1alpha1.Actions{Disruptive: &seclangv1alpha1.DisruptiveAction{Type: seclangv1alpha1.Pass}},
			}},
		},
	}
}

func readGolden(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimRight(string(b), "\n")
}
