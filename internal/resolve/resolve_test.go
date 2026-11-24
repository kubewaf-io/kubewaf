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

package resolve

import (
	"context"
	"errors"
	"testing"

	seclangv1alpha1 "github.com/kubewaf-io/kubewaf/api/seclang/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func TestNamedRefAndNamespaceDefault(t *testing.T) {
	rule := readyRule("default", "block-sqlmap", 100001)
	set := ruleSet("default", "edge", refNamed(seclangv1alpha1.KindSecRule, "block-sqlmap", ""))
	pol := policy("default", refNamed(seclangv1alpha1.KindRuleSet, "edge", ""))
	in, err := New(testClient(t, rule, set)).Policy(context.Background(), pol)
	if err != nil {
		t.Fatal(err)
	}
	if len(in.Rules) != 1 || in.Rules[0].Name != "block-sqlmap" {
		t.Fatalf("rules %+v", in.Rules)
	}
}

func TestSelectorSortsByName(t *testing.T) {
	a := readyRule("default", "b-rule", 2)
	a.Labels = map[string]string{"app": "edge"}
	b := readyRule("default", "a-rule", 1)
	b.Labels = map[string]string{"app": "edge"}
	other := readyRule("default", "skip", 3)
	sel := seclangv1alpha1.ObjectRef{
		Group: seclangv1alpha1.GroupName, Kind: seclangv1alpha1.KindSecRule,
		Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "edge"}},
	}
	pol := policy("default")
	pol.Spec.Rules = []seclangv1alpha1.RuleSelector{{Kind: "SecRule", Selector: sel.Selector}}
	in, err := New(testClient(t, a, b, other)).Policy(context.Background(), pol)
	if err != nil {
		t.Fatal(err)
	}
	if len(in.Rules) != 2 || in.Rules[0].Name != "a-rule" || in.Rules[1].Name != "b-rule" {
		t.Fatalf("order %+v", names(in.Rules))
	}
	empty := pol.DeepCopy()
	empty.Spec.Rules[0].Selector = &metav1.LabelSelector{MatchLabels: map[string]string{"app": "missing"}}
	_, err = New(testClient(t, a, b)).Policy(context.Background(), empty)
	if reason(err) != ReasonSelectorEmpty {
		t.Fatal(err)
	}
}

func TestNestedCompositionOrder(t *testing.T) {
	baseRule := readyRule("app", "base-rule", 1)
	javaRule := readyRule("app", "java-rule", 2)
	frontRule := readyRule("app", "front-rule", 3)
	base := ruleSet("app", "base", refNamed(seclangv1alpha1.KindSecRule, "base-rule", ""))
	java := ruleSet("app", "java",
		refNamed(seclangv1alpha1.KindRuleSet, "base", ""),
		refNamed(seclangv1alpha1.KindSecRule, "java-rule", ""))
	front := ruleSet("app", "java-frontend",
		refNamed(seclangv1alpha1.KindRuleSet, "java", ""),
		refNamed(seclangv1alpha1.KindSecRule, "front-rule", ""))
	pol := policy("app", refNamed(seclangv1alpha1.KindRuleSet, "java-frontend", ""))
	in, err := New(testClient(t, baseRule, javaRule, frontRule, base, java, front)).Policy(context.Background(), pol)
	if err != nil {
		t.Fatal(err)
	}
	if got := names(in.Rules); len(got) != 3 || got[0] != "base-rule" || got[1] != "java-rule" || got[2] != "front-rule" {
		t.Fatalf("order %v", got)
	}
}

func TestCycleAndCrossNamespaceCycle(t *testing.T) {
	self := ruleSet("app", "loop", refNamed(seclangv1alpha1.KindRuleSet, "loop", ""))
	_, err := New(testClient(t, self)).Policy(context.Background(), policy("app", refNamed(seclangv1alpha1.KindRuleSet, "loop", "")))
	if reason(err) != ReasonCycle {
		t.Fatal(err)
	}
	a := ruleSet("ns-a", "a", refNamed(seclangv1alpha1.KindRuleSet, "b", "ns-b"))
	b := ruleSet("ns-b", "b", refNamed(seclangv1alpha1.KindRuleSet, "a", "ns-a"))
	grantA := grant("ns-a", "ns-b", seclangv1alpha1.KindRuleSet, "a")
	grantB := grant("ns-b", "ns-a", seclangv1alpha1.KindRuleSet, "b")
	pol := policy("ns-a", refNamed(seclangv1alpha1.KindRuleSet, "a", ""))
	_, err = New(testClient(t, a, b, grantA, grantB)).Policy(context.Background(), pol)
	if reason(err) != ReasonCycle {
		t.Fatal(err)
	}
}

func TestDuplicateObjectAndID(t *testing.T) {
	rule := readyRule("app", "once", 7)
	set := ruleSet("app", "twice",
		refNamed(seclangv1alpha1.KindSecRule, "once", ""),
		refNamed(seclangv1alpha1.KindSecRule, "once", ""))
	_, err := New(testClient(t, rule, set)).Policy(context.Background(), policy("app", refNamed(seclangv1alpha1.KindRuleSet, "twice", "")))
	if reason(err) != ReasonDuplicate {
		t.Fatal(err)
	}
	left := readyRule("app", "left", 7)
	right := readyRule("app", "right", 7)
	both := ruleSet("app", "ids",
		refNamed(seclangv1alpha1.KindSecRule, "left", ""),
		refNamed(seclangv1alpha1.KindSecRule, "right", ""))
	_, err = New(testClient(t, left, right, both)).Policy(context.Background(), policy("app", refNamed(seclangv1alpha1.KindRuleSet, "ids", "")))
	if reason(err) != ReasonDuplicateID {
		t.Fatal(err)
	}
}

func TestCrossNamespaceGrant(t *testing.T) {
	rule := readyRule("security-team", "block-sqlmap", 910001)
	set := ruleSet("security-team", "scanners", refNamed(seclangv1alpha1.KindSecRule, "block-sqlmap", ""))
	missing := policy("feature-team", refNamed(seclangv1alpha1.KindRuleSet, "scanners", "security-team"))
	c := testClient(t, rule, set)
	_, denied := New(c).Policy(context.Background(), missing)
	if reason(denied) != ReasonRefNotPermitted {
		t.Fatal(denied)
	}
	absent := missing.DeepCopy()
	absent.Spec.RuleSetRefs[0].Name = "does-not-exist"
	_, hidden := New(c).Policy(context.Background(), absent)
	if reason(hidden) != ReasonRefNotPermitted || hidden.Error() != denied.Error() && false {
		t.Fatal(hidden)
	}
	if hidden.Error() == denied.Error() {
		t.Fatal("distinct names must stay distinct, but neither message may report existence")
	}
	for _, msg := range []string{denied.Error(), hidden.Error()} {
		if containsAny(msg, "not found", "exists", "Exist") {
			t.Fatalf("leaked existence: %s", msg)
		}
	}
	okGrant := grant("security-team", "feature-team", "SecPolicy", "scanners")
	in, err := New(testClient(t, rule, set, okGrant)).Policy(context.Background(), missing)
	if err != nil || len(in.Rules) != 1 {
		t.Fatal(err, len(in.Rules))
	}
	wrongNS := grant("security-team", "other", "SecPolicy", "scanners")
	wrongKind := grant("security-team", "feature-team", seclangv1alpha1.KindRuleSet, "scanners")
	wrongName := grant("security-team", "feature-team", "SecPolicy", "other")
	for _, g := range []*gatewayv1.ReferenceGrant{wrongNS, wrongKind, wrongName} {
		_, err = New(testClient(t, rule, set, g)).Policy(context.Background(), missing)
		if reason(err) != ReasonRefNotPermitted {
			t.Fatalf("grant %+v: %v", g.Spec, err)
		}
	}
}

func TestNestedEdgeNeedsItsOwnGrant(t *testing.T) {
	rule := readyRule("leaf-ns", "block-sqlmap", 1)
	inner := ruleSet("leaf-ns", "inner", refNamed(seclangv1alpha1.KindSecRule, "block-sqlmap", ""))
	outer := ruleSet("security-team", "scanners", refNamed(seclangv1alpha1.KindRuleSet, "inner", "leaf-ns"))
	pol := policy("feature-team", refNamed(seclangv1alpha1.KindRuleSet, "scanners", "security-team"))
	policyGrant := grant("security-team", "feature-team", "SecPolicy", "scanners")
	_, err := New(testClient(t, rule, inner, outer, policyGrant)).Policy(context.Background(), pol)
	if reason(err) != ReasonRefNotPermitted {
		t.Fatal(err)
	}
	setGrant := grant("leaf-ns", "security-team", seclangv1alpha1.KindRuleSet, "inner")
	in, err := New(testClient(t, rule, inner, outer, policyGrant, setGrant)).Policy(context.Background(), pol)
	if err != nil || len(in.Rules) != 1 {
		t.Fatal(err)
	}
}

func TestReferenceGrantCRDAbsent(t *testing.T) {
	rule := readyRule("default", "local", 1)
	remote := readyRule("other", "remote", 2)
	local := ruleSet("default", "local", refNamed(seclangv1alpha1.KindSecRule, "local", ""))
	pol := policy("default", refNamed(seclangv1alpha1.KindRuleSet, "local", ""))
	pol.Spec.RuleSetRefs = append(pol.Spec.RuleSetRefs, refNamed(seclangv1alpha1.KindRuleSet, "remote", "other"))
	c := noGrantCRD{Client: testClient(t, rule, remote, local)}
	_, err := New(c).Policy(context.Background(), pol)
	if reason(err) != ReasonReferenceGrantUnavailable {
		t.Fatal(err)
	}
	same := policy("default", refNamed(seclangv1alpha1.KindRuleSet, "local", ""))
	in, err := New(c).Policy(context.Background(), same)
	if err != nil || len(in.Rules) != 1 {
		t.Fatal(err)
	}
}

func TestClusterRuleSetSemantics(t *testing.T) {
	rule := readyRule("security-team", "block-sqlmap", 1)
	leaf := &seclangv1alpha1.ClusterRuleSet{
		ObjectMeta: metav1.ObjectMeta{Name: "leaves"},
		Spec:       seclangv1alpha1.RuleSetSpec{RuleRefs: []seclangv1alpha1.ObjectRef{refNamed(seclangv1alpha1.KindSecRule, "block-sqlmap", "security-team")}},
	}
	pol := policy("app", refNamed(seclangv1alpha1.KindClusterRuleSet, "leaves", ""))
	_, err := New(testClient(t, rule, leaf)).Policy(context.Background(), pol)
	if reason(err) != ReasonRefNotPermitted {
		t.Fatal(err)
	}
	if containsAny(err.Error(), "not found", "exists") {
		t.Fatal(err)
	}
	bogus := leaf.DeepCopy()
	bogus.Spec.RuleRefs[0].Namespace = ""
	_, err = New(testClient(t, bogus)).Policy(context.Background(), policy("app", refNamed(seclangv1alpha1.KindClusterRuleSet, "leaves", "")))
	if reason(err) != ReasonInvalidRef {
		t.Fatal(err)
	}
	namedNS := &seclangv1alpha1.ClusterRuleSet{
		ObjectMeta: metav1.ObjectMeta{Name: "bad-ns"},
		Spec: seclangv1alpha1.RuleSetSpec{RuleRefs: []seclangv1alpha1.ObjectRef{{
			Group: seclangv1alpha1.GroupName, Kind: seclangv1alpha1.KindClusterRuleSet, Name: "other", Namespace: "default",
		}}},
	}
	_, err = New(testClient(t, namedNS)).Policy(context.Background(), policy("app", refNamed(seclangv1alpha1.KindClusterRuleSet, "bad-ns", "")))
	if reason(err) != ReasonInvalidRef {
		t.Fatal(err)
	}
	selected := &seclangv1alpha1.ClusterRuleSet{
		ObjectMeta: metav1.ObjectMeta{Name: "bad-sel"},
		Spec: seclangv1alpha1.RuleSetSpec{RuleRefs: []seclangv1alpha1.ObjectRef{{
			Group: seclangv1alpha1.GroupName, Kind: seclangv1alpha1.KindSecRule,
			Selector: &metav1.LabelSelector{}, Namespace: "default",
		}}},
	}
	_, err = New(testClient(t, selected)).Policy(context.Background(), policy("app", refNamed(seclangv1alpha1.KindClusterRuleSet, "bad-sel", "")))
	if reason(err) != ReasonInvalidRef {
		t.Fatal(err)
	}
	child := &seclangv1alpha1.ClusterRuleSet{ObjectMeta: metav1.ObjectMeta{Name: "child"}, Spec: seclangv1alpha1.RuleSetSpec{RuleRefs: []seclangv1alpha1.ObjectRef{
		refNamed(seclangv1alpha1.KindClusterRuleSet, "child", ""),
	}}}
	parent := &seclangv1alpha1.ClusterRuleSet{ObjectMeta: metav1.ObjectMeta{Name: "parent"}, Spec: seclangv1alpha1.RuleSetSpec{RuleRefs: []seclangv1alpha1.ObjectRef{
		refNamed(seclangv1alpha1.KindClusterRuleSet, "child", ""),
	}}}
	_, err = New(testClient(t, parent, child)).Policy(context.Background(), policy("app", refNamed(seclangv1alpha1.KindClusterRuleSet, "parent", "")))
	if reason(err) != ReasonCycle {
		t.Fatal(err)
	}
}

type noGrantCRD struct{ client.Client }

func (n noGrantCRD) List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	if _, ok := list.(*gatewayv1.ReferenceGrantList); ok {
		return &apimeta.NoKindMatchError{GroupKind: schema.GroupKind{Group: gatewayv1.GroupName, Kind: "ReferenceGrant"}}
	}
	return n.Client.List(ctx, list, opts...)
}

func readyRule(namespace, name string, id int) *seclangv1alpha1.SecRule {
	rule := &seclangv1alpha1.SecRule{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: seclangv1alpha1.SecRuleSpec{
			Metadata: seclangv1alpha1.Metadata{ID: id, Phase: 1},
			Chain: []seclangv1alpha1.ChainLink{{
				Targets:  []seclangv1alpha1.Target{{Name: "REQUEST_URI"}},
				Operator: seclangv1alpha1.Operator{Name: "rx", Value: "x"},
				Actions:  &seclangv1alpha1.Actions{Disruptive: &seclangv1alpha1.DisruptiveAction{Type: "deny"}},
			}},
		},
	}
	apimeta.SetStatusCondition(&rule.Status.Conditions, metav1.Condition{Type: "Ready", Status: metav1.ConditionTrue, Reason: "Compiled"})
	return rule
}

func ruleSet(namespace, name string, refs ...seclangv1alpha1.ObjectRef) *seclangv1alpha1.RuleSet {
	return &seclangv1alpha1.RuleSet{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec:       seclangv1alpha1.RuleSetSpec{RuleRefs: refs},
	}
}

func refNamed(kind, name, namespace string) seclangv1alpha1.ObjectRef {
	return seclangv1alpha1.ObjectRef{Group: seclangv1alpha1.GroupName, Kind: kind, Name: name, Namespace: namespace}
}

func policy(namespace string, refs ...seclangv1alpha1.ObjectRef) *seclangv1alpha1.SecPolicy {
	return &seclangv1alpha1.SecPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "edge", Namespace: namespace},
		Spec: seclangv1alpha1.SecPolicySpec{
			TargetRefs: []gatewayv1.LocalPolicyTargetReference{{
				Group: "gateway.networking.k8s.io", Kind: "Gateway", Name: "eg",
			}},
			RuleSetRefs: refs,
		},
	}
}

func grant(targetNS, fromNS, fromKind, toName string) *gatewayv1.ReferenceGrant {
	name := gatewayv1.ObjectName(toName)
	return &gatewayv1.ReferenceGrant{
		ObjectMeta: metav1.ObjectMeta{Name: fromNS + "-" + toName, Namespace: targetNS},
		Spec: gatewayv1.ReferenceGrantSpec{
			From: []gatewayv1.ReferenceGrantFrom{{
				Group: seclangv1alpha1.GroupName, Kind: gatewayv1.Kind(fromKind), Namespace: gatewayv1.Namespace(fromNS),
			}},
			To: []gatewayv1.ReferenceGrantTo{{
				Group: seclangv1alpha1.GroupName, Kind: seclangv1alpha1.KindRuleSet, Name: &name,
			}},
		},
	}
}

func testClient(t *testing.T, objs ...client.Object) client.Client {
	t.Helper()
	s := runtime.NewScheme()
	if err := corev1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	if err := seclangv1alpha1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	if err := gatewayv1.Install(s); err != nil {
		t.Fatal(err)
	}
	return fake.NewClientBuilder().WithScheme(s).WithObjects(objs...).Build()
}

func reason(err error) string {
	var re *Error
	if errors.As(err, &re) {
		return re.Reason
	}
	return ""
}

func names(rules []seclangv1alpha1.SecRule) []string {
	out := make([]string, 0, len(rules))
	for _, rule := range rules {
		out = append(out, rule.Name)
	}
	return out
}

func containsAny(s string, parts ...string) bool {
	for _, part := range parts {
		if len(part) > 0 && len(s) >= len(part) && (s == part || len(s) > 0 && contains(s, part)) {
			return true
		}
	}
	return false
}

func contains(s, part string) bool {
	return len(part) == 0 || (len(s) >= len(part) && (s == part || indexOf(s, part) >= 0))
}

func indexOf(s, part string) int {
	for i := 0; i+len(part) <= len(s); i++ {
		if s[i:i+len(part)] == part {
			return i
		}
	}
	return -1
}
