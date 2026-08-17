package references2

import (
	"strings"
	"testing"

	"github.com/kubewaf-io/kubewaf/api/seclang/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
)

func mustUnstructured(t *testing.T, sr *v1beta1.SecRule) unstructured.Unstructured {
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

func TestCountSecLangObjects(t *testing.T) {
	objs := make([]unstructured.Unstructured, 0, 4)
	objs = append(objs,
		mustUnstructured(t, &v1beta1.SecRule{ObjectMeta: metav1.ObjectMeta{Name: "a", Namespace: "ns"}}),
		mustUnstructured(t, &v1beta1.SecRule{ObjectMeta: metav1.ObjectMeta{Name: "b", Namespace: "ns"}}),
	)
	u := unstructured.Unstructured{}
	u.SetKind("RuleSet")
	u.SetName("rs")
	objs = append(objs, u)
	sa := unstructured.Unstructured{}
	sa.SetKind("SecAction")
	sa.SetName("act")
	objs = append(objs, sa)

	rules, actions := CountSecLangObjects(objs)
	if rules != 2 || actions != 1 {
		t.Fatalf("rules=%d actions=%d", rules, actions)
	}
}

func TestGetSecRule_SortsByOrder(t *testing.T) {
	mk := func(name string, order int32, id int) *v1beta1.SecRule {
		return &v1beta1.SecRule{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "ns"},
			Spec: v1beta1.SecRuleSpec{
				Order: order,
				Metadata: &v1beta1.SecRuleMetadata{
					OnlyPhaseMetadata: v1beta1.OnlyPhaseMetadata{Phase: "1"},
					Id:                id,
				},
				Match: []v1beta1.Match{{
					AlwaysMatch: true,
				}},
				Actions: &v1beta1.SecRuleActions{
					NonDisruptive: []v1beta1.NonDisruptiveAction{
						{Type: v1beta1.NoLog},
					},
				},
			},
		}
	}

	// Intentionally reverse insertion order.
	objs := []unstructured.Unstructured{
		mustUnstructured(t, mk("c", 0, 942100)), // key=942100
		mustUnstructured(t, mk("a", 10, 100)),   // key=10
		mustUnstructured(t, mk("b", 5, 200)),    // key=5
		mustUnstructured(t, mk("z", 0, 0)),      // no id → last
	}

	rules, err := GetSecRule(objs)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 4 {
		t.Fatalf("got %d rules", len(rules))
	}
	// Expect order: b(5), a(10), c(942100), z(last)
	wantIDs := []string{"id:200", "id:100", "id:942100"}
	for i, want := range wantIDs {
		if !strings.Contains(rules[i], want) {
			t.Fatalf("rules[%d] missing %s:\n%s", i, want, rules[i])
		}
	}
	// last has no id in metadata (id 0) — rendered may omit id or have id:0
	if strings.Contains(rules[3], "id:942100") {
		t.Fatalf("last rule should not be 942100:\n%s", rules[3])
	}
}

func TestSecRuleSortKey(t *testing.T) {
	sr := &v1beta1.SecRule{
		Spec: v1beta1.SecRuleSpec{Order: 42},
	}
	if secRuleSortKey(sr) != 42 {
		t.Fatalf("order key")
	}
	sr.Spec.Order = 0
	sr.Status.RuleID = 99
	if secRuleSortKey(sr) != 99 {
		t.Fatalf("status key")
	}
}

func mustUnstructuredAction(t *testing.T, sa *v1beta1.SecAction) unstructured.Unstructured {
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

func TestGetSecLang_IncludesSecAction(t *testing.T) {
	sa := &v1beta1.SecAction{
		ObjectMeta: metav1.ObjectMeta{Name: "setup", Namespace: "ns"},
		Spec: v1beta1.SecActionSpec{
			Metadata: &v1beta1.SecRuleMetadata{
				OnlyPhaseMetadata: v1beta1.OnlyPhaseMetadata{Phase: "1"},
				Id:                100,
			},
			SecRuleActions: v1beta1.SecRuleActions{
				DisruptiveAction: &v1beta1.DisruptiveAction{Type: v1beta1.Pass},
				NonDisruptive: []v1beta1.NonDisruptiveAction{
					{Type: v1beta1.SetVar, Value: "tx.detection_paranoia_level=1"},
				},
			},
		},
	}
	sr := &v1beta1.SecRule{
		ObjectMeta: metav1.ObjectMeta{Name: "detect", Namespace: "ns"},
		Spec: v1beta1.SecRuleSpec{
			Order: 200,
			Metadata: &v1beta1.SecRuleMetadata{
				OnlyPhaseMetadata: v1beta1.OnlyPhaseMetadata{Phase: "2"},
				Id:                200,
			},
			Match: []v1beta1.Match{{AlwaysMatch: true}},
			Actions: &v1beta1.SecRuleActions{
				NonDisruptive: []v1beta1.NonDisruptiveAction{{Type: v1beta1.NoLog}},
			},
		},
	}
	// Insert SecRule first; SecAction id=100 should sort before order=200.
	objs := []unstructured.Unstructured{
		mustUnstructured(t, sr),
		mustUnstructuredAction(t, sa),
	}
	rules, err := GetSecLang(objs)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 2 {
		t.Fatalf("got %d rules: %v", len(rules), rules)
	}
	if !strings.Contains(rules[0], "id:100") {
		t.Fatalf("first should be SecAction id:100:\n%s", rules[0])
	}
	if !strings.Contains(rules[1], "id:200") {
		t.Fatalf("second should be SecRule id:200:\n%s", rules[1])
	}
}

func TestGetSecLang_UsesStatusSecRuleString(t *testing.T) {
	sa := &v1beta1.SecAction{
		ObjectMeta: metav1.ObjectMeta{Name: "cached", Namespace: "ns"},
		Spec: v1beta1.SecActionSpec{
			Metadata: &v1beta1.SecRuleMetadata{Id: 50},
		},
		Status: v1beta1.SecActionStatus{
			SecRuleString: "SecAction \"id:50,phase:1,pass,nolog\"\n",
		},
	}
	rules, err := GetSecLang([]unstructured.Unstructured{mustUnstructuredAction(t, sa)})
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 || !strings.Contains(rules[0], "id:50") {
		t.Fatalf("unexpected: %v", rules)
	}
}
