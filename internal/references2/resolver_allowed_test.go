package references2

import (
	"context"
	"testing"

	wafv1beta1 "github.com/kubewaf-io/kubewaf/api/waf/v1beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func TestAllowedObject_RuleSetSameNamespace(t *testing.T) {
	r := &RuleRefResolver{Client: fake.NewClientBuilder().Build()}
	src := &wafv1beta1.RuleSet{ObjectMeta: metav1.ObjectMeta{Name: "rs", Namespace: "a"}}
	tgt := &unstructured.Unstructured{}
	tgt.SetName("rule")
	tgt.SetNamespace("a")
	if err := r.allowedObject(context.Background(), tgt, src); err != nil {
		t.Fatalf("same ns should allow: %v", err)
	}
}

func TestAllowedObject_RuleSetDefaultSameDeniesCrossNS(t *testing.T) {
	r := &RuleRefResolver{Client: fake.NewClientBuilder().Build()}
	src := &wafv1beta1.RuleSet{ObjectMeta: metav1.ObjectMeta{Name: "rs", Namespace: "a"}}
	// AllowedRules default From=Same (nil From)
	tgt := &unstructured.Unstructured{}
	tgt.SetName("rule")
	tgt.SetNamespace("b")
	err := r.allowedObject(context.Background(), tgt, src)
	if err == nil {
		t.Fatal("expected cross-ns deny with allowedRules.from=Same")
	}
}

func TestAllowedObject_RuleSetFromAll(t *testing.T) {
	r := &RuleRefResolver{Client: fake.NewClientBuilder().Build()}
	from := gatewayv1.NamespacesFromAll
	src := &wafv1beta1.RuleSet{
		ObjectMeta: metav1.ObjectMeta{Name: "rs", Namespace: "a"},
		Spec: wafv1beta1.RuleSetSpec{
			AllowedRules: wafv1beta1.RuleNamespaces{From: &from},
		},
	}
	tgt := &unstructured.Unstructured{}
	tgt.SetName("rule")
	tgt.SetNamespace("b")
	if err := r.allowedObject(context.Background(), tgt, src); err != nil {
		t.Fatalf("From=All should allow: %v", err)
	}
}

func TestAllowedObject_RuleSetFromSelector(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "team-b",
			Labels: map[string]string{"share-rules": "true"},
		},
	}
	r := &RuleRefResolver{Client: fake.NewClientBuilder().WithScheme(scheme).WithObjects(ns).Build()}
	from := gatewayv1.NamespacesFromSelector
	src := &wafv1beta1.RuleSet{
		ObjectMeta: metav1.ObjectMeta{Name: "rs", Namespace: "a"},
		Spec: wafv1beta1.RuleSetSpec{
			AllowedRules: wafv1beta1.RuleNamespaces{
				From: &from,
				Selector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"share-rules": "true"},
				},
			},
		},
	}
	tgt := &unstructured.Unstructured{}
	tgt.SetName("rule")
	tgt.SetNamespace("team-b")
	if err := r.allowedObject(context.Background(), tgt, src); err != nil {
		t.Fatalf("selector match should allow: %v", err)
	}

	tgt.SetNamespace("other")
	otherNS := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "other"}}
	r.Client = fake.NewClientBuilder().WithScheme(scheme).WithObjects(ns, otherNS).Build()
	if err := r.allowedObject(context.Background(), tgt, src); err == nil {
		t.Fatal("selector miss should deny")
	}
}

func TestAllowedObject_WAFAllowsCrossNSWithoutPolicy(t *testing.T) {
	r := &RuleRefResolver{Client: fake.NewClientBuilder().Build()}
	src := &wafv1beta1.WAF{ObjectMeta: metav1.ObjectMeta{Name: "w", Namespace: "app"}}
	tgt := &unstructured.Unstructured{}
	tgt.SetName("platform-rs")
	tgt.SetNamespace("platform")
	if err := r.allowedObject(context.Background(), tgt, src); err != nil {
		t.Fatalf("WAF without allowedRules should allow cross-ns RuleSet attach: %v", err)
	}
}

func TestApplyRuleRefDefaults(t *testing.T) {
	got := applyRuleRefDefaults(wafv1beta1.RuleRef{Kind: "SecRule", Name: "r"}, "demo")
	if got.Namespace != "demo" || got.Group != "seclang.kubewaf.io" || got.Version != "v1beta1" {
		t.Fatalf("%+v", got)
	}
	got = applyRuleRefDefaults(wafv1beta1.RuleRef{Kind: "RuleSet", Name: "rs", Namespace: "other"}, "demo")
	if got.Namespace != "other" || got.Group != "waf.kubewaf.io" {
		t.Fatalf("%+v", got)
	}
}
