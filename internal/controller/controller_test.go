package controller

import (
	"testing"

	seclangv1beta1 "github.com/kubewaf-io/kubewaf/api/seclang/v1beta1"
	wafv1beta1 "github.com/kubewaf-io/kubewaf/api/waf/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestOwnerKindOf(t *testing.T) {
	rs := &wafv1beta1.RuleSet{ObjectMeta: metav1.ObjectMeta{Name: "x", Namespace: "ns"}}
	if k := ownerKindOf(rs); k != "RuleSet" {
		t.Fatalf("got %q", k)
	}
	w := &wafv1beta1.WAF{ObjectMeta: metav1.ObjectMeta{Name: "w", Namespace: "ns"}}
	if k := ownerKindOf(w); k != "WAF" {
		t.Fatalf("got %q", k)
	}
}

func TestFilterRefs(t *testing.T) {
	refs := []seclangv1beta1.RuleSetRef{
		{Kind: "RuleSet", Name: "a", Namespace: "ns"},
		{Kind: "RuleSet", Name: "b", Namespace: "ns"},
		{Kind: "WAF", Name: "a", Namespace: "ns"},
	}
	out, removed := filterRefs(refs, "RuleSet", "a", "ns")
	if !removed || len(out) != 2 {
		t.Fatalf("removed=%v out=%v", removed, out)
	}
	out, removed = filterRefs(refs, "RuleSet", "missing", "ns")
	if removed || len(out) != 3 {
		t.Fatalf("expected no change")
	}
}

func TestMatchesOwner_EmptyKind(t *testing.T) {
	ref := seclangv1beta1.RuleSetRef{Name: "rs", Namespace: "ns", Kind: "RuleSet"}
	if !matchesOwner(ref, "", "rs", "ns") {
		t.Fatal("empty owner kind should match name+ns")
	}
}
