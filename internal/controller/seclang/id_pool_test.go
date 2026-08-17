/*
Copyright 2025 Buzz-IT GmbH.
*/
package seclang

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	seclangv1beta1 "github.com/kubewaf-io/kubewaf/api/seclang/v1beta1"
)

func TestAllocateIDs_AutoAndSpec(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = seclangv1beta1.AddToScheme(scheme)
	cl := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&seclangv1beta1.SecRuleIDPool{}).
		Build()

	sr := &seclangv1beta1.SecRule{
		ObjectMeta: metav1.ObjectMeta{Name: "r1", Namespace: "ns"},
		Spec: seclangv1beta1.SecRuleSpec{
			SecRules: []seclangv1beta1.SecLangSecRule{
				{Metadata: &seclangv1beta1.SecRuleMetadata{
					OnlyPhaseMetadata: seclangv1beta1.OnlyPhaseMetadata{Phase: "1"},
				}}, // auto
				{Metadata: &seclangv1beta1.SecRuleMetadata{
					OnlyPhaseMetadata: seclangv1beta1.OnlyPhaseMetadata{Phase: "2"},
					Id:                941100,
				}}, // fixed
			},
		},
	}
	used := map[int]struct{}{}
	assigned, primary, src, err := allocateIDs(context.Background(), cl, sr, used)
	if err != nil {
		t.Fatal(err)
	}
	if len(assigned) != 2 {
		t.Fatalf("assigned=%v", assigned)
	}
	if assigned[0] < seclangv1beta1.DefaultIDPoolMin {
		t.Fatalf("auto id too small: %d", assigned[0])
	}
	if assigned[1] != 941100 {
		t.Fatalf("fixed id=%d", assigned[1])
	}
	if primary != assigned[0] {
		t.Fatalf("primary=%d", primary)
	}
	if src != seclangv1beta1.IDSourceMixed {
		t.Fatalf("source=%s", src)
	}

	// Reuse sticky
	sr.Status.AssignedIDs = assigned
	sr.Status.RuleID = primary
	used2 := map[int]struct{}{941100: {}, assigned[0]: {}}
	assigned2, _, src2, err := allocateIDs(context.Background(), cl, sr, used2)
	if err != nil {
		t.Fatal(err)
	}
	if assigned2[0] != assigned[0] || assigned2[1] != 941100 {
		t.Fatalf("reuse failed: %v vs %v", assigned2, assigned)
	}
	if src2 != seclangv1beta1.IDSourceMixed {
		t.Fatalf("source=%s", src2)
	}
}

func TestAllocateIDs_SingleRuleForm(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = seclangv1beta1.AddToScheme(scheme)
	cl := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&seclangv1beta1.SecRuleIDPool{}).
		Build()

	sr := &seclangv1beta1.SecRule{
		ObjectMeta: metav1.ObjectMeta{Name: "single", Namespace: "ns"},
		Spec: seclangv1beta1.SecRuleSpec{
			Order: 1,
			Metadata: &seclangv1beta1.SecRuleMetadata{
				OnlyPhaseMetadata: seclangv1beta1.OnlyPhaseMetadata{Phase: "1"},
			},
			Match: []seclangv1beta1.Match{{AlwaysMatch: true}},
		},
	}
	assigned, primary, src, err := allocateIDs(context.Background(), cl, sr, map[int]struct{}{})
	if err != nil {
		t.Fatal(err)
	}
	if len(assigned) != 1 || assigned[0] < seclangv1beta1.DefaultIDPoolMin {
		t.Fatalf("assigned=%v", assigned)
	}
	if primary != assigned[0] || src != seclangv1beta1.IDSourceAuto {
		t.Fatalf("primary=%d src=%s", primary, src)
	}
}

func TestSyncSecRuleLabels_Tags(t *testing.T) {
	sr := &seclangv1beta1.SecRule{
		ObjectMeta: metav1.ObjectMeta{Name: "r", Namespace: "ns"},
		Spec: seclangv1beta1.SecRuleSpec{
			Order: 42,
			Metadata: &seclangv1beta1.SecRuleMetadata{
				OnlyPhaseMetadata: seclangv1beta1.OnlyPhaseMetadata{Phase: "1"},
				Tags:              []string{"OWASP_CRS", "attack-xss"},
			},
			Match: []seclangv1beta1.Match{{AlwaysMatch: true}},
		},
	}
	if !syncSecRuleLabels(sr, 100001, seclangv1beta1.IDSourceAuto) {
		t.Fatal("expected label change")
	}
	if sr.Labels[seclangv1beta1.LabelID] != "100001" {
		t.Fatalf("id label=%v", sr.Labels)
	}
	if sr.Labels[seclangv1beta1.LabelPhase] != "1" {
		t.Fatalf("phase=%v", sr.Labels)
	}
	if sr.Labels[seclangv1beta1.LabelOrder] != "42" {
		t.Fatalf("order label=%v", sr.Labels)
	}
	key := seclangv1beta1.TagToLabelKey("OWASP_CRS")
	if sr.Labels[key] != "true" {
		t.Fatalf("tag label missing: %v", sr.Labels)
	}
	if sr.Annotations[seclangv1beta1.AnnotationAssignedID] != "100001" {
		t.Fatalf("sticky ann=%v", sr.Annotations)
	}
}
