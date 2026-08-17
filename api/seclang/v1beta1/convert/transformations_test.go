/*
Copyright 2025 Buzz-IT GmbH.
*/
package convert

import (
	"strings"
	"testing"

	types "github.com/coreruleset/crslang/types"
	v1beta1 "github.com/kubewaf-io/kubewaf/api/seclang/v1beta1"
)

func TestFromCRSTransformation_AmericanNormalizePathAliases(t *testing.T) {
	// CRS parses American spellings into crslang enum values that String() as
	// normalizePath / normalizePathWin (unexported constants — reach via AddTransformation).
	cases := []struct {
		crsName string
		want    v1beta1.Transformation
	}{
		{"normalizePath", v1beta1.NormalisePath},
		{"normalizePathWin", v1beta1.NormalisePathWin},
		{"normalisePath", v1beta1.NormalisePath},
		{"normalisePathWin", v1beta1.NormalisePathWin},
		{"urlDecodeUni", v1beta1.UrlDecodeUni},
		{"none", v1beta1.None},
	}
	for _, tc := range cases {
		t.Run(tc.crsName, func(t *testing.T) {
			var bag types.Transformations
			if err := bag.AddTransformation(tc.crsName); err != nil {
				t.Fatalf("AddTransformation(%q): %v", tc.crsName, err)
			}
			if len(bag.Transformations) != 1 {
				t.Fatalf("len=%d", len(bag.Transformations))
			}
			got, err := FromCRSTransformation(bag.Transformations[0])
			if err != nil {
				t.Fatalf("FromCRSTransformation: %v", err)
			}
			if got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
}

func TestFromCRSTransformation_UnknownErrors(t *testing.T) {
	_, err := FromCRSTransformation(types.UnknownTransformation)
	if err == nil {
		t.Fatal("expected error for UnknownTransformation")
	}
}

func TestToCRSTransformation_RejectsEmptyAndUnknown(t *testing.T) {
	for _, bad := range []v1beta1.Transformation{"", v1beta1.UnknownTransformation, "unknown", "notARealTransform"} {
		if _, err := ToCRSTransformation(bad); err == nil {
			t.Fatalf("expected error for %q", bad)
		}
	}
}

func TestToCRSTransformation_AmericanAPIAliases(t *testing.T) {
	for _, tc := range []struct {
		in   v1beta1.Transformation
		want string
	}{
		{"normalizePath", "normalisePath"},
		{"normalizePathWin", "normalisePathWin"},
		{v1beta1.NormalisePath, "normalisePath"},
		{v1beta1.NormalisePathWin, "normalisePathWin"},
	} {
		got, err := ToCRSTransformation(tc.in)
		if err != nil {
			t.Fatalf("%q: %v", tc.in, err)
		}
		if got.String() != tc.want {
			t.Fatalf("%q: got %q want %q", tc.in, got.String(), tc.want)
		}
	}
}

func TestConvertCrsRule_NormalizePathWinRoundTrip(t *testing.T) {
	// Simulate CRS 930120: t:none,t:utf8toUnicode,t:urlDecodeUni,t:normalizePathWin
	var bag types.Transformations
	for _, name := range []string{"none", "utf8toUnicode", "urlDecodeUni", "normalizePathWin"} {
		if err := bag.AddTransformation(name); err != nil {
			t.Fatal(err)
		}
	}
	src := types.RuleWithCondition{
		Kind: types.RuleKind,
		Metadata: types.SecRuleMetadata{
			OnlyPhaseMetadata: types.OnlyPhaseMetadata{Phase: "2"},
			Id:                930120,
			Msg:               "OS File Access Attempt",
		},
		Conditions: []types.Condition{{
			Collections: []types.Collection{{Name: types.ARGS}},
			Operator: types.Operator{
				Name:  types.PmFromFile,
				Value: "lfi-os-files.data",
			},
			Transformations: bag,
		}},
	}
	legacy, err := ConvertCrsRule(src, "")
	if err != nil {
		t.Fatalf("ConvertCrsRule: %v", err)
	}
	if len(legacy.Conditions) != 1 {
		t.Fatalf("conditions=%d", len(legacy.Conditions))
	}
	ts := legacy.Conditions[0].Transformations
	wantLast := v1beta1.NormalisePathWin
	if len(ts) != 4 || ts[3] != wantLast {
		t.Fatalf("transforms=%v want last %q", ts, wantLast)
	}
	// Empty string must never appear (prior bug).
	for i, tr := range ts {
		if tr == "" || tr == v1beta1.UnknownTransformation {
			t.Fatalf("transform[%d]=%q is poison", i, tr)
		}
	}

	// Round-trip to SecLang: must not contain t:unknown.
	spec, err := ConvertCrsRuleToSingleForm(src, "")
	if err != nil {
		t.Fatal(err)
	}
	sr := v1beta1.SecRule{Spec: spec}
	dirs, err := ConvertSecRule(sr)
	if err != nil {
		t.Fatalf("ConvertSecRule: %v", err)
	}
	out := ConvertToSecLangString(dirs)
	if strings.Contains(out, "t:unknown") {
		t.Fatalf("rendered t:unknown:\n%s", out)
	}
	if !strings.Contains(out, "t:normalisePathWin") && !strings.Contains(out, "t:normalizePathWin") {
		t.Fatalf("expected path-normalize transform in:\n%s", out)
	}
}

func TestConvertSecRule_EmptyTransformNeverReady(t *testing.T) {
	// Existing poisoned CRs store transformations: ["", ...] or omit mapping.
	sr := v1beta1.SecRule{
		Spec: v1beta1.SecRuleSpec{
			Metadata: &v1beta1.SecRuleMetadata{
				OnlyPhaseMetadata: v1beta1.OnlyPhaseMetadata{Phase: "2"},
				Id:                930120,
			},
			Match: []v1beta1.Match{{
				Collections: []v1beta1.Collection{{Name: v1beta1.ARGS}},
				Operator: v1beta1.Operator{
					Name:  v1beta1.PmFromFile,
					Value: "lfi-os-files.data",
				},
				Transformations: []v1beta1.Transformation{
					v1beta1.None,
					v1beta1.Utf8toUnicode,
					v1beta1.UrlDecodeUni,
					"", // poison from old CRS import
				},
			}},
			Actions: &v1beta1.SecRuleActions{
				DisruptiveAction: &v1beta1.DisruptiveAction{Type: v1beta1.Block},
			},
		},
	}
	_, err := ConvertSecRule(sr)
	if err == nil {
		t.Fatal("expected ConvertSecRule to reject empty transformation")
	}
	if !strings.Contains(err.Error(), "empty") && !strings.Contains(err.Error(), "transformation") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestConvertSecRule_UnknownTransformationRejected(t *testing.T) {
	sr := v1beta1.SecRule{
		Spec: v1beta1.SecRuleSpec{
			Metadata: &v1beta1.SecRuleMetadata{
				OnlyPhaseMetadata: v1beta1.OnlyPhaseMetadata{Phase: "2"},
				Id:                100001,
			},
			Match: []v1beta1.Match{{
				Collections: []v1beta1.Collection{{Name: v1beta1.ARGS}},
				Operator:    v1beta1.Operator{Name: v1beta1.Rx, Value: "x"},
				Transformations: []v1beta1.Transformation{
					v1beta1.UnknownTransformation,
				},
			}},
			Actions: &v1beta1.SecRuleActions{
				DisruptiveAction: &v1beta1.DisruptiveAction{Type: v1beta1.Pass},
			},
		},
	}
	if _, err := ConvertSecRule(sr); err == nil {
		t.Fatal("expected reject unknownTransformation")
	}
}

func TestValidateAPITransformations(t *testing.T) {
	if err := ValidateAPITransformations(nil); err != nil {
		t.Fatal(err)
	}
	if err := ValidateAPITransformations([]v1beta1.Transformation{v1beta1.None, v1beta1.NormalisePath}); err != nil {
		t.Fatal(err)
	}
	if err := ValidateAPITransformations([]v1beta1.Transformation{""}); err == nil {
		t.Fatal("expected error for empty")
	}
}
