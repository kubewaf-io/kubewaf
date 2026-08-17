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

func TestConvertCrsRuleToSingleForm_ChainAndMarker(t *testing.T) {
	// Parent with chain link.
	child := types.RuleWithCondition{
		Kind: types.RuleKind,
		Conditions: []types.Condition{{
			Collections: []types.Collection{{Name: types.TX, Arguments: []string{"0"}}},
			Operator:    types.Operator{Name: types.Rx, Value: ".+"},
		}},
	}
	parent := types.RuleWithCondition{
		Kind: types.RuleKind,
		Metadata: types.SecRuleMetadata{
			OnlyPhaseMetadata: types.OnlyPhaseMetadata{Phase: "2"},
			Id:                942130,
			Msg:               "SQLi chain",
		},
		Conditions: []types.Condition{{
			Collections: []types.Collection{{Name: types.ARGS}},
			Operator:    types.Operator{Name: types.Rx, Value: "(?i)select"},
		}},
		ChainedRule: &child,
	}
	// Attach chain action on parent via API convert path is not needed —
	// ConvertCrsRuleToSingleForm walks ChainedRule.
	spec, err := ConvertCrsRuleToSingleForm(parent, "END-SQLI")
	if err != nil {
		t.Fatal(err)
	}
	if len(spec.Match) != 2 {
		t.Fatalf("match=%d", len(spec.Match))
	}
	if spec.Metadata == nil || spec.Metadata.Id != 942130 {
		t.Fatalf("metadata=%v", spec.Metadata)
	}
	if spec.Order != 942130 {
		t.Fatalf("order=%d", spec.Order)
	}
	if spec.MarkerAfter != "END-SQLI" {
		t.Fatalf("marker=%s", spec.MarkerAfter)
	}
	// Render via SecRule CR.
	sr := v1beta1.SecRule{Spec: spec}
	dirs, err := ConvertSecRule(sr)
	if err != nil {
		t.Fatal(err)
	}
	out := ConvertToSecLangString(dirs)
	if !strings.Contains(out, "chain") || !strings.Contains(out, "SecMarker") {
		t.Fatalf("expected chain+marker:\n%s", out)
	}
}

func TestConvertCrsRule_AlwaysMatchGetsUnconditionalMatch(t *testing.T) {
	src := types.RuleWithCondition{
		Kind: types.RuleKind,
		Metadata: types.SecRuleMetadata{
			OnlyPhaseMetadata: types.OnlyPhaseMetadata{Phase: "1"},
			Id:                901200,
		},
		Conditions: []types.Condition{{
			AlwaysMatch: true,
			// crslang leaves operator empty / unknown for SecAction.
			Operator: types.Operator{Name: types.UnknownOperator},
		}},
		Actions: types.SeclangActions{},
	}
	got, err := ConvertCrsRule(src, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Conditions) != 1 {
		t.Fatalf("conditions=%d", len(got.Conditions))
	}
	c := got.Conditions[0]
	if !c.AlwaysMatch {
		t.Fatal("expected AlwaysMatch")
	}
	if c.Operator.Name != v1beta1.UnconditionalMatch {
		t.Fatalf("operator=%q want unconditionalMatch", c.Operator.Name)
	}
}

func TestConvertCrsRule_PreservesTransformations(t *testing.T) {
	src := types.RuleWithCondition{
		Kind: types.RuleKind,
		Metadata: types.SecRuleMetadata{
			OnlyPhaseMetadata: types.OnlyPhaseMetadata{Phase: "2"},
			Id:                941100,
		},
		Conditions: []types.Condition{{
			Collections: []types.Collection{{
				Name:      types.ARGS,
				Arguments: []string{},
			}},
			Operator: types.Operator{Name: types.Rx, Value: "attack"},
			Transformations: types.Transformations{
				Transformations: []types.Transformation{
					types.Utf8toUnicode,
					types.UrlDecodeUni,
					types.HtmlEntityDecode,
					types.Lowercase,
				},
			},
		}},
	}
	got, err := ConvertCrsRule(src, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Conditions) != 1 {
		t.Fatalf("conditions=%d", len(got.Conditions))
	}
	want := []v1beta1.Transformation{
		v1beta1.Utf8toUnicode,
		v1beta1.UrlDecodeUni,
		v1beta1.HtmlEntityDecode,
		v1beta1.Lowercase,
	}
	if len(got.Conditions[0].Transformations) != len(want) {
		t.Fatalf("transforms=%v want %v", got.Conditions[0].Transformations, want)
	}
	for i, w := range want {
		if got.Conditions[0].Transformations[i] != w {
			t.Fatalf("transform[%d]=%q want %q", i, got.Conditions[0].Transformations[i], w)
		}
	}
}

func TestConvertSecRule_RoundTripTransformsAndUnconditional(t *testing.T) {
	sr := v1beta1.SecRule{
		Spec: v1beta1.SecRuleSpec{
			SecRules: []v1beta1.SecLangSecRule{
				{
					Metadata: &v1beta1.SecRuleMetadata{
						OnlyPhaseMetadata: v1beta1.OnlyPhaseMetadata{Phase: "2"},
						Id:                1001,
						Msg:               "xss",
					},
					Conditions: []v1beta1.Condition{{
						Collections: []v1beta1.Collection{{
							Name: v1beta1.ARGS,
						}},
						Operator: v1beta1.Operator{Name: v1beta1.Rx, Value: "x"},
						Transformations: []v1beta1.Transformation{
							v1beta1.UrlDecodeUni,
							v1beta1.Lowercase,
						},
					}},
					Actions: &v1beta1.SecRuleActions{
						DisruptiveAction: &v1beta1.DisruptiveAction{Type: v1beta1.Pass},
					},
				},
				{
					Metadata: &v1beta1.SecRuleMetadata{
						OnlyPhaseMetadata: v1beta1.OnlyPhaseMetadata{Phase: "1"},
						Id:                1002,
					},
					Conditions: []v1beta1.Condition{{
						AlwaysMatch: true,
						Operator:    v1beta1.Operator{Name: v1beta1.UnconditionalMatch},
					}},
					Actions: &v1beta1.SecRuleActions{
						DisruptiveAction: &v1beta1.DisruptiveAction{Type: v1beta1.Pass},
						NonDisruptive: []v1beta1.NonDisruptiveAction{
							{Type: v1beta1.NoLog},
							{Type: v1beta1.SetVar, Value: "TX.foo=1"},
						},
					},
				},
			},
		},
	}
	dirs, err := ConvertSecRule(sr)
	if err != nil {
		t.Fatal(err)
	}
	out := ConvertToSecLangString(dirs)
	if !strings.Contains(out, "t:urlDecodeUni") && !strings.Contains(out, "t:lowercase") {
		// crslang may emit transforms as t:name in action list or variable side
		if !strings.Contains(out, "urlDecodeUni") || !strings.Contains(out, "lowercase") {
			t.Fatalf("expected transformations in SecLang:\n%s", out)
		}
	}
	if !strings.Contains(out, "id:1001") || !strings.Contains(out, "id:1002") {
		t.Fatalf("missing rule ids:\n%s", out)
	}
	// Unconditional should emit SecAction or @unconditionalMatch
	if !strings.Contains(out, "SecAction") && !strings.Contains(out, "unconditionalMatch") {
		t.Fatalf("expected SecAction or unconditionalMatch:\n%s", out)
	}
}
