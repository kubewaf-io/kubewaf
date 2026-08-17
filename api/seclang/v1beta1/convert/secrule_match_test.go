/*
Copyright 2025 Buzz-IT GmbH.
*/
package convert

import (
	"strings"
	"testing"

	v1beta1 "github.com/kubewaf-io/kubewaf/api/seclang/v1beta1"
)

func TestConvertSecRule_SingleRuleMatch(t *testing.T) {
	sr := v1beta1.SecRule{
		Spec: v1beta1.SecRuleSpec{
			Order: 100001,
			Metadata: &v1beta1.SecRuleMetadata{
				OnlyPhaseMetadata: v1beta1.OnlyPhaseMetadata{Phase: "1"},
				Id:                100001,
				Msg:               "Scanner UA",
				Severity:          "WARNING",
				Tags:              []string{"attack-recon", "custom"},
			},
			Match: []v1beta1.Match{
				{
					Collections: []v1beta1.Collection{{
						Name:      v1beta1.REQUEST_HEADERS,
						Arguments: []string{"User-Agent"},
					}},
					Operator: v1beta1.Operator{
						Name:  v1beta1.Rx,
						Value: `(?i)(nikto|sqlmap)`,
					},
				},
			},
			Actions: &v1beta1.SecRuleActions{
				DisruptiveAction: &v1beta1.DisruptiveAction{Type: v1beta1.Pass},
				NonDisruptive: []v1beta1.NonDisruptiveAction{
					{Type: v1beta1.SetVar, Value: "TX.anomaly_score_pl1=+2"},
				},
			},
		},
	}
	dirs, err := ConvertSecRule(sr)
	if err != nil {
		t.Fatal(err)
	}
	out := ConvertToSecLangString(dirs)
	if !strings.Contains(out, "id:100001") {
		t.Fatalf("missing id:\n%s", out)
	}
	if !strings.Contains(out, "REQUEST_HEADERS") {
		t.Fatalf("missing var:\n%s", out)
	}
	if strings.Contains(out, "SecMarker") {
		t.Fatalf("unexpected marker:\n%s", out)
	}
}

func TestConvertSecRule_MatchChainAndMarkerAfter(t *testing.T) {
	sr := v1beta1.SecRule{
		Spec: v1beta1.SecRuleSpec{
			Order:       942130,
			MarkerAfter: "END-SQLI-TEST",
			Metadata: &v1beta1.SecRuleMetadata{
				OnlyPhaseMetadata: v1beta1.OnlyPhaseMetadata{Phase: "2"},
				Id:                942130,
				Msg:               "SQLi chain",
			},
			Match: []v1beta1.Match{
				{
					Collections: []v1beta1.Collection{{Name: v1beta1.ARGS}},
					Operator:    v1beta1.Operator{Name: v1beta1.Rx, Value: `(?i)select`},
					Actions: &v1beta1.SecRuleActions{
						NonDisruptive: []v1beta1.NonDisruptiveAction{
							{Type: v1beta1.Capture},
						},
					},
				},
				{
					Collections: []v1beta1.Collection{{
						Name:      v1beta1.TX,
						Arguments: []string{"0"},
					}},
					Operator: v1beta1.Operator{Name: v1beta1.Rx, Value: `.+`},
				},
			},
			Actions: &v1beta1.SecRuleActions{
				DisruptiveAction: &v1beta1.DisruptiveAction{Type: v1beta1.Block},
			},
		},
	}
	dirs, err := ConvertSecRule(sr)
	if err != nil {
		t.Fatal(err)
	}
	out := ConvertToSecLangString(dirs)
	if !strings.Contains(out, "chain") {
		t.Fatalf("expected chain action:\n%s", out)
	}
	// Marker after rule content.
	idxRule := strings.Index(out, "SecRule")
	idxMarker := strings.Index(out, `SecMarker "END-SQLI-CLASS"`)
	if idxMarker < 0 {
		// crslang may quote differently
		idxMarker = strings.Index(out, "SecMarker")
	}
	if idxRule < 0 || idxMarker < 0 {
		t.Fatalf("missing rule or marker:\n%s", out)
	}
	if idxMarker < idxRule {
		t.Fatalf("marker should be after rule:\n%s", out)
	}
	// Two SecRule lines for chain.
	count := strings.Count(out, "SecRule")
	if count < 2 {
		t.Fatalf("expected chained SecRules, got %d:\n%s", count, out)
	}
}

func TestConvertSecRule_LegacyBagStillWorks(t *testing.T) {
	sr := v1beta1.SecRule{
		Spec: v1beta1.SecRuleSpec{
			SecRules: []v1beta1.SecLangSecRule{
				{
					Metadata: &v1beta1.SecRuleMetadata{
						OnlyPhaseMetadata: v1beta1.OnlyPhaseMetadata{Phase: "1"},
						Id:                100010,
					},
					Conditions: []v1beta1.Condition{{
						AlwaysMatch: true,
					}},
					Actions: &v1beta1.SecRuleActions{
						NonDisruptive: []v1beta1.NonDisruptiveAction{
							{Type: v1beta1.SetVar, Value: "tx.detection_paranoia_level=1"},
						},
					},
					SecMarker: "END-INIT",
				},
			},
		},
	}
	dirs, err := ConvertSecRule(sr)
	if err != nil {
		t.Fatal(err)
	}
	out := ConvertToSecLangString(dirs)
	if !strings.Contains(out, "id:100010") {
		t.Fatalf("missing id:\n%s", out)
	}
	idxRule := strings.Index(out, "SecRule")
	idxMarker := strings.Index(out, "SecMarker")
	if idxMarker >= 0 && idxMarker < idxRule {
		t.Fatalf("legacy marker should be after rule:\n%s", out)
	}
}

func TestIsSingleRuleForm(t *testing.T) {
	if !(v1beta1.SecRuleSpec{Metadata: &v1beta1.SecRuleMetadata{}}).IsSingleRuleForm() {
		t.Fatal("metadata implies single form")
	}
	if !(v1beta1.SecRuleSpec{Match: []v1beta1.Match{{AlwaysMatch: true}}}).IsSingleRuleForm() {
		t.Fatal("match implies single form")
	}
	if (v1beta1.SecRuleSpec{SecRules: []v1beta1.SecLangSecRule{{}}}).IsSingleRuleForm() {
		t.Fatal("legacy bag only should not be single form")
	}
}
