package convert

import (
	"strings"
	"testing"

	v1beta1 "github.com/kubewaf-io/kubewaf/api/seclang/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestAlwaysMatch_RendersSecAction_NotUnconditionalMatch(t *testing.T) {
	sr := v1beta1.SecRule{
		ObjectMeta: metav1.ObjectMeta{Name: "crs-901200"},
		Spec: v1beta1.SecRuleSpec{
			Metadata: &v1beta1.SecRuleMetadata{
				OnlyPhaseMetadata: v1beta1.OnlyPhaseMetadata{Phase: "1"},
				Id:                901200,
			},
			Order: 901200,
			Match: []v1beta1.Match{{
				AlwaysMatch:     true,
				Transformations: []v1beta1.Transformation{v1beta1.None},
				// Samples often still carry unconditionalMatch; conversion must ignore it.
				Operator: v1beta1.Operator{Name: v1beta1.UnconditionalMatch},
			}},
			Actions: &v1beta1.SecRuleActions{
				DisruptiveAction: &v1beta1.DisruptiveAction{Type: v1beta1.Pass},
				NonDisruptive: []v1beta1.NonDisruptiveAction{
					{Type: v1beta1.NoLog},
					{Type: v1beta1.SetVar, Value: "TX.blocking_inbound_anomaly_score=0"},
				},
			},
		},
	}
	dirs, err := ConvertSecRule(sr)
	if err != nil {
		t.Fatal(err)
	}
	out := ConvertToSecLangString(dirs)
	if !strings.Contains(out, "SecAction") {
		t.Fatalf("want SecAction:\n%s", out)
	}
	if strings.Contains(out, "unconditionalMatch") {
		t.Fatalf("must not use unconditionalMatch:\n%s", out)
	}
	if !strings.Contains(out, "id:901200") {
		t.Fatalf("missing id:\n%s", out)
	}
}

func TestChainChild_NoDefaultPass(t *testing.T) {
	// Mirrors CRS 901320: parent pass+chain, child only initcol (disruptive: null).
	sr := v1beta1.SecRule{
		ObjectMeta: metav1.ObjectMeta{Name: "crs-901320"},
		Spec: v1beta1.SecRuleSpec{
			Metadata: &v1beta1.SecRuleMetadata{
				OnlyPhaseMetadata: v1beta1.OnlyPhaseMetadata{Phase: "1"},
				Id:                901320,
			},
			Order: 901320,
			Match: []v1beta1.Match{
				{
					Collections: []v1beta1.Collection{{
						Name:      v1beta1.TX,
						Arguments: []string{"ENABLE_DEFAULT_COLLECTIONS"},
						Count:     true,
					}},
					Operator: v1beta1.Operator{Name: v1beta1.Eq, Value: "1"},
				},
				{
					// Explicit per-link actions with no disruptive (YAML null).
					Actions: &v1beta1.SecRuleActions{
						NonDisruptive: []v1beta1.NonDisruptiveAction{
							{Type: v1beta1.InitCol, Value: "global=global"},
						},
					},
					Collections: []v1beta1.Collection{{
						Name:      v1beta1.TX,
						Arguments: []string{"ENABLE_DEFAULT_COLLECTIONS"},
					}},
					Operator: v1beta1.Operator{Name: v1beta1.Eq, Value: "1"},
				},
			},
			Actions: &v1beta1.SecRuleActions{
				DisruptiveAction: &v1beta1.DisruptiveAction{Type: v1beta1.Pass},
				NonDisruptive: []v1beta1.NonDisruptiveAction{
					{Type: v1beta1.NoLog},
					{Type: v1beta1.SetVar, Value: "TX.ua_hash=%{REQUEST_HEADERS.User-Agent}"},
				},
			},
		},
	}
	dirs, err := ConvertSecRule(sr)
	if err != nil {
		t.Fatal(err)
	}
	out := ConvertToSecLangString(dirs)
	// Parent must keep pass + chain.
	if !strings.Contains(out, "chain") {
		t.Fatalf("expected chain:\n%s", out)
	}
	// Find child SecRule line(s) after the first — must not include pass.
	// collapseSecLangLineContinuations puts each directive on one line.
	var secrules []string
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "SecRule") {
			secrules = append(secrules, line)
		}
	}
	if len(secrules) < 2 {
		// chained child may be on same multi-line before collapse, or embedded
		// After collapse, chain child is often a second SecRule line.
		t.Logf("output:\n%s", out)
	}
	// Stronger check: child initcol line must not be paired with pass as disruptive.
	// Pattern after collapse: second SecRule "...pass,initcol..." would be wrong.
	if strings.Count(out, "pass") > 1 {
		t.Fatalf("chain child must not inherit default pass:\n%s", out)
	}
	if !strings.Contains(out, "initcol") {
		t.Fatalf("missing initcol on child:\n%s", out)
	}
}
