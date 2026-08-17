package convert

import (
	"strings"
	"testing"

	v1beta1 "github.com/kubewaf-io/kubewaf/api/seclang/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestChainChild_NoInheritedDeny(t *testing.T) {
	sr := v1beta1.SecRule{
		ObjectMeta: metav1.ObjectMeta{Name: "crs-959101"},
		Spec: v1beta1.SecRuleSpec{
			Metadata: &v1beta1.SecRuleMetadata{
				OnlyPhaseMetadata: v1beta1.OnlyPhaseMetadata{Phase: "3"},
				Id:                959101,
			},
			Match: []v1beta1.Match{
				{
					Collections: []v1beta1.Collection{{Name: v1beta1.TX, Arguments: []string{"BLOCKING_OUTBOUND_ANOMALY_SCORE"}}},
					Operator:    v1beta1.Operator{Name: v1beta1.Ge, Value: "%{tx.outbound_anomaly_score_threshold}"},
				},
				{
					Collections: []v1beta1.Collection{{Name: v1beta1.TX, Arguments: []string{"EARLY_BLOCKING"}}},
					Operator:    v1beta1.Operator{Name: v1beta1.Eq, Value: "1"},
				},
			},
			Actions: &v1beta1.SecRuleActions{
				DisruptiveAction: &v1beta1.DisruptiveAction{Type: v1beta1.Deny},
			},
		},
	}
	dirs, err := ConvertSecRule(sr)
	if err != nil {
		t.Fatal(err)
	}
	out := ConvertToSecLangString(dirs)
	t.Log(out)
	if !strings.Contains(out, "deny") {
		t.Fatal("parent should keep deny")
	}
	// Child line must not include deny
	lines := strings.Split(out, "\n")
	var child string
	for _, l := range lines {
		if strings.Contains(l, "EARLY_BLOCKING") {
			child = l
		}
	}
	if child == "" {
		t.Fatalf("no child:\n%s", out)
	}
	if strings.Contains(child, "deny") {
		t.Fatalf("child must not have deny:\n%s", out)
	}
}
