package convert

import (
	"strings"
	"testing"

	v1beta1 "github.com/kubewaf-io/kubewaf/api/seclang/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestThreeLinkChain_KeepsMiddleChain(t *testing.T) {
	sr := v1beta1.SecRule{
		ObjectMeta: metav1.ObjectMeta{Name: "crs-901320"},
		Spec: v1beta1.SecRuleSpec{
			Metadata: &v1beta1.SecRuleMetadata{
				OnlyPhaseMetadata: v1beta1.OnlyPhaseMetadata{Phase: "1"},
				Id:                901320,
			},
			Match: []v1beta1.Match{
				{
					Collections: []v1beta1.Collection{{Name: v1beta1.TX, Arguments: []string{"ENABLE_DEFAULT_COLLECTIONS"}, Count: true}},
					Operator:    v1beta1.Operator{Name: v1beta1.Eq, Value: "1"},
				},
				{
					Collections: []v1beta1.Collection{{Name: v1beta1.TX, Arguments: []string{"ENABLE_DEFAULT_COLLECTIONS"}}},
					Operator:    v1beta1.Operator{Name: v1beta1.Eq, Value: "1"},
				},
				{
					Collections:     []v1beta1.Collection{{Name: v1beta1.TX, Arguments: []string{"ua_hash"}}},
					Operator:        v1beta1.Operator{Name: v1beta1.UnconditionalMatch},
					Transformations: []v1beta1.Transformation{v1beta1.None, v1beta1.Sha1, v1beta1.HexEncode},
					Actions: &v1beta1.SecRuleActions{
						NonDisruptive: []v1beta1.NonDisruptiveAction{
							{Type: v1beta1.InitCol, Value: "global=global"},
							{Type: v1beta1.InitCol, Value: "ip=%{remote_addr}_%{MATCHED_VAR}"},
						},
					},
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
	t.Log(out)
	// Expect two chain actions (parent + middle), final link with initcol and unconditionalMatch
	if strings.Count(out, "chain") < 2 {
		t.Fatalf("want >=2 chain actions:\n%s", out)
	}
	if !strings.Contains(out, "unconditionalMatch") {
		t.Fatalf("want unconditionalMatch on last link:\n%s", out)
	}
	if !strings.Contains(out, "initcol") {
		t.Fatalf("want initcol:\n%s", out)
	}
	// Must be SecRule TX:ua_hash not empty-var
	if strings.Contains(out, `SecRule  "`) || strings.Contains(out, `SecRule "@`) {
		t.Fatalf("empty-var SecRule:\n%s", out)
	}
}
