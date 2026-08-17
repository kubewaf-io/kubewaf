/*
Copyright 2025 Buzz-IT GmbH.
*/
package convert

import (
	"strings"
	"testing"

	v1beta1 "github.com/kubewaf-io/kubewaf/api/seclang/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestConvertSecAction_RendersSecAction(t *testing.T) {
	sa := v1beta1.SecAction{
		ObjectMeta: metav1.ObjectMeta{Name: "init-pl", Namespace: "ns"},
		Spec: v1beta1.SecActionSpec{
			Metadata: &v1beta1.SecRuleMetadata{
				OnlyPhaseMetadata: v1beta1.OnlyPhaseMetadata{Phase: "1"},
				Id:                900010,
			},
			SecRuleActions: v1beta1.SecRuleActions{
				DisruptiveAction: &v1beta1.DisruptiveAction{Type: v1beta1.Pass},
				NonDisruptive: []v1beta1.NonDisruptiveAction{
					{Type: v1beta1.SetVar, Value: "tx.detection_paranoia_level=2"},
					{Type: v1beta1.NoLog},
				},
			},
		},
	}
	out, err := ConvertSecActionToString(sa)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "id:900010") {
		t.Fatalf("missing id:\n%s", out)
	}
	if !strings.Contains(out, "detection_paranoia_level=2") && !strings.Contains(out, "setvar") {
		t.Fatalf("missing setvar:\n%s", out)
	}
	// Always-match must render as SecAction — not SecRule @unconditionalMatch
	// (empty-variable SecRule has trapped Envoy V8 as unreachable).
	if !strings.Contains(out, "SecAction") {
		t.Fatalf("expected SecAction:\n%s", out)
	}
	if strings.Contains(out, "unconditionalMatch") {
		t.Fatalf("must not use @unconditionalMatch:\n%s", out)
	}
}
