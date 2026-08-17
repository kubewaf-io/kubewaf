package webhook

import (
	"strings"
	"testing"

	egv1a1 "github.com/envoyproxy/gateway/api/v1alpha1"
	seclangv1beta1 "github.com/kubewaf-io/kubewaf/api/seclang/v1beta1"
	wafv1beta1 "github.com/kubewaf-io/kubewaf/api/waf/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func TestValidateRuleRef_WAFKind(t *testing.T) {
	err := ValidateRuleRef(wafv1beta1.RuleRef{Kind: "SecRule", Name: "r"}, "WAF", 0)
	if err == nil {
		t.Fatal("WAF must not reference SecRule directly")
	}
	err = ValidateRuleRef(wafv1beta1.RuleRef{Kind: "RuleSet", Name: "rs"}, "WAF", 0)
	if err != nil {
		t.Fatal(err)
	}
}

func TestValidateRuleRef_NameXorSelector(t *testing.T) {
	if err := ValidateRuleRef(wafv1beta1.RuleRef{}, "RuleSet", 0); err == nil {
		t.Fatal("empty ref")
	}
	if err := ValidateRuleRef(wafv1beta1.RuleRef{
		Name:     "x",
		Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"a": "b"}},
	}, "RuleSet", 0); err == nil {
		t.Fatal("both name and selector")
	}
}

func TestValidateAllowedRules_SelectorRequiresSelector(t *testing.T) {
	from := gatewayv1.NamespacesFromSelector
	err := ValidateAllowedRules(wafv1beta1.RuleNamespaces{From: &from})
	if err == nil {
		t.Fatal("expected selector required")
	}
}

func TestSecRuleValidator_RequiresMatch(t *testing.T) {
	v := &SecRuleValidator{}
	sr := &seclangv1beta1.SecRule{
		ObjectMeta: metav1.ObjectMeta{Name: "bad"},
		Spec: seclangv1beta1.SecRuleSpec{
			Metadata: &seclangv1beta1.SecRuleMetadata{
				OnlyPhaseMetadata: seclangv1beta1.OnlyPhaseMetadata{Phase: "1"},
			},
		},
	}
	_, err := v.ValidateCreate(t.Context(), sr)
	if err == nil {
		t.Fatal("expected invalid SecRule without match")
	}
}

func TestSecRuleValidator_OK(t *testing.T) {
	v := &SecRuleValidator{}
	sr := &seclangv1beta1.SecRule{
		ObjectMeta: metav1.ObjectMeta{Name: "ok"},
		Spec: seclangv1beta1.SecRuleSpec{
			Metadata: &seclangv1beta1.SecRuleMetadata{
				OnlyPhaseMetadata: seclangv1beta1.OnlyPhaseMetadata{Phase: "1"},
				Id:                100001,
			},
			Match: []seclangv1beta1.Match{{AlwaysMatch: true}},
		},
	}
	if _, err := v.ValidateCreate(t.Context(), sr); err != nil {
		t.Fatal(err)
	}
}

func TestSecRuleValidator_RejectsEmptyTransformation(t *testing.T) {
	v := &SecRuleValidator{}
	sr := &seclangv1beta1.SecRule{
		ObjectMeta: metav1.ObjectMeta{Name: "poison-transform"},
		Spec: seclangv1beta1.SecRuleSpec{
			Metadata: &seclangv1beta1.SecRuleMetadata{
				OnlyPhaseMetadata: seclangv1beta1.OnlyPhaseMetadata{Phase: "2"},
				Id:                930120,
			},
			Match: []seclangv1beta1.Match{{
				Collections: []seclangv1beta1.Collection{{Name: seclangv1beta1.ARGS}},
				Operator: seclangv1beta1.Operator{
					Name:  seclangv1beta1.Rx,
					Value: "x",
				},
				// Empty transform previously rendered as t:unknown and trapped wasm.
				Transformations: []seclangv1beta1.Transformation{
					seclangv1beta1.None,
					"",
				},
			}},
		},
	}
	if _, err := v.ValidateCreate(t.Context(), sr); err == nil {
		t.Fatal("expected admission reject for empty transformation")
	}
}

func TestSecRuleValidator_AcceptsNormalisePath(t *testing.T) {
	v := &SecRuleValidator{}
	sr := &seclangv1beta1.SecRule{
		ObjectMeta: metav1.ObjectMeta{Name: "path-norm"},
		Spec: seclangv1beta1.SecRuleSpec{
			Metadata: &seclangv1beta1.SecRuleMetadata{
				OnlyPhaseMetadata: seclangv1beta1.OnlyPhaseMetadata{Phase: "2"},
				Id:                100002,
			},
			Match: []seclangv1beta1.Match{{
				Collections: []seclangv1beta1.Collection{{Name: seclangv1beta1.ARGS}},
				Operator: seclangv1beta1.Operator{
					Name:  seclangv1beta1.Rx,
					Value: "x",
				},
				Transformations: []seclangv1beta1.Transformation{
					seclangv1beta1.None,
					seclangv1beta1.NormalisePathWin,
				},
			}},
		},
	}
	if _, err := v.ValidateCreate(t.Context(), sr); err != nil {
		t.Fatal(err)
	}
}

func TestWAFValidator_RequiresTarget(t *testing.T) {
	v := &WAFValidator{}
	w := &wafv1beta1.WAF{
		ObjectMeta: metav1.ObjectMeta{Name: "w"},
		Spec:       wafv1beta1.WAFSpec{},
	}
	_, err := v.ValidateCreate(t.Context(), w)
	if err == nil {
		t.Fatal("expected target required")
	}
}

func gwTarget() *gatewayv1.LocalPolicyTargetReferenceWithSectionName {
	return &gatewayv1.LocalPolicyTargetReferenceWithSectionName{
		LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{
			Group: gatewayv1.Group("gateway.networking.k8s.io"),
			Kind:  gatewayv1.Kind("Gateway"),
			Name:  gatewayv1.ObjectName("gw"),
		},
	}
}

func TestWAFValidator_OK(t *testing.T) {
	v := &WAFValidator{}
	w := &wafv1beta1.WAF{
		ObjectMeta: metav1.ObjectMeta{Name: "w"},
		Spec: wafv1beta1.WAFSpec{
			PolicyTargetReferences: egv1a1.PolicyTargetReferences{
				TargetRef: gwTarget(),
			},
			Mode: wafv1beta1.WAFModeDetectionOnly,
			RuleSetRefs: []wafv1beta1.RuleRef{
				{Kind: "RuleSet", Name: "rs"},
			},
		},
	}
	if _, err := v.ValidateCreate(t.Context(), w); err != nil {
		t.Fatal(err)
	}
}

func TestWAFValidator_RejectsSecRuleRef(t *testing.T) {
	v := &WAFValidator{}
	w := &wafv1beta1.WAF{
		ObjectMeta: metav1.ObjectMeta{Name: "w"},
		Spec: wafv1beta1.WAFSpec{
			PolicyTargetReferences: egv1a1.PolicyTargetReferences{
				TargetRef: gwTarget(),
			},
			RuleSetRefs: []wafv1beta1.RuleRef{{Kind: "SecRule", Name: "r"}},
		},
	}
	_, err := v.ValidateCreate(t.Context(), w)
	if err == nil || !strings.Contains(err.Error(), "RuleSet") {
		t.Fatalf("expected RuleSet-only error, got %v", err)
	}
}

func TestWAFValidator_Telemetry(t *testing.T) {
	v := &WAFValidator{}
	ok := &wafv1beta1.WAF{
		ObjectMeta: metav1.ObjectMeta{Name: "w"},
		Spec: wafv1beta1.WAFSpec{
			PolicyTargetReferences: egv1a1.PolicyTargetReferences{TargetRef: gwTarget()},
			Telemetry: &wafv1beta1.WAFTelemetry{
				Mode: wafv1beta1.TelemetryModeManaged,
				Traces: &wafv1beta1.WAFTelemetryTraces{
					SampleRate:       "0.25",
					SampleDisruptive: "1.0",
				},
			},
		},
	}
	if _, err := v.ValidateCreate(t.Context(), ok); err != nil {
		t.Fatal(err)
	}

	badMode := ok.DeepCopy()
	badMode.Spec.Telemetry.Mode = "Push"
	if _, err := v.ValidateCreate(t.Context(), badMode); err == nil {
		t.Fatal("expected reject for telemetry.mode")
	}

	badRate := ok.DeepCopy()
	badRate.Spec.Telemetry.Traces.SampleRate = "1.5"
	if _, err := v.ValidateCreate(t.Context(), badRate); err == nil {
		t.Fatal("expected reject for sampleRate")
	}

	emptyMode := ok.DeepCopy()
	emptyMode.Spec.Telemetry.Mode = ""
	if _, err := v.ValidateCreate(t.Context(), emptyMode); err != nil {
		t.Fatalf("empty mode should be allowed: %v", err)
	}
}

func TestWAFValidator_TelemetryRates(t *testing.T) {
	v := &WAFValidator{}
	base := &wafv1beta1.WAF{
		ObjectMeta: metav1.ObjectMeta{Name: "w"},
		Spec: wafv1beta1.WAFSpec{
			PolicyTargetReferences: egv1a1.PolicyTargetReferences{TargetRef: gwTarget()},
			Telemetry:              &wafv1beta1.WAFTelemetry{Mode: wafv1beta1.TelemetryModeManaged, Traces: &wafv1beta1.WAFTelemetryTraces{}},
		},
	}
	valid := []string{"0", "1", "0.0", "1.00", "0.25"}
	for _, s := range valid {
		w := base.DeepCopy()
		w.Spec.Telemetry.Traces.SampleRate = s
		w.Spec.Telemetry.Traces.SampleDisruptive = s
		if _, err := v.ValidateCreate(t.Context(), w); err != nil {
			t.Fatalf("valid %q: %v", s, err)
		}
	}
	invalid := []string{"0.", ".25", "1.5", "2", "-0.1", "01", "1e-1", " 0.25"}
	for _, s := range invalid {
		w := base.DeepCopy()
		w.Spec.Telemetry.Traces.SampleRate = s
		if _, err := v.ValidateCreate(t.Context(), w); err == nil {
			t.Fatalf("sampleRate %q should fail", s)
		}
		w = base.DeepCopy()
		w.Spec.Telemetry.Traces.SampleDisruptive = s
		if _, err := v.ValidateCreate(t.Context(), w); err == nil {
			t.Fatalf("sampleDisruptive %q should fail", s)
		}
	}
}

func TestWAFValidator_ExtraLabelsSpoof(t *testing.T) {
	v := &WAFValidator{}
	base := &wafv1beta1.WAF{
		ObjectMeta: metav1.ObjectMeta{Name: "w"},
		Spec: wafv1beta1.WAFSpec{
			PolicyTargetReferences: egv1a1.PolicyTargetReferences{TargetRef: gwTarget()},
			Metrics:                &wafv1beta1.WAFMetrics{ExtraLabels: map[string]string{}},
		},
	}
	ok := base.DeepCopy()
	ok.Spec.Metrics.ExtraLabels = map[string]string{"team": "payments"}
	if _, err := v.ValidateCreate(t.Context(), ok); err != nil {
		t.Fatal(err)
	}
	for k, val := range map[string]string{
		"waf_namespace":     "x",
		"app_waf_namespace": "victim",
		"team":              "x_waf_namespace=victim",
	} {
		w := base.DeepCopy()
		w.Spec.Metrics.ExtraLabels = map[string]string{k: val}
		if _, err := v.ValidateCreate(t.Context(), w); err == nil {
			t.Fatalf("expected reject extraLabels %s=%s", k, val)
		}
	}
}

func TestRuleSetValidator_OK(t *testing.T) {
	v := &RuleSetValidator{}
	rs := &wafv1beta1.RuleSet{
		ObjectMeta: metav1.ObjectMeta{Name: "rs"},
		Spec: wafv1beta1.RuleSetSpec{
			RuleRefs: []wafv1beta1.RuleRef{{Kind: "SecRule", Name: "r1"}},
		},
	}
	if _, err := v.ValidateCreate(t.Context(), rs); err != nil {
		t.Fatal(err)
	}
}
