/*
Copyright 2025 Buzz-IT GmbH.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package webhook

import (
	"context"
	"regexp"
	"strings"

	wafv1beta1 "github.com/kubewaf-io/kubewaf/api/waf/v1beta1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// telemetrySampleRateRE is 0, 0.x, 1, or 1.0+.
var telemetrySampleRateRE = regexp.MustCompile(`^(0(\.[0-9]+)?|1(\.0+)?)$`)

var extraLabelKeyRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*$`)
var extraLabelValueRE = regexp.MustCompile(`^[A-Za-z0-9.:_-]*$`)

var extraLabelSpoofFrags = []string{
	"_waf_namespace=", "_waf_name=", "_engine=", "_owner=",
	"_phase=", "_ruleid=", "_severity=", "_tag=",
}

func reservedMetricLabelKey(k string) bool {
	switch k {
	case "waf_namespace", "waf_name", "engine", "owner":
		return true
	default:
		return false
	}
}

func extraLabelSpoofsStatsTags(k, v string) bool {
	composed := "_" + k + "=" + v
	for _, f := range extraLabelSpoofFrags {
		if strings.Contains(composed, f) || strings.Contains(k, f) || strings.Contains(v, f) {
			return true
		}
	}
	return false
}

// WAFValidator validates WAF create/update.
type WAFValidator struct{}

// SetupWAFWebhook registers the validating webhook for WAF.
func SetupWAFWebhook(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr, &wafv1beta1.WAF{}).
		WithValidator(&WAFValidator{}).
		Complete()
}

// +kubebuilder:webhook:path=/validate-waf-kubewaf-io-v1beta1-waf,mutating=false,failurePolicy=fail,sideEffects=None,groups=waf.kubewaf.io,resources=wafs,verbs=create;update,versions=v1beta1,name=vwaf.kubewaf.io,admissionReviewVersions=v1

var _ admission.Validator[*wafv1beta1.WAF] = &WAFValidator{}

func (v *WAFValidator) ValidateCreate(_ context.Context, obj *wafv1beta1.WAF) (admission.Warnings, error) {
	return v.validate(obj)
}

func (v *WAFValidator) ValidateUpdate(_ context.Context, _, newObj *wafv1beta1.WAF) (admission.Warnings, error) {
	return v.validate(newObj)
}

func (v *WAFValidator) ValidateDelete(_ context.Context, _ *wafv1beta1.WAF) (admission.Warnings, error) {
	return nil, nil
}

func (v *WAFValidator) validate(waf *wafv1beta1.WAF) (admission.Warnings, error) {
	var all field.ErrorList
	var warnings admission.Warnings

	targets := waf.Spec.EffectivePolicyTargets()
	//nolint:staticcheck // SA1019: TargetRef still part of EG PolicyTargetReferences
	if targets.TargetRef == nil && len(targets.TargetRefs) == 0 {
		all = append(all, field.Required(field.NewPath("spec"),
			"targetRef or targetRefs is required (or legacy parentRefs.targetRef)"))
	}

	if err := ValidateRuleRefs(waf.Spec.RuleSetRefs, "WAF"); err != nil {
		all = append(all, field.Invalid(field.NewPath("spec", "ruleRefs"), waf.Spec.RuleSetRefs, err.Error()))
	}

	if waf.Spec.LogLevel < 0 || waf.Spec.LogLevel > 7 {
		all = append(all, field.Invalid(field.NewPath("spec", "logLevel"), waf.Spec.LogLevel,
			"must be between 0 and 7"))
	}

	switch waf.Spec.Mode {
	case "", wafv1beta1.WAFModeBlocking, wafv1beta1.WAFModeDetectionOnly:
	default:
		all = append(all, field.Invalid(field.NewPath("spec", "mode"), waf.Spec.Mode,
			"must be Blocking or DetectionOnly"))
	}

	if p := waf.Spec.Provider; p != nil {
		switch p.Type {
		case "", wafv1beta1.ProviderAuto, wafv1beta1.ProviderEnvoyGateway,
			wafv1beta1.ProviderIstio, wafv1beta1.ProviderCilium:
		default:
			all = append(all, field.Invalid(field.NewPath("spec", "provider", "type"), p.Type,
				"must be Auto, EnvoyGateway, Istio, or Cilium"))
		}
	}

	if crs := waf.Spec.CRS; crs != nil {
		if crs.ParanoiaLevel != nil {
			pl := *crs.ParanoiaLevel
			if pl < 1 || pl > 4 {
				all = append(all, field.Invalid(field.NewPath("spec", "crs", "paranoiaLevel"), pl,
					"must be between 1 and 4"))
			}
		}
	}

	if waf.Spec.Mode == "" || waf.Spec.Mode == wafv1beta1.WAFModeBlocking {
		if waf.Spec.CRSEnable {
			warnings = append(warnings,
				"crsEnable with mode=Blocking: prefer DetectionOnly for first CRS rollouts")
		}
	}

	if m := waf.Spec.Metrics; m != nil {
		for k, v := range m.ExtraLabels {
			if reservedMetricLabelKey(k) {
				all = append(all, field.Invalid(field.NewPath("spec", "metrics", "extraLabels").Key(k), k,
					"cannot override reserved identity keys (waf_namespace, waf_name, engine, owner)"))
				continue
			}
			if !extraLabelKeyRE.MatchString(k) {
				all = append(all, field.Invalid(field.NewPath("spec", "metrics", "extraLabels").Key(k), k,
					"must match ^[A-Za-z0-9][A-Za-z0-9_.-]*$"))
			}
			if !extraLabelValueRE.MatchString(v) || extraLabelSpoofsStatsTags(k, v) {
				all = append(all, field.Invalid(field.NewPath("spec", "metrics", "extraLabels").Key(k), v,
					"must not contain '=' or reserved stats_tags fragments"))
			}
		}
	}

	if t := waf.Spec.Telemetry; t != nil {
		switch t.Mode {
		case "", wafv1beta1.TelemetryModeNone, wafv1beta1.TelemetryModeManaged:
		default:
			all = append(all, field.Invalid(field.NewPath("spec", "telemetry", "mode"), t.Mode,
				"must be None or Managed"))
		}
		if tr := t.Traces; tr != nil {
			if tr.SampleRate != "" && !telemetrySampleRateRE.MatchString(tr.SampleRate) {
				all = append(all, field.Invalid(field.NewPath("spec", "telemetry", "traces", "sampleRate"),
					tr.SampleRate, "must match ^(0(\\.[0-9]+)?|1(\\.0+)?)$"))
			}
			if tr.SampleDisruptive != "" && !telemetrySampleRateRE.MatchString(tr.SampleDisruptive) {
				all = append(all, field.Invalid(field.NewPath("spec", "telemetry", "traces", "sampleDisruptive"),
					tr.SampleDisruptive, "must match ^(0(\\.[0-9]+)?|1(\\.0+)?)$"))
			}
		}
	}

	if len(all) > 0 {
		return warnings, apierrors.NewInvalid(
			schema.GroupKind{Group: "waf.kubewaf.io", Kind: "WAF"},
			waf.Name,
			all,
		)
	}
	return warnings, nil
}
