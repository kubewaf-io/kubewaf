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
	"fmt"
	"strings"

	seclangv1beta1 "github.com/kubewaf-io/kubewaf/api/seclang/v1beta1"
	"github.com/kubewaf-io/kubewaf/api/seclang/v1beta1/convert"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// SecRuleValidator validates SecRule create/update.
type SecRuleValidator struct{}

// SetupSecRuleWebhook registers the validating webhook for SecRule.
func SetupSecRuleWebhook(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr, &seclangv1beta1.SecRule{}).
		WithValidator(&SecRuleValidator{}).
		Complete()
}

// +kubebuilder:webhook:path=/validate-seclang-kubewaf-io-v1beta1-secrule,mutating=false,failurePolicy=fail,sideEffects=None,groups=seclang.kubewaf.io,resources=secrules,verbs=create;update,versions=v1beta1,name=vsecrule.kubewaf.io,admissionReviewVersions=v1

var _ admission.Validator[*seclangv1beta1.SecRule] = &SecRuleValidator{}

func (v *SecRuleValidator) ValidateCreate(_ context.Context, obj *seclangv1beta1.SecRule) (admission.Warnings, error) {
	return v.validate(obj)
}

func (v *SecRuleValidator) ValidateUpdate(_ context.Context, _, newObj *seclangv1beta1.SecRule) (admission.Warnings, error) {
	return v.validate(newObj)
}

func (v *SecRuleValidator) ValidateDelete(_ context.Context, _ *seclangv1beta1.SecRule) (admission.Warnings, error) {
	return nil, nil
}

func (v *SecRuleValidator) validate(sr *seclangv1beta1.SecRule) (admission.Warnings, error) {
	var all field.ErrorList
	var warnings admission.Warnings

	if errList, warns := validateSecRuleSpec(&sr.Spec, field.NewPath("spec")); len(errList) > 0 || len(warns) > 0 {
		all = append(all, errList...)
		warnings = append(warnings, warns...)
	}

	if len(all) > 0 {
		return warnings, apierrors.NewInvalid(
			schema.GroupKind{Group: "seclang.kubewaf.io", Kind: "SecRule"},
			sr.Name,
			all,
		)
	}
	return warnings, nil
}

func validateSecRuleSpec(spec *seclangv1beta1.SecRuleSpec, p *field.Path) (field.ErrorList, admission.Warnings) {
	var all field.ErrorList
	var warnings admission.Warnings
	if spec == nil {
		return field.ErrorList{field.Required(p, "spec is required")}, nil
	}

	single := spec.IsSingleRuleForm()
	legacy := len(spec.SecRules) > 0
	if !single && !legacy {
		all = append(all, field.Invalid(p, nil,
			"must set metadata/match (one-rule form) or secLangRules (legacy multi-rule bag)"))
		return all, warnings
	}

	if single {
		all = append(all, validateSingleRuleForm(spec, p)...)
		warnings = append(warnings, singleRuleWarnings(spec)...)
	} else if len(spec.Match) > 0 {
		all = append(all, validateMatchTransforms(spec.Match, p)...)
	}
	bagErrs, bagWarns := validateSecLangBags(spec.SecRules, p)
	all = append(all, bagErrs...)
	warnings = append(warnings, bagWarns...)
	return all, warnings
}

func validateSingleRuleForm(spec *seclangv1beta1.SecRuleSpec, p *field.Path) field.ErrorList {
	var all field.ErrorList
	if len(spec.Match) == 0 && spec.Metadata != nil && len(spec.SecRules) == 0 {
		all = append(all, field.Required(p.Child("match"),
			"match[] is required for one-rule form (or use always-match condition)"))
	}
	for i, m := range spec.Match {
		mp := p.Child("match").Index(i)
		if !m.AlwaysMatch && len(m.Variables) == 0 && len(m.Collections) == 0 && strings.TrimSpace(m.Script) == "" {
			all = append(all, field.Invalid(mp, m,
				"each match needs always-match, variables/collections, or script"))
		}
		if err := convert.ValidateAPITransformations(m.Transformations); err != nil {
			all = append(all, field.Invalid(mp.Child("transformations"), m.Transformations, err.Error()))
		}
	}
	if phase := phaseOf(spec.Metadata); phase != "" && !validPhase(phase) {
		all = append(all, field.Invalid(p.Child("metadata").Child("phase"), phase,
			"phase must be 1–5 (or empty)"))
	}
	return all
}

func singleRuleWarnings(spec *seclangv1beta1.SecRuleSpec) admission.Warnings {
	if spec.Metadata != nil && spec.Metadata.Id > 0 && spec.Metadata.Id <= 100000 {
		return admission.Warnings{
			fmt.Sprintf("metadata.id=%d: custom rules should use ids > 100000 to avoid CRS collisions", spec.Metadata.Id),
		}
	}
	return nil
}

func validateMatchTransforms(matches []seclangv1beta1.Match, p *field.Path) field.ErrorList {
	var all field.ErrorList
	for i, m := range matches {
		if err := convert.ValidateAPITransformations(m.Transformations); err != nil {
			all = append(all, field.Invalid(
				p.Child("match").Index(i).Child("transformations"),
				m.Transformations, err.Error()))
		}
	}
	return all
}

func validateSecLangBags(bags []seclangv1beta1.SecLangSecRule, p *field.Path) (field.ErrorList, admission.Warnings) {
	var all field.ErrorList
	var warnings admission.Warnings
	for i, bag := range bags {
		bp := p.Child("secLangRules").Index(i)
		if bag.Metadata != nil && bag.Metadata.Id > 0 && bag.Metadata.Id <= 100000 {
			warnings = append(warnings,
				fmt.Sprintf("secLangRules[%d].metadata.id=%d: prefer ids > 100000 for custom rules", i, bag.Metadata.Id))
		}
		if phase := phaseOf(bag.Metadata); phase != "" && !validPhase(phase) {
			all = append(all, field.Invalid(bp.Child("metadata").Child("phase"), phase,
				"phase must be 1–5 (or empty)"))
		}
		for j, cond := range bag.Conditions {
			if err := convert.ValidateAPITransformations(cond.Transformations); err != nil {
				all = append(all, field.Invalid(
					bp.Child("conditions").Index(j).Child("transformations"),
					cond.Transformations, err.Error()))
			}
		}
	}
	return all, warnings
}

func phaseOf(m *seclangv1beta1.SecRuleMetadata) string {
	if m == nil {
		return ""
	}
	return strings.TrimSpace(m.Phase)
}

func validPhase(p string) bool {
	switch p {
	case "1", "2", "3", "4", "5":
		return true
	default:
		return false
	}
}
