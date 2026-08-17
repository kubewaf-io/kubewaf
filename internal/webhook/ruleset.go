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

	wafv1beta1 "github.com/kubewaf-io/kubewaf/api/waf/v1beta1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// RuleSetValidator validates RuleSet create/update.
type RuleSetValidator struct{}

// SetupRuleSetWebhook registers the validating webhook for RuleSet.
func SetupRuleSetWebhook(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr, &wafv1beta1.RuleSet{}).
		WithValidator(&RuleSetValidator{}).
		Complete()
}

// +kubebuilder:webhook:path=/validate-waf-kubewaf-io-v1beta1-ruleset,mutating=false,failurePolicy=fail,sideEffects=None,groups=waf.kubewaf.io,resources=rulesets,verbs=create;update,versions=v1beta1,name=vruleset.kubewaf.io,admissionReviewVersions=v1

var _ admission.Validator[*wafv1beta1.RuleSet] = &RuleSetValidator{}

func (v *RuleSetValidator) ValidateCreate(_ context.Context, obj *wafv1beta1.RuleSet) (admission.Warnings, error) {
	return v.validate(obj)
}

func (v *RuleSetValidator) ValidateUpdate(_ context.Context, _, newObj *wafv1beta1.RuleSet) (admission.Warnings, error) {
	return v.validate(newObj)
}

func (v *RuleSetValidator) ValidateDelete(_ context.Context, _ *wafv1beta1.RuleSet) (admission.Warnings, error) {
	return nil, nil
}

func (v *RuleSetValidator) validate(rs *wafv1beta1.RuleSet) (admission.Warnings, error) {
	var all field.ErrorList

	if err := ValidateRuleRefs(rs.Spec.RuleRefs, "RuleSet"); err != nil {
		all = append(all, field.Invalid(field.NewPath("spec", "ruleRefs"), rs.Spec.RuleRefs, err.Error()))
	}
	if err := ValidateAllowedRules(rs.Spec.AllowedRules); err != nil {
		all = append(all, field.Invalid(field.NewPath("spec", "allowedRules"), rs.Spec.AllowedRules, err.Error()))
	}

	if len(all) > 0 {
		return nil, apierrors.NewInvalid(
			schema.GroupKind{Group: "waf.kubewaf.io", Kind: "RuleSet"},
			rs.Name,
			all,
		)
	}
	return nil, nil
}
