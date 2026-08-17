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

	seclangv1beta1 "github.com/kubewaf-io/kubewaf/api/seclang/v1beta1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// SecActionValidator validates SecAction create/update.
type SecActionValidator struct{}

// SetupSecActionWebhook registers the validating webhook for SecAction.
func SetupSecActionWebhook(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr, &seclangv1beta1.SecAction{}).
		WithValidator(&SecActionValidator{}).
		Complete()
}

// +kubebuilder:webhook:path=/validate-seclang-kubewaf-io-v1beta1-secaction,mutating=false,failurePolicy=fail,sideEffects=None,groups=seclang.kubewaf.io,resources=secactions,verbs=create;update,versions=v1beta1,name=vsecaction.kubewaf.io,admissionReviewVersions=v1

var _ admission.Validator[*seclangv1beta1.SecAction] = &SecActionValidator{}

func (v *SecActionValidator) ValidateCreate(_ context.Context, obj *seclangv1beta1.SecAction) (admission.Warnings, error) {
	return v.validate(obj)
}

func (v *SecActionValidator) ValidateUpdate(_ context.Context, _, newObj *seclangv1beta1.SecAction) (admission.Warnings, error) {
	return v.validate(newObj)
}

func (v *SecActionValidator) ValidateDelete(_ context.Context, _ *seclangv1beta1.SecAction) (admission.Warnings, error) {
	return nil, nil
}

func (v *SecActionValidator) validate(sa *seclangv1beta1.SecAction) (admission.Warnings, error) {
	var all field.ErrorList
	if sa.Spec.Metadata != nil {
		if phase := phaseOf(sa.Spec.Metadata); phase != "" && !validPhase(phase) {
			all = append(all, field.Invalid(field.NewPath("spec", "metadata", "phase"), phase,
				"phase must be 1–5 (or empty)"))
		}
	}
	if sa.Spec.DisruptiveAction == nil && len(sa.Spec.NonDisruptive) == 0 && len(sa.Spec.Flow) == 0 {
		if sa.Spec.Metadata == nil {
			all = append(all, field.Required(field.NewPath("spec"),
				"SecAction needs metadata and/or actions (disruptive, non-disruptive, or flow)"))
		}
	}
	if len(all) > 0 {
		return nil, apierrors.NewInvalid(
			schema.GroupKind{Group: "seclang.kubewaf.io", Kind: "SecAction"},
			sa.Name,
			all,
		)
	}
	return nil, nil
}
