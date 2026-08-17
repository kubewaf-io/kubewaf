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
	"strings"

	seclangv1beta1 "github.com/kubewaf-io/kubewaf/api/seclang/v1beta1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// PhraseListValidator validates PhraseList create/update.
type PhraseListValidator struct{}

// SetupPhraseListWebhook registers the validating webhook for PhraseList.
func SetupPhraseListWebhook(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr, &seclangv1beta1.PhraseList{}).
		WithValidator(&PhraseListValidator{}).
		Complete()
}

// +kubebuilder:webhook:path=/validate-seclang-kubewaf-io-v1beta1-phraselist,mutating=false,failurePolicy=fail,sideEffects=None,groups=seclang.kubewaf.io,resources=phraselists,verbs=create;update,versions=v1beta1,name=vphraselist.kubewaf.io,admissionReviewVersions=v1

var _ admission.Validator[*seclangv1beta1.PhraseList] = &PhraseListValidator{}

func (v *PhraseListValidator) ValidateCreate(_ context.Context, obj *seclangv1beta1.PhraseList) (admission.Warnings, error) {
	return v.validate(obj)
}

func (v *PhraseListValidator) ValidateUpdate(_ context.Context, _, newObj *seclangv1beta1.PhraseList) (admission.Warnings, error) {
	return v.validate(newObj)
}

func (v *PhraseListValidator) ValidateDelete(_ context.Context, _ *seclangv1beta1.PhraseList) (admission.Warnings, error) {
	return nil, nil
}

func (v *PhraseListValidator) validate(pl *seclangv1beta1.PhraseList) (admission.Warnings, error) {
	var all field.ErrorList
	p := field.NewPath("spec")

	if pl.Spec.FileName == "" {
		all = append(all, field.Required(p.Child("fileName"), "fileName is required"))
	}

	sources := 0
	if pl.Spec.Content != "" {
		sources++
	}
	if pl.Spec.ConfigMapRef != nil {
		sources++
		if strings.TrimSpace(pl.Spec.ConfigMapRef.Name) == "" || strings.TrimSpace(pl.Spec.ConfigMapRef.Key) == "" {
			all = append(all, field.Invalid(p.Child("configMapRef"), pl.Spec.ConfigMapRef, "name and key are required"))
		}
	}
	if len(pl.Spec.Parts) > 0 {
		sources++
		for i, part := range pl.Spec.Parts {
			if strings.TrimSpace(part.ConfigMapRef.Name) == "" || strings.TrimSpace(part.ConfigMapRef.Key) == "" {
				all = append(all, field.Invalid(p.Child("parts").Index(i).Child("configMapRef"), part.ConfigMapRef, "name and key are required"))
			}
		}
	}
	if sources != 1 {
		all = append(all, field.Invalid(p, pl.Spec, "exactly one of content, configMapRef, or parts is required"))
	}
	if pl.Spec.Content != "" && strings.TrimSpace(pl.Spec.Content) == "" {
		all = append(all, field.Invalid(p.Child("content"), pl.Spec.Content, "content must not be empty/whitespace-only"))
	}

	if len(all) > 0 {
		return nil, apierrors.NewInvalid(
			schema.GroupKind{Group: "seclang.kubewaf.io", Kind: "PhraseList"},
			pl.Name,
			all,
		)
	}
	return nil, nil
}
