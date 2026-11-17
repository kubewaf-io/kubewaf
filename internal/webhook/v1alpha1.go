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

	seclangv1alpha1 "github.com/kubewaf-io/kubewaf/api/seclang/v1alpha1"
	wafv1alpha1 "github.com/kubewaf-io/kubewaf/api/waf/v1alpha1"
	"github.com/kubewaf-io/kubewaf/internal/compile"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// SetupV1Alpha1 registers Coraza parse webhooks for the v1alpha1 SecLang types.
func SetupV1Alpha1(mgr ctrl.Manager) error {
	if err := ctrl.NewWebhookManagedBy(mgr, &seclangv1alpha1.SecRule{}).
		WithValidator(&SecRuleV1Alpha1{}).Complete(); err != nil {
		return err
	}
	if err := ctrl.NewWebhookManagedBy(mgr, &seclangv1alpha1.SecAction{}).
		WithValidator(&SecActionV1Alpha1{}).Complete(); err != nil {
		return err
	}
	if err := ctrl.NewWebhookManagedBy(mgr, &seclangv1alpha1.Include{}).
		WithValidator(&IncludeV1Alpha1{}).Complete(); err != nil {
		return err
	}
	if err := ctrl.NewWebhookManagedBy(mgr, &seclangv1alpha1.SecPolicy{}).
		WithValidator(&SecPolicyV1Alpha1{}).Complete(); err != nil {
		return err
	}
	return ctrl.NewWebhookManagedBy(mgr, &wafv1alpha1.Protection{}).
		WithValidator(&ProtectionV1Alpha1{}).Complete()
}

// +kubebuilder:webhook:path=/validate-seclang-kubewaf-io-v1alpha1-secrule,mutating=false,failurePolicy=fail,sideEffects=None,groups=seclang.kubewaf.io,resources=secrules,verbs=create;update,versions=v1alpha1,name=v1a1secrule.kubewaf.io,admissionReviewVersions=v1

type SecRuleV1Alpha1 struct{}

var _ admission.Validator[*seclangv1alpha1.SecRule] = &SecRuleV1Alpha1{}

func (v *SecRuleV1Alpha1) ValidateCreate(_ context.Context, obj *seclangv1alpha1.SecRule) (admission.Warnings, error) {
	return nil, admitRule(obj)
}
func (v *SecRuleV1Alpha1) ValidateUpdate(_ context.Context, _, obj *seclangv1alpha1.SecRule) (admission.Warnings, error) {
	return nil, admitRule(obj)
}
func (v *SecRuleV1Alpha1) ValidateDelete(_ context.Context, _ *seclangv1alpha1.SecRule) (admission.Warnings, error) {
	return nil, nil
}

func admitRule(rule *seclangv1alpha1.SecRule) error {
	text, err := compile.EmitRule(rule)
	if err != nil {
		return invalid("SecRule", rule.Name, field.NewPath("spec"), err)
	}
	if err := compile.Parse(text); err != nil {
		return invalid("SecRule", rule.Name, field.NewPath("spec"), err)
	}
	return nil
}

// +kubebuilder:webhook:path=/validate-seclang-kubewaf-io-v1alpha1-secaction,mutating=false,failurePolicy=fail,sideEffects=None,groups=seclang.kubewaf.io,resources=secactions,verbs=create;update,versions=v1alpha1,name=v1a1secaction.kubewaf.io,admissionReviewVersions=v1

type SecActionV1Alpha1 struct{}

var _ admission.Validator[*seclangv1alpha1.SecAction] = &SecActionV1Alpha1{}

func (v *SecActionV1Alpha1) ValidateCreate(_ context.Context, obj *seclangv1alpha1.SecAction) (admission.Warnings, error) {
	return nil, admitAction(obj)
}
func (v *SecActionV1Alpha1) ValidateUpdate(_ context.Context, _, obj *seclangv1alpha1.SecAction) (admission.Warnings, error) {
	return nil, admitAction(obj)
}
func (v *SecActionV1Alpha1) ValidateDelete(_ context.Context, _ *seclangv1alpha1.SecAction) (admission.Warnings, error) {
	return nil, nil
}

func admitAction(action *seclangv1alpha1.SecAction) error {
	text, err := compile.EmitAction(action)
	if err != nil {
		return invalid("SecAction", action.Name, field.NewPath("spec"), err)
	}
	if err := compile.Parse(text); err != nil {
		return invalid("SecAction", action.Name, field.NewPath("spec"), err)
	}
	return nil
}

// +kubebuilder:webhook:path=/validate-seclang-kubewaf-io-v1alpha1-include,mutating=false,failurePolicy=fail,sideEffects=None,groups=seclang.kubewaf.io,resources=includes,verbs=create;update,versions=v1alpha1,name=v1a1include.kubewaf.io,admissionReviewVersions=v1

type IncludeV1Alpha1 struct{}

var _ admission.Validator[*seclangv1alpha1.Include] = &IncludeV1Alpha1{}

func (v *IncludeV1Alpha1) ValidateCreate(_ context.Context, obj *seclangv1alpha1.Include) (admission.Warnings, error) {
	return nil, admitInclude(obj)
}
func (v *IncludeV1Alpha1) ValidateUpdate(_ context.Context, _, obj *seclangv1alpha1.Include) (admission.Warnings, error) {
	return nil, admitInclude(obj)
}
func (v *IncludeV1Alpha1) ValidateDelete(_ context.Context, _ *seclangv1alpha1.Include) (admission.Warnings, error) {
	return nil, nil
}

func admitInclude(inc *seclangv1alpha1.Include) error {
	text, err := compile.EmitInclude(inc)
	if err != nil {
		return invalid("Include", inc.Name, field.NewPath("spec"), err)
	}
	if err := compile.Parse(text); err != nil {
		return invalid("Include", inc.Name, field.NewPath("spec"), err)
	}
	return nil
}

// +kubebuilder:webhook:path=/validate-seclang-kubewaf-io-v1alpha1-secpolicy,mutating=false,failurePolicy=fail,sideEffects=None,groups=seclang.kubewaf.io,resources=secpolicies,verbs=create;update,versions=v1alpha1,name=v1a1secpolicy.kubewaf.io,admissionReviewVersions=v1

type SecPolicyV1Alpha1 struct{}

var _ admission.Validator[*seclangv1alpha1.SecPolicy] = &SecPolicyV1Alpha1{}

func (v *SecPolicyV1Alpha1) ValidateCreate(_ context.Context, obj *seclangv1alpha1.SecPolicy) (admission.Warnings, error) {
	return nil, admitPolicy(obj)
}
func (v *SecPolicyV1Alpha1) ValidateUpdate(_ context.Context, _, obj *seclangv1alpha1.SecPolicy) (admission.Warnings, error) {
	return nil, admitPolicy(obj)
}
func (v *SecPolicyV1Alpha1) ValidateDelete(_ context.Context, _ *seclangv1alpha1.SecPolicy) (admission.Warnings, error) {
	return nil, nil
}

func admitPolicy(policy *seclangv1alpha1.SecPolicy) error {
	for i, d := range policy.Spec.DefaultActions {
		// SecDefaultAction does not reject unknown actions. A synthetic SecAction does.
		line := fmt.Sprintf("SecAction \"id:1,phase:%d,%s\"", d.Phase, d.Actions)
		if err := compile.Parse(line); err != nil {
			return invalid("SecPolicy", policy.Name, field.NewPath("spec").Child("defaultActions").Index(i), err)
		}
	}
	for i, line := range policy.Spec.PostDirectives {
		if err := compile.Parse(line); err != nil {
			return invalid("SecPolicy", policy.Name, field.NewPath("spec").Child("postDirectives").Index(i), err)
		}
	}
	return nil
}

// +kubebuilder:webhook:path=/validate-waf-kubewaf-io-v1alpha1-protection,mutating=false,failurePolicy=fail,sideEffects=None,groups=waf.kubewaf.io,resources=protections,verbs=create;update,versions=v1alpha1,name=v1a1protection.kubewaf.io,admissionReviewVersions=v1

type ProtectionV1Alpha1 struct{}

var _ admission.Validator[*wafv1alpha1.Protection] = &ProtectionV1Alpha1{}

func (v *ProtectionV1Alpha1) ValidateCreate(_ context.Context, obj *wafv1alpha1.Protection) (admission.Warnings, error) {
	return nil, admitProtection(obj)
}
func (v *ProtectionV1Alpha1) ValidateUpdate(_ context.Context, _, obj *wafv1alpha1.Protection) (admission.Warnings, error) {
	return nil, admitProtection(obj)
}
func (v *ProtectionV1Alpha1) ValidateDelete(_ context.Context, _ *wafv1alpha1.Protection) (admission.Warnings, error) {
	return nil, nil
}

func admitProtection(obj *wafv1alpha1.Protection) error {
	lines, err := compile.ProtectionLines(obj.Spec)
	if err != nil {
		return invalidGroup("waf.kubewaf.io", "Protection", obj.Name, field.NewPath("spec"), err)
	}
	if len(lines) == 0 {
		return nil
	}
	if err := compile.Parse(lines[0]); err != nil {
		return invalidGroup("waf.kubewaf.io", "Protection", obj.Name, field.NewPath("spec").Child("crs"), err)
	}
	for i, line := range obj.Spec.PostDirectives {
		if err := compile.Parse(line); err != nil {
			return invalidGroup("waf.kubewaf.io", "Protection", obj.Name, field.NewPath("spec").Child("postDirectives").Index(i), err)
		}
	}
	return nil
}

func invalid(kind, name string, path *field.Path, err error) error {
	return invalidGroup("seclang.kubewaf.io", kind, name, path, err)
}

func invalidGroup(group, kind, name string, path *field.Path, err error) error {
	return apierrors.NewInvalid(
		schema.GroupKind{Group: group, Kind: kind},
		name,
		field.ErrorList{field.Invalid(path, "", err.Error())},
	)
}
