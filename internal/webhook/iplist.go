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
	"net"
	"strings"

	seclangv1beta1 "github.com/kubewaf-io/kubewaf/api/seclang/v1beta1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// IPListValidator validates IPList create/update.
type IPListValidator struct{}

// SetupIPListWebhook registers the validating webhook for IPList.
func SetupIPListWebhook(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr, &seclangv1beta1.IPList{}).
		WithValidator(&IPListValidator{}).
		Complete()
}

// +kubebuilder:webhook:path=/validate-seclang-kubewaf-io-v1beta1-iplist,mutating=false,failurePolicy=fail,sideEffects=None,groups=seclang.kubewaf.io,resources=iplists,verbs=create;update,versions=v1beta1,name=viplist.kubewaf.io,admissionReviewVersions=v1

var _ admission.Validator[*seclangv1beta1.IPList] = &IPListValidator{}

func (v *IPListValidator) ValidateCreate(_ context.Context, obj *seclangv1beta1.IPList) (admission.Warnings, error) {
	return v.validate(obj)
}

func (v *IPListValidator) ValidateUpdate(_ context.Context, _, newObj *seclangv1beta1.IPList) (admission.Warnings, error) {
	return v.validate(newObj)
}

func (v *IPListValidator) ValidateDelete(_ context.Context, _ *seclangv1beta1.IPList) (admission.Warnings, error) {
	return nil, nil
}

func (v *IPListValidator) validate(ipl *seclangv1beta1.IPList) (admission.Warnings, error) {
	var all field.ErrorList
	var warnings admission.Warnings
	p := field.NewPath("spec")

	if ipl.Spec.FileName == "" {
		all = append(all, field.Required(p.Child("fileName"), "fileName is required"))
	}

	sources := 0
	if ipl.Spec.Content != "" {
		sources++
	}
	if ipl.Spec.ConfigMapRef != nil {
		sources++
		if strings.TrimSpace(ipl.Spec.ConfigMapRef.Name) == "" || strings.TrimSpace(ipl.Spec.ConfigMapRef.Key) == "" {
			all = append(all, field.Invalid(p.Child("configMapRef"), ipl.Spec.ConfigMapRef, "name and key are required"))
		}
	}
	if len(ipl.Spec.Parts) > 0 {
		sources++
		for i, part := range ipl.Spec.Parts {
			if strings.TrimSpace(part.ConfigMapRef.Name) == "" || strings.TrimSpace(part.ConfigMapRef.Key) == "" {
				all = append(all, field.Invalid(p.Child("parts").Index(i).Child("configMapRef"), part.ConfigMapRef, "name and key are required"))
			}
		}
	}
	if sources != 1 {
		all = append(all, field.Invalid(p, ipl.Spec, "exactly one of content, configMapRef, or parts is required"))
	}
	if ipl.Spec.Content != "" && strings.TrimSpace(ipl.Spec.Content) == "" {
		all = append(all, field.Invalid(p.Child("content"), ipl.Spec.Content, "content must not be empty/whitespace-only"))
	}

	// Soft-validate IP/CIDR lines for inline content (parts/CM may include bulk dumps).
	if ipl.Spec.Content != "" {
		if bad := firstInvalidIPLine(ipl.Spec.Content); bad != "" {
			warnings = append(warnings,
				"line does not look like an IP or CIDR (use one address/prefix per line): "+bad)
		}
	}

	if len(all) > 0 {
		return warnings, apierrors.NewInvalid(
			schema.GroupKind{Group: "seclang.kubewaf.io", Kind: "IPList"},
			ipl.Name,
			all,
		)
	}
	return warnings, nil
}

// firstInvalidIPLine returns the first non-comment, non-empty line that is not a valid IP or CIDR.
func firstInvalidIPLine(content string) string {
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Strip trailing comments.
		if i := strings.Index(line, "#"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}
		if net.ParseIP(line) != nil {
			continue
		}
		if _, _, err := net.ParseCIDR(line); err == nil {
			continue
		}
		return line
	}
	return ""
}
