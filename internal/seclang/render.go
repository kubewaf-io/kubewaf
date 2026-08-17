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

// Package seclang holds shared SecRule render/validate helpers used by the
// SecRule controller, webhooks (optional), and dataplane assembly.
package seclang

import (
	"fmt"
	"strings"

	"github.com/coreruleset/crslang/types"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	seclangv1beta1 "github.com/kubewaf-io/kubewaf/api/seclang/v1beta1"
	"github.com/kubewaf-io/kubewaf/api/seclang/v1beta1/convert"
	"github.com/kubewaf-io/kubewaf/internal/controller"
	"github.com/kubewaf-io/kubewaf/internal/coraza"
	"github.com/kubewaf-io/kubewaf/internal/coraza/crsdata"
)

// RenderResult is convert + optional engine validation.
type RenderResult struct {
	Directives []types.SeclangDirective
	SecLang    string
	// ValidateErr is non-nil when Coraza rejected the directives.
	// Convert may still have succeeded (SecLang is populated).
	ValidateErr error
}

// RenderSecRule converts Spec to SecLang. assignedIDs (when non-empty) are
// applied onto a deep copy so status-only auto-ids are used for emission.
func RenderSecRule(sr *seclangv1beta1.SecRule, assignedIDs []int) (*RenderResult, error) {
	if sr == nil {
		return nil, fmt.Errorf("secrule is nil")
	}
	withIDs := applyAssignedIDs(sr, assignedIDs)
	dirs, err := convert.ConvertSecRule(*withIDs)
	if err != nil {
		return nil, fmt.Errorf("convert: %w", err)
	}
	if len(dirs) == 0 {
		return nil, fmt.Errorf("convert produced no directives")
	}
	secLang := convert.ConvertToSecLangString(dirs)
	// Defense in depth: never surface t:unknown to status/dataplane. Convert
	// already rejects empty/unknown transforms; this catches any future mapper
	// regression that would trap ModSecurity wasm on configure.
	if strings.Contains(secLang, "t:unknown") {
		return nil, fmt.Errorf("rendered SecLang contains t:unknown (unsupported transformation); SecRule must not become Ready")
	}
	out := &RenderResult{
		Directives: dirs,
		SecLang:    secLang,
	}
	return out, nil
}

// RenderAndValidate is the shared controller/assembly path: convert then Coraza load
// with embedded CRS phrase lists as the root FS.
func RenderAndValidate(sr *seclangv1beta1.SecRule, assignedIDs []int) (*RenderResult, error) {
	return RenderAndValidateWithOverrides(sr, assignedIDs, nil)
}

// RenderAndValidateWithOverrides converts then loads into Coraza with CRS embed
// plus optional PhraseList basename overrides (MapFS merge).
func RenderAndValidateWithOverrides(sr *seclangv1beta1.SecRule, assignedIDs []int, overrides map[string][]byte) (*RenderResult, error) {
	res, err := RenderSecRule(sr, assignedIDs)
	if err != nil {
		return nil, err
	}
	root := crsdata.MapFS(overrides)
	if !crsdata.Available() && len(overrides) == 0 {
		// Emergency: no embed pack — validate without root FS (may fail on pmFromFile).
		_, res.ValidateErr = coraza.LoadAndValidateSeclangDirectivesWithFS(res.Directives, nil)
		return res, nil
	}
	_, res.ValidateErr = coraza.LoadAndValidateSeclangDirectivesWithFS(res.Directives, root)
	return res, nil
}

// LooksLikeMissingDataFile heuristically detects Coraza errors from missing @pmFromFile bodies.
func LooksLikeMissingDataFile(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, ".data") ||
		strings.Contains(msg, "pmfromfile") ||
		strings.Contains(msg, "no such file") ||
		strings.Contains(msg, "open ")
}

// IsReadyTrue reports whether status.conditions Ready is True.
// Missing Ready is treated as not ready (do not ship unvalidated rules).
func IsReadyTrue(conditions []metav1.Condition) bool {
	return meta.IsStatusConditionTrue(conditions, controller.ConditionTypeReady)
}

// IsReadyFalse reports explicit Ready=False (failed validation).
func IsReadyFalse(conditions []metav1.Condition) bool {
	return meta.IsStatusConditionFalse(conditions, controller.ConditionTypeReady)
}

// applyAssignedIDs fills metadata.id from status.assignedIds when Spec omitted id.
// Mirrors id_pool.applyAssignedIDs (status-assigned auto ids).
func applyAssignedIDs(sr *seclangv1beta1.SecRule, ids []int) *seclangv1beta1.SecRule {
	if sr == nil {
		return nil
	}
	cp := sr.DeepCopy()
	if len(ids) == 0 {
		ids = cp.Status.AssignedIDs
	}
	if len(ids) == 0 {
		return cp
	}
	if cp.Spec.IsSingleRuleForm() {
		if ids[0] <= 0 {
			return cp
		}
		if cp.Spec.Metadata == nil {
			cp.Spec.Metadata = &seclangv1beta1.SecRuleMetadata{}
		}
		if cp.Spec.Metadata.Id <= 0 {
			cp.Spec.Metadata.Id = ids[0]
		}
		return cp
	}
	for i := range cp.Spec.SecRules {
		if i >= len(ids) || ids[i] <= 0 {
			continue
		}
		if cp.Spec.SecRules[i].Metadata == nil {
			cp.Spec.SecRules[i].Metadata = &seclangv1beta1.SecRuleMetadata{}
		}
		if cp.Spec.SecRules[i].Metadata.Id <= 0 {
			cp.Spec.SecRules[i].Metadata.Id = ids[i]
		}
	}
	return cp
}
