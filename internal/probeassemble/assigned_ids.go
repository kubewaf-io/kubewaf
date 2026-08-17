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

package probeassemble

import (
	"fmt"

	seclangv1beta1 "github.com/kubewaf-io/kubewaf/api/seclang/v1beta1"
)

// ErrRuleIDsUnresolved is returned when auto-id rules lack status.assignedIds
// and have no explicit metadata ids (K7b / assembly contract).
var ErrRuleIDsUnresolved = fmt.Errorf("RuleIDsUnresolved")

// ApplyAssignedIDs fills metadata.id from status.assignedIds when Spec omitted id.
// Pure helper copied from internal/seclang (avoids importing that package → coraza).
func ApplyAssignedIDs(sr *seclangv1beta1.SecRule, ids []int) *seclangv1beta1.SecRule {
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

// EnsureRuleIDs checks that every rule has a positive id after ApplyAssignedIDs.
// Returns ErrRuleIDsUnresolved when auto-id is incomplete.
func EnsureRuleIDs(sr *seclangv1beta1.SecRule) error {
	if sr == nil {
		return fmt.Errorf("nil SecRule")
	}
	if sr.Spec.IsSingleRuleForm() {
		if sr.Spec.Metadata == nil || sr.Spec.Metadata.Id <= 0 {
			return ErrRuleIDsUnresolved
		}
		return nil
	}
	if len(sr.Spec.SecRules) == 0 {
		// Empty bag — treat as unresolved (nothing to probe).
		return ErrRuleIDsUnresolved
	}
	for i := range sr.Spec.SecRules {
		if sr.Spec.SecRules[i].Metadata == nil || sr.Spec.SecRules[i].Metadata.Id <= 0 {
			return ErrRuleIDsUnresolved
		}
	}
	return nil
}
