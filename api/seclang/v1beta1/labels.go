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

package v1beta1

import (
	"fmt"
	"regexp"
	"strings"
	"unicode"
)

// Label / annotation keys for SecRule selection and sticky auto-IDs.
const (
	// LabelID is the effective rule id (string), mirrored from status.ruleId / spec.
	LabelID = "seclang.kubewaf.io/id"
	// LabelPhase is the primary phase for the rule CR.
	LabelPhase = "seclang.kubewaf.io/phase"
	// LabelIDSource is Auto or Spec for how the primary id was chosen.
	LabelIDSource = "seclang.kubewaf.io/id-source"
	// LabelOrder is the relative RuleSet assembly order (spec.order).
	LabelOrder = "seclang.kubewaf.io/order"
	// LabelTagPrefix prefixes each CRS/custom tag as a label key
	// (value is always "true"). Example: seclang.kubewaf.io/tag.owasp_crs=true
	LabelTagPrefix = "seclang.kubewaf.io/tag."

	// AnnotationAssignedID pins an auto-allocated id so restarts do not reshuffle.
	AnnotationAssignedID = "seclang.kubewaf.io/assigned-id"

	// IDSourceSpec means the id came from rule metadata / user.
	IDSourceSpec = "Spec"
	// IDSourceAuto means the id was allocated from SecRuleIDPool.
	IDSourceAuto = "Auto"
	// IDSourceMixed means some rules in the CR are Spec and some Auto.
	IDSourceMixed = "Mixed"

	// DefaultIDPoolName is the cluster-scoped singleton pool object name.
	DefaultIDPoolName = "cluster"
	// DefaultIDPoolMin is the first auto-allocated id (custom rules).
	DefaultIDPoolMin = 100000
	// DefaultIDPoolMax is the last auto-allocated id (inclusive).
	DefaultIDPoolMax = 999999
)

var nonLabel = regexp.MustCompile(`[^a-z0-9._-]`)

// TagToLabelKey converts a SecLang tag into a valid label key suffix under LabelTagPrefix.
// Returns empty string if the tag cannot be sanitized.
func TagToLabelKey(tag string) string {
	t := strings.ToLower(strings.TrimSpace(tag))
	if t == "" {
		return ""
	}
	// Common CRS style: OWASP_CRS/ATTACK-XSS → owasp_crs.attack-xss
	t = strings.ReplaceAll(t, "/", ".")
	t = strings.ReplaceAll(t, " ", "-")
	t = nonLabel.ReplaceAllString(t, "-")
	t = strings.Trim(t, "-._")
	if t == "" {
		return ""
	}
	// Label name segment max 63; prefix is fixed length.
	const maxSuffix = 63
	if len(t) > maxSuffix {
		t = t[:maxSuffix]
		t = strings.TrimRight(t, "-._")
	}
	// Must start with alphanumeric.
	if t == "" || !unicode.IsLetter(rune(t[0])) && !unicode.IsDigit(rune(t[0])) {
		t = "t-" + t
		if len(t) > maxSuffix {
			t = t[:maxSuffix]
		}
	}
	return LabelTagPrefix + t
}

// CollectTagsFromSecRule returns unique tags from single-rule metadata and legacy bags.
func CollectTagsFromSecRule(sr *SecRule) []string {
	if sr == nil {
		return nil
	}
	seen := map[string]struct{}{}
	var out []string
	add := func(tags []string) {
		for _, tag := range tags {
			tag = strings.TrimSpace(tag)
			if tag == "" {
				continue
			}
			if _, ok := seen[tag]; ok {
				continue
			}
			seen[tag] = struct{}{}
			out = append(out, tag)
		}
	}
	if sr.Spec.Metadata != nil {
		add(sr.Spec.Metadata.Tags)
	}
	for _, rule := range sr.Spec.SecRules {
		if rule.Metadata != nil {
			add(rule.Metadata.Tags)
		}
	}
	return out
}

// PrimaryPhase returns the phase of the single-rule metadata or first bag entry.
func PrimaryPhase(sr *SecRule) string {
	if sr == nil {
		return ""
	}
	if sr.Spec.Metadata != nil && sr.Spec.Metadata.Phase != "" {
		return sr.Spec.Metadata.Phase
	}
	for _, rule := range sr.Spec.SecRules {
		if rule.Metadata != nil && rule.Metadata.Phase != "" {
			return rule.Metadata.Phase
		}
	}
	return ""
}

// FormatIDLabel returns the string form used on labels.
func FormatIDLabel(id int) string {
	if id <= 0 {
		return ""
	}
	return fmt.Sprintf("%d", id)
}
