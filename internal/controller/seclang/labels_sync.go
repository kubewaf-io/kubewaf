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

package seclang

import (
	"strconv"
	"strings"

	seclangv1beta1 "github.com/kubewaf-io/kubewaf/api/seclang/v1beta1"
)

// syncSecRuleLabels mirrors id, phase, id-source, and tags onto labels.
// Tag labels are rebuilt from spec metadata tags (prefix seclang.kubewaf.io/tag.).
// Returns true if labels or sticky annotation changed.
func syncSecRuleLabels(sr *seclangv1beta1.SecRule, primaryID int, idSource string) bool {
	if sr.Labels == nil {
		sr.Labels = map[string]string{}
	}
	if sr.Annotations == nil {
		sr.Annotations = map[string]string{}
	}
	changed := false

	set := func(k, v string) {
		if v == "" {
			if _, ok := sr.Labels[k]; ok {
				delete(sr.Labels, k)
				changed = true
			}
			return
		}
		if sr.Labels[k] != v {
			sr.Labels[k] = v
			changed = true
		}
	}

	set(seclangv1beta1.LabelID, seclangv1beta1.FormatIDLabel(primaryID))
	set(seclangv1beta1.LabelPhase, seclangv1beta1.PrimaryPhase(sr))
	set(seclangv1beta1.LabelIDSource, idSource)
	if sr.Spec.Order != 0 {
		set(seclangv1beta1.LabelOrder, strconv.FormatInt(int64(sr.Spec.Order), 10))
	} else {
		set(seclangv1beta1.LabelOrder, "")
	}

	// Sticky auto id on primary when Auto or Mixed.
	if idSource == seclangv1beta1.IDSourceAuto || idSource == seclangv1beta1.IDSourceMixed {
		if primaryID > 0 {
			want := strconv.Itoa(primaryID)
			if sr.Annotations[seclangv1beta1.AnnotationAssignedID] != want {
				sr.Annotations[seclangv1beta1.AnnotationAssignedID] = want
				changed = true
			}
		}
	}

	// Rebuild tag labels from spec.
	desiredTags := map[string]struct{}{}
	for _, tag := range seclangv1beta1.CollectTagsFromSecRule(sr) {
		key := seclangv1beta1.TagToLabelKey(tag)
		if key == "" {
			continue
		}
		desiredTags[key] = struct{}{}
		if sr.Labels[key] != "true" {
			sr.Labels[key] = "true"
			changed = true
		}
	}
	// Drop stale tag labels we manage.
	for k := range sr.Labels {
		if !strings.HasPrefix(k, seclangv1beta1.LabelTagPrefix) {
			continue
		}
		if _, ok := desiredTags[k]; !ok {
			delete(sr.Labels, k)
			changed = true
		}
	}
	return changed
}
