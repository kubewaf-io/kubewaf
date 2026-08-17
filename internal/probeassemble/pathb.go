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
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"

	seclangv1beta1 "github.com/kubewaf-io/kubewaf/api/seclang/v1beta1"
	"github.com/kubewaf-io/kubewaf/api/seclang/v1beta1/convert"
	wafv1beta1 "github.com/kubewaf-io/kubewaf/api/waf/v1beta1"
)

// ErrCRSPathA is returned when a WAF requests CRS Path A (virtual includes).
var ErrCRSPathA = errors.New("CorazaCRSPathAUnsupported")

// ErrReferencesUnresolved is returned when references2.Resolve reported member errors.
var ErrReferencesUnresolved = errors.New("ReferencesUnresolved")

const (
	groupSeclang = "seclang.kubewaf.io"
	groupWAF     = "waf.kubewaf.io"
	versionV1b1  = "v1beta1"

	kindSecRule   = "SecRule"
	kindSecAction = "SecAction"
	kindRuleSet   = "RuleSet"
)

// ReferenceFailures wraps per-ref resolve errors (fail-closed for probes).
type ReferenceFailures struct {
	Messages []string
}

func (e *ReferenceFailures) Error() string {
	if e == nil {
		return ErrReferencesUnresolved.Error()
	}
	return ErrReferencesUnresolved.Error() + ": " + strings.Join(e.Messages, "; ")
}

func (e *ReferenceFailures) Unwrap() error { return ErrReferencesUnresolved }

// DefaultRuleRefs fills omitted namespace / GVK so name lookups match the
// RuleRef docs (namespace defaults to the owner) and typical sample YAML.
func DefaultRuleRefs(ownerNS string, refs []wafv1beta1.RuleRef) []wafv1beta1.RuleRef {
	if len(refs) == 0 {
		return nil
	}
	out := make([]wafv1beta1.RuleRef, len(refs))
	copy(out, refs)
	for i := range out {
		if out[i].Namespace == "" {
			out[i].Namespace = ownerNS
		}
		switch out[i].Kind {
		case kindSecRule, kindSecAction:
			if out[i].Group == "" {
				out[i].Group = groupSeclang
			}
			if out[i].Version == "" {
				out[i].Version = versionV1b1
			}
		case kindRuleSet, "":
			if out[i].Kind == "" {
				out[i].Kind = kindRuleSet
			}
			if out[i].Group == "" {
				out[i].Group = groupWAF
			}
			if out[i].Version == "" {
				out[i].Version = versionV1b1
			}
		default:
			if out[i].Group == "" {
				out[i].Group = groupWAF
			}
			if out[i].Version == "" {
				out[i].Version = versionV1b1
			}
		}
	}
	return out
}

// CRSTuningFromWAF copies WAF.spec.crs into the probe preamble helper type.
func CRSTuningFromWAF(in *wafv1beta1.CRSTuning) *CRSTuning {
	if in == nil {
		return nil
	}
	out := &CRSTuning{
		ParanoiaLevel:            in.ParanoiaLevel,
		InboundAnomalyThreshold:  in.InboundAnomalyThreshold,
		OutboundAnomalyThreshold: in.OutboundAnomalyThreshold,
		RemoveByID:               append([]int(nil), in.RemoveByID...),
		RemoveByTag:              append([]string(nil), in.RemoveByTag...),
	}
	if len(in.UpdateTargetByID) > 0 {
		out.UpdateTargetByID = make([]CRSUpdateTarget, 0, len(in.UpdateTargetByID))
		for _, te := range in.UpdateTargetByID {
			out.UpdateTargetByID = append(out.UpdateTargetByID, CRSUpdateTarget{
				ID:            te.ID,
				RemoveTargets: append([]string(nil), te.RemoveTargets...),
			})
		}
	}
	return out
}

// PhraseListPolicyFromWAF maps WAF.spec.phraseListPolicy (default FailClosed).
func PhraseListPolicyFromWAF(p wafv1beta1.PhraseListPolicy) PhraseListPolicy {
	if p == wafv1beta1.PhraseListPolicyIgnoreUnknown {
		return PhraseListPolicyIgnoreUnknown
	}
	return PhraseListPolicyFailClosed
}

// AssembleResolved converts Resolve() leaves to a Coraza-safe document.
// Nested RuleSet / ConfigMap entries are ignored (already flattened by Resolve).
// Does not import internal/coraza — convert + AssignedIDs only.
func AssembleResolved(objects []unstructured.Unstructured, stamp bool, crs *CRSTuning) (*AssemblyResult, error) {
	items := make([]pathBItem, 0, len(objects))
	for i := range objects {
		item, skip, err := pathBItemFromUnstructured(&objects[i])
		if err != nil {
			return nil, err
		}
		if skip {
			continue
		}
		items = append(items, item)
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].key != items[j].key {
			return items[i].key < items[j].key
		}
		if items[i].name != items[j].name {
			return items[i].name < items[j].name
		}
		// SecAction before SecRule at the same key (setup actions first).
		return items[i].kind < items[j].kind
	})

	ruleLines := make([]string, 0, len(items))
	var rulesN, actionsN int
	for i := range items {
		lines, err := items[i].seclangLines()
		if err != nil {
			return nil, err
		}
		ruleLines = append(ruleLines, lines...)
		switch items[i].kind {
		case kindSecRule:
			rulesN++
		case kindSecAction:
			actionsN++
		}
	}

	asm := AssembleFromRuleLines(ruleLines, stamp, crs)
	asm.RulesLoaded = rulesN
	asm.ActionsLoaded = actionsN
	return asm, nil
}

type pathBItem struct {
	kind      string
	key       int64
	name      string
	secRule   *seclangv1beta1.SecRule
	secAction *seclangv1beta1.SecAction
}

func pathBItemFromUnstructured(obj *unstructured.Unstructured) (pathBItem, bool, error) {
	if obj == nil {
		return pathBItem{}, true, nil
	}
	switch obj.GetKind() {
	case kindSecRule:
		var sr seclangv1beta1.SecRule
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(obj.Object, &sr); err != nil {
			return pathBItem{}, false, fmt.Errorf("decode SecRule %s/%s: %w", obj.GetNamespace(), obj.GetName(), err)
		}
		return pathBItem{
			kind:    kindSecRule,
			key:     secRuleSortKey(&sr),
			name:    sr.Name,
			secRule: &sr,
		}, false, nil
	case kindSecAction:
		var sa seclangv1beta1.SecAction
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(obj.Object, &sa); err != nil {
			return pathBItem{}, false, fmt.Errorf("decode SecAction %s/%s: %w", obj.GetNamespace(), obj.GetName(), err)
		}
		return pathBItem{
			kind:      kindSecAction,
			key:       secActionSortKey(&sa),
			name:      sa.Name,
			secAction: &sa,
		}, false, nil
	default:
		return pathBItem{}, true, nil
	}
}

func (it pathBItem) seclangLines() ([]string, error) {
	switch it.kind {
	case kindSecRule:
		sr := ApplyAssignedIDs(it.secRule, nil)
		if err := EnsureRuleIDs(sr); err != nil {
			return nil, fmt.Errorf("secrule %s/%s: %w", sr.Namespace, sr.Name, err)
		}
		dirs, err := convert.ConvertSecRule(*sr)
		if err != nil {
			return nil, fmt.Errorf("convert SecRule %s/%s: %w", sr.Namespace, sr.Name, err)
		}
		return splitLines(convert.ConvertToSecLangString(dirs)), nil
	case kindSecAction:
		out, err := convert.ConvertSecActionToString(*it.secAction)
		if err != nil {
			return nil, fmt.Errorf("convert SecAction %s/%s: %w", it.secAction.Namespace, it.secAction.Name, err)
		}
		return splitLines(out), nil
	default:
		return nil, nil
	}
}

func secRuleSortKey(sr *seclangv1beta1.SecRule) int64 {
	if sr == nil {
		return math.MaxInt32
	}
	if sr.Spec.Order != 0 {
		return int64(sr.Spec.Order)
	}
	if sr.Status.RuleID > 0 {
		return int64(sr.Status.RuleID)
	}
	if sr.Spec.Metadata != nil && sr.Spec.Metadata.Id > 0 {
		return int64(sr.Spec.Metadata.Id)
	}
	for _, rule := range sr.Spec.SecRules {
		if rule.Metadata != nil && rule.Metadata.Id > 0 {
			return int64(rule.Metadata.Id)
		}
	}
	return math.MaxInt32
}

func secActionSortKey(sa *seclangv1beta1.SecAction) int64 {
	if sa == nil {
		return math.MaxInt32
	}
	if sa.Spec.Metadata != nil && sa.Spec.Metadata.Id > 0 {
		return int64(sa.Spec.Metadata.Id)
	}
	return math.MaxInt32
}
