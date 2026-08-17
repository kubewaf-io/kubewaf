package references2

import (
	"fmt"
	"math"
	"sort"

	"github.com/kubewaf-io/kubewaf/api/seclang/v1beta1"
	"github.com/kubewaf-io/kubewaf/api/seclang/v1beta1/convert"
	"github.com/kubewaf-io/kubewaf/internal/seclang"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
)

// Note: SecRule Ready is Coraza-on-operator only. Assembly must not hard-gate on it
// (see GetSecLang). Convert failures remain hard errors.

// langItem is one SecRule or SecAction to assemble into the dataplane directive list.
type langItem struct {
	kind string
	key  int64
	name string
	// Exactly one of these is set.
	secRule   *v1beta1.SecRule
	secAction *v1beta1.SecAction
}

// CountSecLangObjects returns how many SecRule and SecAction objects are present.
// Nested RuleSet list entries and other kinds are ignored.
func CountSecLangObjects(objects []unstructured.Unstructured) (rules, actions int) {
	for i := range objects {
		switch objects[i].GetKind() {
		case "SecRule":
			rules++
		case "SecAction":
			actions++
		}
	}
	return rules, actions
}

// GetSecRule converts SecRule and SecAction objects into ordered SecLang strings.
// Other kinds in the list are ignored. Name kept for call-site compatibility.
//
// Sort order (stable, ascending):
//  1. spec.order (SecRule) when non-zero
//  2. else status.ruleId / metadata.id / first bag rule id
//  3. object name (tie-break)
//
// Items with no order/id sort last.
func GetSecRule(objects []unstructured.Unstructured) ([]string, error) {
	return GetSecLang(objects)
}

// GetSecLang is the preferred name for assembling SecRule + SecAction SecLang.
func GetSecLang(objects []unstructured.Unstructured) ([]string, error) {
	items := make([]langItem, 0, len(objects))
	for _, obj := range objects {
		switch obj.GetKind() {
		case "SecRule":
			var sr v1beta1.SecRule
			if err := runtime.DefaultUnstructuredConverter.FromUnstructured(obj.Object, &sr); err != nil {
				return nil, err
			}
			items = append(items, langItem{
				kind:    "SecRule",
				key:     secRuleSortKey(&sr),
				name:    sr.Name,
				secRule: &sr,
			})
		case "SecAction":
			var sa v1beta1.SecAction
			if err := runtime.DefaultUnstructuredConverter.FromUnstructured(obj.Object, &sa); err != nil {
				return nil, err
			}
			items = append(items, langItem{
				kind:      "SecAction",
				key:       secActionSortKey(&sa),
				name:      sa.Name,
				secAction: &sa,
			})
		}
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].key != items[j].key {
			return items[i].key < items[j].key
		}
		if items[i].name != items[j].name {
			return items[i].name < items[j].name
		}
		// SecAction before SecRule at same key (setup-style actions first).
		return items[i].kind < items[j].kind
	})

	rules := make([]string, 0, len(items))
	for i := range items {
		switch items[i].kind {
		case "SecRule":
			sr := items[i].secRule
			// Always re-convert from Spec for dataplane assembly (shared render path).
			//
			// Do NOT refuse assembly when status Ready=False. The SecRule controller
			// validates with Coraza on the operator, which is not authoritative for
			// ModSecurity Path B: @pmFromFile (and similar) needs the wasm-side CRS
			// data catalog (e.g. scanners-user-agents.data). Coraza marks those
			// Ready=False with "open /….data: no such file", but the rules are still
			// valid for modsecurity-proxy-wasm. Convert errors still fail assembly.
			res, err := seclang.RenderSecRule(sr, sr.Status.AssignedIDs)
			if err != nil {
				return rules, fmt.Errorf("secrule %s/%s: %w", sr.Namespace, sr.Name, err)
			}
			rules = append(rules, res.SecLang)
		case "SecAction":
			sa := items[i].secAction
			out, err := convert.ConvertSecActionToString(*sa)
			if err != nil {
				return rules, err
			}
			rules = append(rules, out)
		}
	}
	return rules, nil
}

// secRuleSortKey returns the assembly order key for a SecRule.
func secRuleSortKey(sr *v1beta1.SecRule) int64 {
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

// secActionSortKey uses metadata.id (setup SecActions often use low ids like 900000).
func secActionSortKey(sa *v1beta1.SecAction) int64 {
	if sa == nil {
		return math.MaxInt32
	}
	if sa.Spec.Metadata != nil && sa.Spec.Metadata.Id > 0 {
		return int64(sa.Spec.Metadata.Id)
	}
	return math.MaxInt32
}
