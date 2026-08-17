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

package convert

import (
	"regexp"
	"strings"

	types "github.com/coreruleset/crslang/types"
	"github.com/jinzhu/copier"
	v1beta1 "github.com/kubewaf-io/kubewaf/api/seclang/v1beta1"
)

var (
	variableReverseMapper       = VariableReverseMapperImpl{}
	variableMapper              = VariableMapperImpl{}
	operatorMapper              = OperatorReverseMapperImpl{}
	operatorForwardMapper       = OperatorMapperImpl{}
	collectionReverseMapper     = CollectionReverseMapperImpl{}
	collectionMapper            = CollectionMapperImpl{}
	transformationMapper        = TransformationMapperImpl{}
	transformationReverseMapper = TransformationMapperCSRImpl{}
)

// ConvertSecRule renders a SecRule CR into crslang directives.
// Canonical form: spec.metadata + spec.match[] (+ order / markerAfter).
// Legacy form: spec.secLangRules[] multi-rule bag (CRS bulk samples).
func ConvertSecRule(source v1beta1.SecRule) ([]types.SeclangDirective, error) {
	if source.Spec.IsSingleRuleForm() {
		return convertSingleRuleForm(source)
	}
	return convertLegacySecLangRules(source)
}

// convertSingleRuleForm builds one SecRule (+ optional N-way chain) and optional SecMarker after.
func convertSingleRuleForm(source v1beta1.SecRule) ([]types.SeclangDirective, error) {
	matches := source.Spec.Match
	if len(matches) == 0 {
		// Allow metadata-only always-match style via empty match → synthetic always-match.
		matches = []v1beta1.Match{{AlwaysMatch: true}}
	}

	// Pure always-match (no chain): emit RuleWithCondition{AlwaysMatch} so
	// FromCRSLangToUnformattedDirectives produces SecAction. A SecRule with
	// empty variables and @unconditionalMatch is invalid ModSecurity and has
	// trapped Envoy V8 as unreachable. Do not return *SecAction here — that type
	// is dropped by FromCRSLang (only *RuleWithCondition is expanded).
	if len(matches) == 1 && matches[0].AlwaysMatch {
		actions := matches[0].Actions
		if actions == nil {
			actions = source.Spec.Actions
		}
		rwc, err := alwaysMatchToRuleWithCondition(source.Spec.Metadata, matches[0], actions)
		if err != nil {
			return nil, err
		}
		out := []types.SeclangDirective{rwc}
		if source.Spec.MarkerAfter != "" {
			out = append(out, markerDirective(source.Spec.MarkerAfter))
		}
		return out, nil
	}

	// Build linked chain from match[].
	var head *types.RuleWithCondition
	var prev *types.RuleWithCondition
	for i, m := range matches {
		isLast := i == len(matches)-1
		isParent := i == 0
		linkActions := m.Actions
		if linkActions == nil {
			if isParent {
				// Parent inherits Spec.Actions (id/phase/disruptive live here).
				linkActions = source.Spec.Actions
			} else if isLast {
				// Final link may inherit non-disruptive/data from Spec, but never
				// disruptive — ModSecurity only allows deny/block/pass on the chain
				// starter ("Disruptive actions can only be specified by chain starter").
				linkActions = stripDisruptiveActions(source.Spec.Actions)
			}
			// Intermediate links with no per-match actions stay empty (except chain).
		} else if !isParent {
			// Explicit per-link actions on children: still strip disruptive.
			linkActions = stripDisruptiveActions(linkActions)
		}
		// Only the parent carries Spec.Metadata.
		var meta *v1beta1.SecRuleMetadata
		if isParent {
			meta = source.Spec.Metadata
		}
		// Always-match as a chain link is unusual; still use RuleWithCondition.
		rwc, err := matchToRuleWithCondition(meta, m, linkActions, !isLast && len(matches) > 1)
		if err != nil {
			return nil, err
		}
		if head == nil {
			head = rwc
			prev = rwc
			continue
		}
		// Only the final chain link must drop "chain". Intermediate N-way links need
		// chain so ModSecurity continues to the next SecRule (CRS multi-link chains).
		if isLast {
			removeChainFromFlowActions(rwc)
		}
		// Defense in depth: never leave disruptive on a chain child.
		if rwc.Actions.DisruptiveAction != nil {
			rwc.Actions.DisruptiveAction = nil
		}
		prev.ChainedRule = rwc
		prev = rwc
	}

	out := []types.SeclangDirective{}
	if head != nil {
		out = append(out, head)
	}
	// markerAfter is emitted AFTER the rule (skipAfter target).
	if source.Spec.MarkerAfter != "" {
		out = append(out, markerDirective(source.Spec.MarkerAfter))
	}
	return out, nil
}

// alwaysMatchToRuleWithCondition builds a RuleWithCondition that FromCRSLang
// turns into SecAction (AlwaysMatch + UnknownOperator). Setting Operator to
// UnconditionalMatch would instead produce SecRule "@unconditionalMatch" with
// empty variables, which traps Envoy V8.
func alwaysMatchToRuleWithCondition(
	meta *v1beta1.SecRuleMetadata,
	m v1beta1.Match,
	actions *v1beta1.SecRuleActions,
) (*types.RuleWithCondition, error) {
	cond := types.Condition{
		AlwaysMatch: true,
		// Leave Operator as Unknown so FromConditionToUnmorfattedDirective
		// takes the AlwaysMatch → *SecAction branch.
		Operator: types.Operator{Name: types.UnknownOperator},
	}
	mapped, err := mapAPITransformations(m.Transformations)
	if err != nil {
		return nil, err
	}
	cond.Transformations.Transformations = mapped
	rwc := &types.RuleWithCondition{
		Kind:       types.RuleKind,
		Conditions: []types.Condition{cond},
	}
	if meta != nil {
		if err := copier.Copy(&rwc.Metadata, meta); err != nil {
			return nil, err
		}
	}
	if actions != nil {
		act, err := SecActionToCSR(*actions)
		if err != nil {
			return nil, err
		}
		rwc.Actions = act
	}
	return rwc, nil
}

func convertLegacySecLangRules(source v1beta1.SecRule) ([]types.SeclangDirective, error) {
	target := []types.SeclangDirective{}

	// Manual index to properly consume chained rules (skip next entry after attaching ChainedRule).
	// Supports multi-link chains: while current has chain and next exists, keep linking.
	for i := 0; i < len(source.Spec.SecRules); i++ {
		secRule := source.Spec.SecRules[i]
		sds, err := secLangSecRuleToRuleWithCondition(secRule)
		if err != nil {
			return target, err
		}

		for _, r := range sds {
			switch rwc := r.(type) {
			case *types.RuleWithCondition:
				// Consume following entries while chain action is present.
				cur := rwc
				for hasChainInFlow(source.Spec.SecRules[i]) && i+1 < len(source.Spec.SecRules) {
					i++
					nextSecRule := source.Spec.SecRules[i]
					nextSds, err := secLangSecRuleToRuleWithCondition(nextSecRule)
					if err != nil {
						return target, err
					}
					var nextRwc *types.RuleWithCondition
					for _, nextR := range nextSds {
						if n, ok := nextR.(*types.RuleWithCondition); ok {
							nextRwc = n
							break
						}
					}
					if nextRwc == nil {
						break
					}
					removeChainFromFlowActions(nextRwc)
					// Drop marker from intermediate link; attach after whole chain later.
					cur.ChainedRule = nextRwc
					cur = nextRwc
					// Continue only if this next link also requests chain.
					if !hasChainInFlow(nextSecRule) {
						break
					}
				}
				target = append(target, rwc)
				// Legacy secMarker on the (last consumed) entry: emit AFTER the rule.
				// Find marker from the last secLangRules entry used for this chain.
				marker := secRule.SecMarker
				// Prefer marker on the last link of the chain if set.
				if i < len(source.Spec.SecRules) && source.Spec.SecRules[i].SecMarker != "" {
					marker = source.Spec.SecRules[i].SecMarker
				}
				if marker != "" {
					target = append(target, markerDirective(marker))
				}

			default:
				target = append(target, rwc)
			}
		}
	}

	// Spec-level markerAfter also applies to legacy bags (after all rules).
	if source.Spec.MarkerAfter != "" {
		target = append(target, markerDirective(source.Spec.MarkerAfter))
	}
	return target, nil
}

func markerDirective(name string) types.ConfigurationDirective {
	return types.ConfigurationDirective{
		Kind:      types.ConfigurationKind,
		Name:      types.SecMarker,
		Parameter: name,
	}
}

func matchToRuleWithCondition(
	meta *v1beta1.SecRuleMetadata,
	m v1beta1.Match,
	actions *v1beta1.SecRuleActions,
	needChain bool,
) (*types.RuleWithCondition, error) {
	// Build a temporary SecLangSecRule and reuse conversion.
	sr := v1beta1.SecLangSecRule{
		Metadata:   meta,
		Conditions: []v1beta1.Condition{m.ToCondition()},
		Actions:    actions,
	}
	if needChain {
		sr.Actions = ensureChainAction(actions)
	}
	sds, err := secLangSecRuleToRuleWithCondition(sr)
	if err != nil {
		return nil, err
	}
	for _, d := range sds {
		if rwc, ok := d.(*types.RuleWithCondition); ok {
			return rwc, nil
		}
	}
	// No rule produced (shouldn't happen).
	return &types.RuleWithCondition{Kind: types.RuleKind}, nil
}

// stripDisruptiveActions returns a copy of actions without disruptive (chain children).
func stripDisruptiveActions(actions *v1beta1.SecRuleActions) *v1beta1.SecRuleActions {
	if actions == nil {
		return nil
	}
	out := *actions
	out.DisruptiveAction = nil
	if len(actions.Flow) > 0 {
		out.Flow = append([]v1beta1.FlowAction{}, actions.Flow...)
	}
	if len(actions.NonDisruptive) > 0 {
		out.NonDisruptive = append([]v1beta1.NonDisruptiveAction{}, actions.NonDisruptive...)
	}
	if len(actions.Data) > 0 {
		out.Data = append([]v1beta1.DataAction{}, actions.Data...)
	}
	return &out
}

// ensureChainAction returns a copy of actions with flow chain present.
func ensureChainAction(actions *v1beta1.SecRuleActions) *v1beta1.SecRuleActions {
	var out v1beta1.SecRuleActions
	if actions != nil {
		out = *actions
		if actions.DisruptiveAction != nil {
			d := *actions.DisruptiveAction
			out.DisruptiveAction = &d
		}
		if len(actions.Flow) > 0 {
			out.Flow = append([]v1beta1.FlowAction{}, actions.Flow...)
		}
		if len(actions.NonDisruptive) > 0 {
			out.NonDisruptive = append([]v1beta1.NonDisruptiveAction{}, actions.NonDisruptive...)
		}
		if len(actions.Data) > 0 {
			out.Data = append([]v1beta1.DataAction{}, actions.Data...)
		}
	}
	if !hasChainInActions(&out) {
		out.Flow = append(out.Flow, v1beta1.FlowAction{Type: v1beta1.Chain})
	}
	return &out
}

func hasChainInActions(a *v1beta1.SecRuleActions) bool {
	if a == nil {
		return false
	}
	for _, f := range a.Flow {
		if f.Type == v1beta1.Chain {
			return true
		}
	}
	return false
}

func secLangSecRuleToRuleWithCondition(secRule v1beta1.SecLangSecRule) ([]types.SeclangDirective, error) {
	sds := make([]types.SeclangDirective, 0, 1)

	rwc := types.RuleWithCondition{
		Kind: types.RuleKind,
	}

	if secRule.Metadata != nil {
		if err := copier.Copy(&rwc.Metadata, secRule.Metadata); err != nil {
			return sds, err
		}
	}

	// Note: SecMarker is NOT prepended here. Callers emit markerAfter the rule.

	for _, cond := range secRule.Conditions {
		condition := types.Condition{
			AlwaysMatch: cond.AlwaysMatch,
			Script:      cond.Script,
		}

		if len(cond.Variables) > 0 {
			for _, variable := range cond.Variables {
				condition.Variables = append(condition.Variables, types.Variable{
					Name:     variableMapper.Convert(variable.Name),
					Excluded: variable.Excluded,
				})
			}
		}

		for _, collection := range cond.Collections {
			condition.Collections = append(condition.Collections, types.Collection{
				Arguments: collection.Arguments,
				Excluded:  collection.Excluded,
				Count:     collection.Count,
				Name:      collectionMapper.Convert(collection.Name),
			})
		}
		condition.Operator = types.Operator{
			Negate: cond.Operator.Negate,
			Value:  cond.Operator.Value,
		}
		if string(cond.Operator.Name) != "" {
			condition.Operator.Name = operatorForwardMapper.Convert(cond.Operator.Name)
		}
		// Always-match must keep Operator as Unknown so FromCRSLang emits SecAction.
		// Mapping to UnconditionalMatch produces SecRule "" "@unconditionalMatch"
		// which has trapped Envoy V8 as unreachable.
		if cond.AlwaysMatch {
			condition.AlwaysMatch = true
			condition.Operator = types.Operator{Name: types.UnknownOperator}
		}
		// t: transformations — error on empty/unknown (never emit t:unknown).
		mapped, err := mapAPITransformations(cond.Transformations)
		if err != nil {
			return sds, err
		}
		condition.Transformations.Transformations = mapped

		rwc.Conditions = append(rwc.Conditions, condition)
	}

	if secRule.Actions != nil {
		actions, err := SecActionToCSR(*secRule.Actions)
		if err != nil {
			return sds, err
		}
		rwc.Actions = actions
	}
	sds = append(sds, &rwc)
	return sds, nil
}

func hasChainInFlow(secRule v1beta1.SecLangSecRule) bool {
	if secRule.Actions == nil || len(secRule.Actions.Flow) == 0 {
		return false
	}
	for _, flow := range secRule.Actions.Flow {
		if flow.Type == v1beta1.Chain {
			return true
		}
	}
	return false
}

func removeChainFromFlowActions(rwc *types.RuleWithCondition) {
	if rwc == nil || len(rwc.Actions.FlowActions) == 0 {
		return
	}
	newFlow := []types.Action{}
	for _, fa := range rwc.Actions.FlowActions {
		if fa.GetKey() != "chain" {
			newFlow = append(newFlow, fa)
		}
	}
	rwc.Actions.FlowActions = newFlow
}

func ConvertCrsRule(source types.RuleWithCondition, secMarker string) (v1beta1.SecLangSecRule, error) {
	target := v1beta1.SecLangSecRule{}
	targetMetdata := v1beta1.SecRuleMetadata{}

	err := copier.Copy(&targetMetdata, source.Metadata)
	if err != nil {
		return target, err
	}
	// CRS conf comments often contain 3+ consecutive blank lines; collapse so
	// generated YAML passes yamllint empty-lines.max (see CollapseEmptyLines).
	if targetMetdata.Comment != "" {
		targetMetdata.Comment = SanitizeRuleComment(targetMetdata.Comment)
	}
	target.Metadata = &targetMetdata
	if len(source.Conditions) > 0 {
		for _, condition := range source.Conditions {
			targetCondition := v1beta1.Condition{}
			targetCondition.AlwaysMatch = condition.AlwaysMatch
			targetCondition.Script = condition.Script

			if len(condition.Variables) > 0 {
				for _, variable := range condition.Variables {
					targetVariable := v1beta1.Variable{
						Excluded: variable.Excluded,
						Name:     variableReverseMapper.Convert(variable.Name),
					}
					targetCondition.Variables = append(targetCondition.Variables, targetVariable)
				}
			}
			if len(condition.Collections) > 0 {
				for _, collection := range condition.Collections {
					targetCollection := v1beta1.Collection{
						Arguments: collection.Arguments,
						Excluded:  collection.Excluded,
						Count:     collection.Count,
						Name:      collectionReverseMapper.Convert(collection.Name),
					}
					targetCondition.Collections = append(targetCondition.Collections, targetCollection)
				}
			}
			targetCondition.Operator = v1beta1.Operator{
				Negate: condition.Operator.Negate,
				Value:  condition.Operator.Value,
				Name:   operatorMapper.Convert(condition.Operator.Name),
			}
			// crslang leaves Operator empty for SecAction (AlwaysMatch); map to
			// unconditionalMatch so CRDs never store unknownOperator.
			if condition.AlwaysMatch &&
				(targetCondition.Operator.Name == "" || targetCondition.Operator.Name == v1beta1.UnknownOperator) {
				targetCondition.Operator.Name = v1beta1.UnconditionalMatch
			}
			// Preserve t: transforms from CRS SecRule/SecAction.
			// American CRS spellings (normalizePath) alias to normalisePath;
			// unmapped transforms fail the convert (never store "" / unknown).
			mapped, err := mapCRSTransformations(condition.Transformations.Transformations)
			if err != nil {
				return target, err
			}
			targetCondition.Transformations = mapped

			target.Conditions = append(target.Conditions, targetCondition)
		}
	}
	// Action
	actions := SecActionToAPI(source.Actions)
	target.Actions = &actions
	// CRS bulk converter still uses legacy secMarker on the last bag entry.
	target.SecMarker = secMarker
	return target, nil
}

// ConvertCrsRuleToSingleForm maps a CRS RuleWithCondition (+ optional marker) into
// the canonical one-rule-per-CR Spec fields. ChainedRule is expanded into match[].
func ConvertCrsRuleToSingleForm(source types.RuleWithCondition, markerAfter string) (v1beta1.SecRuleSpec, error) {
	spec := v1beta1.SecRuleSpec{
		MarkerAfter: markerAfter,
	}
	// Walk chain into match[].
	cur := &source
	first := true
	for cur != nil {
		legacy, err := ConvertCrsRule(*cur, "")
		if err != nil {
			return spec, err
		}
		if first {
			spec.Metadata = legacy.Metadata
			// Parent actions without chain (chain is implied by match length).
			if legacy.Actions != nil {
				a := *legacy.Actions
				a.Flow = filterOutChain(a.Flow)
				spec.Actions = &a
			}
			first = false
		}
		// Prefer first condition per link; CRS links are almost always 1 condition.
		m := v1beta1.Match{}
		if len(legacy.Conditions) > 0 {
			c := legacy.Conditions[0]
			m.Variables = c.Variables
			m.Collections = c.Collections
			m.Operator = c.Operator
			m.Transformations = c.Transformations
			m.AlwaysMatch = c.AlwaysMatch
			m.Script = c.Script
		}
		// Intermediate/parent link-specific actions (except parent uses Spec.Actions).
		if cur != &source && legacy.Actions != nil {
			a := *legacy.Actions
			a.Flow = filterOutChain(a.Flow)
			m.Actions = &a
		} else if cur == &source && len(legacy.Conditions) > 1 {
			// Multiple conditions on one CRS rule without chain → multiple match entries
			// with same actions is wrong; keep as multi-condition on first match by
			// folding remaining conditions is not expressible — append as extra matches
			// only when chained. For multi-condition single rule, use Conditions path
			// via legacy. Here we only take first; extras appended as AND matches.
			for _, c := range legacy.Conditions[1:] {
				// already stored first; push extras after loop step — handled below
				_ = c
			}
		}
		// Multi-condition single (non-chain) rule: encode all conditions as sequential
		// match entries with chain (AND). Unusual in CRS but supported.
		if cur.ChainedRule == nil && len(legacy.Conditions) > 1 && len(spec.Match) == 0 {
			for _, c := range legacy.Conditions {
				mm := v1beta1.Match{
					Variables:       c.Variables,
					Collections:     c.Collections,
					Operator:        c.Operator,
					Transformations: c.Transformations,
					AlwaysMatch:     c.AlwaysMatch,
					Script:          c.Script,
				}
				spec.Match = append(spec.Match, mm)
			}
			break
		}
		spec.Match = append(spec.Match, m)
		cur = cur.ChainedRule
	}
	// Order defaults from rule id when present.
	if spec.Metadata != nil && spec.Metadata.Id > 0 {
		spec.Order = int32(spec.Metadata.Id)
	}
	return spec, nil
}

func filterOutChain(flow []v1beta1.FlowAction) []v1beta1.FlowAction {
	if len(flow) == 0 {
		return flow
	}
	out := make([]v1beta1.FlowAction, 0, len(flow))
	for _, f := range flow {
		if f.Type == v1beta1.Chain {
			continue
		}
		out = append(out, f)
	}
	return out
}

func ConvertToSecLangString(rules []types.SeclangDirective) string {
	// FromCRSLangToUnformattedDirectives only expands *RuleWithCondition.
	// Already-unformatted directives (*SecAction, *SecRule, SecMarker, …) must
	// be passed through; otherwise they become nil and ToSeclang panics.
	normalized := make([]types.SeclangDirective, 0, len(rules))
	for _, r := range rules {
		if r == nil {
			continue
		}
		switch r.(type) {
		case *types.RuleWithCondition:
			unf := types.FromCRSLangToUnformattedDirectives(types.ConfigurationList{
				DirectiveList: []types.DirectiveList{{
					Directives: []types.SeclangDirective{r},
				}},
			})
			if len(unf.DirectiveList) == 0 {
				continue
			}
			for _, d := range unf.DirectiveList[0].Directives {
				if d != nil {
					normalized = append(normalized, d)
				}
			}
		default:
			normalized = append(normalized, r)
		}
	}
	raw := types.DirectiveList{Directives: normalized}.ToSeclang()
	// crslang pretty-prints actions with "\\\n    " continuations *inside* the
	// action quote. After a full OWASP CRS load, modsecurity-proxy-wasm (Envoy
	// V8) has been observed to trap ("Uncaught RuntimeError: unreachable") on
	// those multi-line SecRules. Collapse to a single physical line for safe load.
	raw = collapseSecLangLineContinuations(raw)
	// crslang sortActions only emits one action per key except setvar/ctl, so
	// multiple initcol actions collapse to a single initcol. Re-inject the rest
	// (CRS 901320 uses two: global=global and ip=...).
	raw = expandMultiInitcol(raw, normalized)
	return raw
}

// expandMultiInitcol appends missing initcol:… actions that crslang dropped.
func expandMultiInitcol(raw string, dirs []types.SeclangDirective) string {
	var collect func(types.SeclangDirective)
	var params []string
	collect = func(d types.SeclangDirective) {
		var acts *types.SeclangActions
		switch t := d.(type) {
		case *types.SecRule:
			acts = t.Actions
			if t.ChainedRule != nil {
				collect(t.ChainedRule)
			}
		case *types.SecAction:
			acts = t.Actions
			if t.ChainedRule != nil {
				collect(t.ChainedRule)
			}
		}
		if acts == nil {
			return
		}
		for _, a := range acts.NonDisruptiveActions {
			if a == nil || a.GetKey() != "initcol" {
				continue
			}
			// ActionWithParam.ToString is initcol:'value' or similar; prefer GetParam if present.
			p := ""
			type paramGetter interface{ GetParam() string }
			if g, ok := a.(paramGetter); ok {
				p = g.GetParam()
			} else {
				s := a.ToString()
				s = strings.TrimPrefix(s, "initcol:")
				s = strings.Trim(s, "'\"")
				p = s
			}
			if p != "" {
				params = append(params, p)
			}
		}
	}
	for _, d := range dirs {
		collect(d)
	}
	if len(params) <= 1 {
		return raw
	}
	// Ensure every initcol:param appears (unquoted).
	for _, p := range params {
		token := "initcol:" + p
		if strings.Contains(raw, token) {
			continue
		}
		// Insert after the first initcol:… occurrence in the file.
		idx := strings.Index(raw, "initcol:")
		if idx < 0 {
			// No initcol emitted — append before the closing quote of the last action list.
			// Fallback: append near end of first SecRule action quote (best-effort).
			continue
		}
		// Find end of existing initcol token (until comma or quote).
		end := idx
		for end < len(raw) && raw[end] != ',' && raw[end] != '"' && raw[end] != '\n' {
			end++
		}
		raw = raw[:end] + "," + token + raw[end:]
	}
	return raw
}

// seclangLineCont matches a SecLang line continuation: backslash, newline, indent.
var seclangLineCont = regexp.MustCompile(`\\\r?\n[ \t]*`)

// crslang quotes status/severity as status:'403' / severity:'ERROR'.
// It also quotes initcol as initcol:'global=global'; CRS/ModSecurity expects
// initcol:global=global (unquoted). Quoted initcol has trapped Envoy V8.
// skipAfter is similarly unquoted in CRS catalog (skipAfter:END-FOO).
var (
	statusQuoted    = regexp.MustCompile(`status:'(\d+)'`)
	severityQuoted  = regexp.MustCompile(`severity:'([^']*)'`)
	initcolQuoted   = regexp.MustCompile(`initcol:'([^']*)'`)
	skipAfterQuoted = regexp.MustCompile(`skipAfter:'([^']*)'`)
)

// severityNameToLevel maps ModSecurity severity names to 0–7 (RFC 5424).
var severityNameToLevel = map[string]string{
	"EMERGENCY": "0",
	"ALERT":     "1",
	"CRITICAL":  "2",
	"ERROR":     "3",
	"WARNING":   "4",
	"NOTICE":    "5",
	"INFO":      "6",
	"DEBUG":     "7",
}

// collapseSecLangLineContinuations joins multi-line SecRule/SecAction pretty-print
// into one line per directive and normalizes common action quoting for ModSecurity.
func collapseSecLangLineContinuations(s string) string {
	if s == "" {
		return s
	}
	// First join "\\\n" continuations (including inside action quotes).
	s = seclangLineCont.ReplaceAllString(s, "")
	// Normalize any remaining "action,    phase" double-spaces from indent collapse.
	s = strings.ReplaceAll(s, ",    ", ",")
	// status:403 (numeric, unquoted) is the usual ModSecurity form.
	s = statusQuoted.ReplaceAllString(s, `status:$1`)
	// initcol:name=value (unquoted) matches CRS catalog / libmodsecurity.
	s = initcolQuoted.ReplaceAllString(s, `initcol:$1`)
	// skipAfter:MARKER unquoted (CRS style).
	s = skipAfterQuoted.ReplaceAllString(s, `skipAfter:$1`)
	// severity: prefer numeric 0-7 — named severity after a full CRS load has trapped
	// in modsecurity-proxy-wasm (Envoy V8 unreachable) for some custom rules.
	s = severityQuoted.ReplaceAllStringFunc(s, func(m string) string {
		sub := severityQuoted.FindStringSubmatch(m)
		if len(sub) != 2 {
			return m
		}
		name := strings.ToUpper(strings.TrimSpace(sub[1]))
		if n, ok := severityNameToLevel[name]; ok {
			return "severity:" + n
		}
		// Already numeric or unknown — emit unquoted.
		return "severity:" + sub[1]
	})
	// Also handle already-unquoted named severity from a prior pass.
	for name, n := range severityNameToLevel {
		s = strings.ReplaceAll(s, "severity:"+name, "severity:"+n)
		s = strings.ReplaceAll(s, "severity:"+strings.ToLower(name), "severity:"+n)
	}
	return strings.TrimRight(s, " \t\r\n") + "\n"
}
