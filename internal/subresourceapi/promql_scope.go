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

package subresourceapi

import (
	"fmt"
	"strings"
	"unicode"
)

// WAFIdentity is the Prom/Jaeger scope for one WAF object.
type WAFIdentity struct {
	Namespace string
	Name      string
}

var promqlKeywords = map[string]struct{}{
	"and": {}, "or": {}, "unless": {}, "by": {}, "without": {},
	"on": {}, "ignoring": {}, "group_left": {}, "group_right": {},
	"bool": {}, "offset": {}, "inf": {}, "nan": {}, "atan2": {},
}

var promqlAggregators = map[string]struct{}{
	"sum": {}, "min": {}, "max": {}, "avg": {}, "group": {},
	"stddev": {}, "stdvar": {}, "count": {}, "count_values": {},
	"bottomk": {}, "topk": {}, "quantile": {},
}

// rangeVectorFuncs take a range-vector argument. Multi-WAF unions must
// distribute the function: increase(s1[5m]) or increase(s2[5m]), never
// increase((s1[5m] or s2[5m])).
var rangeVectorFuncs = map[string]struct{}{
	"increase": {}, "rate": {}, "irate": {}, "delta": {}, "idelta": {},
	"deriv": {}, "resets": {}, "changes": {}, "predict_linear": {},
	"avg_over_time": {}, "min_over_time": {}, "max_over_time": {},
	"sum_over_time": {}, "count_over_time": {}, "stddev_over_time": {},
	"stdvar_over_time": {}, "last_over_time": {}, "present_over_time": {},
	"absent_over_time": {}, "holt_winters": {},
}

const maxPromQLUnionWAFs = 256

// ScopePromQL injects waf_namespace/waf_name into every vector selector.
// Conflicting identity matchers are rejected rather than forwarded.
func ScopePromQL(query, ns, name string) (string, error) {
	if strings.TrimSpace(query) == "" {
		return "", fmt.Errorf("empty query")
	}
	if ns == "" || name == "" {
		return "", fmt.Errorf("missing WAF identity")
	}
	return rewritePromQL(query, []WAFIdentity{{Namespace: ns, Name: name}})
}

// ScopePromQLToWAFs rewrites every selector as an or-union of authorized identities.
func ScopePromQLToWAFs(query string, ids []WAFIdentity) (string, error) {
	if strings.TrimSpace(query) == "" {
		return "", fmt.Errorf("empty query")
	}
	if len(ids) == 0 {
		// Scalar zero — no series, no tenant leak.
		return "vector(0)", nil
	}
	if len(ids) > maxPromQLUnionWAFs {
		ids = ids[:maxPromQLUnionWAFs]
	}
	return rewritePromQL(query, ids)
}

func rewritePromQL(query string, ids []WAFIdentity) (string, error) {
	var b strings.Builder
	b.Grow(len(query) + 64*len(ids))
	i := 0
	for i < len(query) {
		c := query[i]
		if c == '"' || c == '\'' {
			end, err := skipQuoted(query, i)
			if err != nil {
				return "", err
			}
			b.WriteString(query[i:end])
			i = end
			continue
		}
		if isNumberStart(query, i) {
			end := skipNumber(query, i)
			b.WriteString(query[i:end])
			i = end
			continue
		}
		if c == '[' {
			end, err := skipBracket(query, i)
			if err != nil {
				return "", err
			}
			b.WriteString(query[i:end])
			i = end
			continue
		}
		if c == '{' {
			out, next, err := rewriteSelectorAt(query, "", i, ids)
			if err != nil {
				return "", err
			}
			b.WriteString(out)
			i = next
			continue
		}
		if isIdentStart(rune(c)) {
			ident, next := readIdent(query, i)
			low := strings.ToLower(ident)
			if _, kw := promqlKeywords[low]; kw {
				b.WriteString(ident)
				i = next
				if isGroupingKeyword(low) {
					i = copyGroupingList(&b, query, i)
				}
				continue
			}
			j := skipSpace(query, next)
			if j < len(query) && query[j] == '(' {
				if _, ok := rangeVectorFuncs[low]; ok {
					out, after, ok, err := rewriteRangeFuncCall(query, ident, j, ids)
					if err != nil {
						return "", err
					}
					if ok {
						b.WriteString(out)
						i = after
						continue
					}
				}
				b.WriteString(ident)
				i = next
				continue
			}
			if _, agg := promqlAggregators[low]; agg && isAggModifier(query, j) {
				b.WriteString(ident)
				i = next
				continue
			}
			if j < len(query) && query[j] == '{' {
				out, after, err := rewriteSelectorAt(query, ident, j, ids)
				if err != nil {
					return "", err
				}
				b.WriteString(out)
				i = after
				continue
			}
			// Bare metric name (up, http_requests_total, …).
			out, after, err := rewriteNamedMetric(query, ident, next, ids)
			if err != nil {
				return "", err
			}
			b.WriteString(out)
			i = after
			continue
		}
		b.WriteByte(c)
		i++
	}
	return b.String(), nil
}

func isGroupingKeyword(low string) bool {
	switch low {
	case "by", "without", "on", "ignoring", "group_left", "group_right":
		return true
	}
	return false
}

func isAggModifier(q string, j int) bool {
	if j >= len(q) {
		return false
	}
	if q[j] == '(' {
		return true
	}
	ident, next := readIdent(q, j)
	low := strings.ToLower(ident)
	if low != "by" && low != "without" {
		return false
	}
	k := skipSpace(q, next)
	return k < len(q) && q[k] == '('
}

func copyGroupingList(b *strings.Builder, q string, i int) int {
	j := skipSpace(q, i)
	if j >= len(q) || q[j] != '(' {
		return i
	}
	end, err := skipParen(q, j)
	if err != nil {
		return i
	}
	b.WriteString(q[i:end])
	return end
}

func rewriteSelectorAt(q, metric string, braceStart int, ids []WAFIdentity) (string, int, error) {
	sel, after, err := readSelector(q, braceStart)
	if err != nil {
		return "", braceStart, err
	}
	inner := strings.TrimSpace(strings.TrimPrefix(strings.TrimSuffix(sel, "}"), "{"))
	return emitScopedSelectors(q, metric, inner, after, ids)
}

func rewriteNamedMetric(q, metric string, afterIdent int, ids []WAFIdentity) (string, int, error) {
	return emitScopedSelectors(q, metric, "", afterIdent, ids)
}

// rewriteRangeFuncCall rewrites func(selector[range] extra) as
// func(s1[range] extra) or func(s2[range] extra) for multi-WAF unions.
// Returns ok=false when the argument is not a simple selector (caller falls back).
func rewriteRangeFuncCall(q, ident string, parenIdx int, ids []WAFIdentity) (string, int, bool, error) {
	i := skipSpace(q, parenIdx+1)
	metric := ""
	if i < len(q) && isIdentStart(rune(q[i])) {
		metric, i = readIdent(q, i)
		i = skipSpace(q, i)
	}
	inner := ""
	afterSel := i
	if i < len(q) && q[i] == '{' {
		sel, after, err := readSelector(q, i)
		if err != nil {
			return "", parenIdx, false, err
		}
		inner = strings.TrimSpace(strings.TrimPrefix(strings.TrimSuffix(sel, "}"), "{"))
		afterSel = after
	} else if metric == "" {
		return "", parenIdx, false, nil
	}
	parts, afterSel, err := scopedSelectorParts(q, metric, inner, afterSel, ids)
	if err != nil {
		return "", parenIdx, false, err
	}
	end, err := skipParen(q, parenIdx)
	if err != nil {
		return "", parenIdx, false, err
	}
	extra := q[afterSel : end-1]
	if strings.ContainsAny(extra, "{}") {
		// Subquery / nested selector — let the generic walker handle it.
		return "", parenIdx, false, nil
	}
	calls := make([]string, 0, len(parts))
	for _, p := range parts {
		calls = append(calls, ident+"("+p+extra+")")
	}
	if len(calls) == 1 {
		return calls[0], end, true, nil
	}
	return "(" + strings.Join(calls, " or ") + ")", end, true, nil
}

func emitScopedSelectors(q, metric, inner string, afterSel int, ids []WAFIdentity) (string, int, error) {
	parts, after, err := scopedSelectorParts(q, metric, inner, afterSel, ids)
	if err != nil {
		return "", afterSel, err
	}
	if len(parts) == 1 {
		return parts[0], after, nil
	}
	return "(" + strings.Join(parts, " or ") + ")", after, nil
}

func scopedSelectorParts(q, metric, inner string, afterSel int, ids []WAFIdentity) ([]string, int, error) {
	if err := rejectForeignIdentity(inner, ids); err != nil {
		return nil, afterSel, err
	}
	cleaned := stripIdentityMatchers(inner)
	rangeStr := ""
	j := skipSpace(q, afterSel)
	if j < len(q) && q[j] == '[' {
		end, err := skipBracket(q, j)
		if err != nil {
			return nil, afterSel, err
		}
		rangeStr = q[afterSel:end]
		afterSel = end
	}
	parts := make([]string, 0, len(ids))
	for _, id := range ids {
		sel, err := injectIdentity(metric, cleaned, id)
		if err != nil {
			return nil, afterSel, err
		}
		parts = append(parts, sel+rangeStr)
	}
	return parts, afterSel, nil
}

func injectIdentity(metric, inner string, id WAFIdentity) (string, error) {
	if id.Namespace == "" || id.Name == "" {
		return "", fmt.Errorf("invalid WAF identity")
	}
	scope := fmt.Sprintf(`waf_namespace=%q,waf_name=%q`, id.Namespace, id.Name)
	var body string
	if strings.TrimSpace(inner) == "" {
		body = scope
	} else {
		body = scope + "," + strings.TrimSpace(inner)
	}
	if metric == "" {
		return "{" + body + "}", nil
	}
	return metric + "{" + body + "}", nil
}

func rejectForeignIdentity(inner string, allowed []WAFIdentity) error {
	ns, name, err := extractIdentityMatchers(inner)
	if err != nil {
		return err
	}
	if ns == "" && name == "" {
		return nil
	}
	for _, id := range allowed {
		if (ns == "" || ns == id.Namespace) && (name == "" || name == id.Name) {
			return nil
		}
	}
	return fmt.Errorf("query identity escapes authorized WAF scope")
}

func extractIdentityMatchers(inner string) (ns, name string, err error) {
	matchers, err := splitMatchers(inner)
	if err != nil {
		return "", "", err
	}
	for _, m := range matchers {
		key, op, val, ok := parseMatcher(m)
		if !ok {
			continue
		}
		if op != "=" {
			if key == "waf_namespace" || key == "waf_name" {
				return "", "", fmt.Errorf("identity matcher %s must be exact equality", key)
			}
			continue
		}
		switch key {
		case "waf_namespace":
			ns = val
		case "waf_name":
			name = val
		}
	}
	return ns, name, nil
}

func stripIdentityMatchers(inner string) string {
	matchers, err := splitMatchers(inner)
	if err != nil {
		return inner
	}
	keep := make([]string, 0, len(matchers))
	for _, m := range matchers {
		key, _, _, ok := parseMatcher(m)
		if ok && (key == "waf_namespace" || key == "waf_name") {
			continue
		}
		keep = append(keep, m)
	}
	return strings.Join(keep, ",")
}

func splitMatchers(inner string) ([]string, error) {
	inner = strings.TrimSpace(inner)
	if inner == "" {
		return nil, nil
	}
	var (
		parts []string
		cur   strings.Builder
		quote byte
	)
	for i := 0; i < len(inner); i++ {
		c := inner[i]
		if quote != 0 {
			cur.WriteByte(c)
			if c == '\\' && i+1 < len(inner) {
				i++
				cur.WriteByte(inner[i])
				continue
			}
			if c == quote {
				quote = 0
			}
			continue
		}
		if c == '"' || c == '\'' {
			quote = c
			cur.WriteByte(c)
			continue
		}
		if c == ',' {
			parts = append(parts, strings.TrimSpace(cur.String()))
			cur.Reset()
			continue
		}
		cur.WriteByte(c)
	}
	if quote != 0 {
		return nil, fmt.Errorf("unterminated matcher string")
	}
	if s := strings.TrimSpace(cur.String()); s != "" {
		parts = append(parts, s)
	}
	return parts, nil
}

func parseMatcher(m string) (key, op, val string, ok bool) {
	m = strings.TrimSpace(m)
	for _, cand := range []string{"=~", "!~", "!=", "="} {
		if i := strings.Index(m, cand); i > 0 {
			key = strings.TrimSpace(m[:i])
			rest := strings.TrimSpace(m[i+len(cand):])
			val = unquoteProm(rest)
			return key, cand, val, key != ""
		}
	}
	return "", "", "", false
}

func unquoteProm(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && (s[0] == '"' || s[0] == '\'') && s[len(s)-1] == s[0] {
		return s[1 : len(s)-1]
	}
	return s
}

func readSelector(q string, start int) (string, int, error) {
	if start >= len(q) || q[start] != '{' {
		return "", start, fmt.Errorf("expected '{'")
	}
	quote := byte(0)
	for i := start + 1; i < len(q); i++ {
		c := q[i]
		if quote != 0 {
			if c == '\\' && i+1 < len(q) {
				i++
				continue
			}
			if c == quote {
				quote = 0
			}
			continue
		}
		if c == '"' || c == '\'' {
			quote = c
			continue
		}
		if c == '}' {
			return q[start : i+1], i + 1, nil
		}
	}
	return "", start, fmt.Errorf("unterminated selector")
}

func skipBracket(q string, start int) (int, error) {
	if start >= len(q) || q[start] != '[' {
		return start, fmt.Errorf("expected '['")
	}
	quote := byte(0)
	depth := 0
	for i := start; i < len(q); i++ {
		c := q[i]
		if quote != 0 {
			if c == '\\' && i+1 < len(q) {
				i++
				continue
			}
			if c == quote {
				quote = 0
			}
			continue
		}
		if c == '"' || c == '\'' {
			quote = c
			continue
		}
		if c == '[' {
			depth++
			continue
		}
		if c == ']' {
			depth--
			if depth == 0 {
				return i + 1, nil
			}
		}
	}
	return start, fmt.Errorf("unterminated range")
}

func skipParen(q string, start int) (int, error) {
	if start >= len(q) || q[start] != '(' {
		return start, fmt.Errorf("expected '('")
	}
	quote := byte(0)
	depth := 0
	for i := start; i < len(q); i++ {
		c := q[i]
		if quote != 0 {
			if c == '\\' && i+1 < len(q) {
				i++
				continue
			}
			if c == quote {
				quote = 0
			}
			continue
		}
		if c == '"' || c == '\'' {
			quote = c
			continue
		}
		if c == '(' {
			depth++
			continue
		}
		if c == ')' {
			depth--
			if depth == 0 {
				return i + 1, nil
			}
		}
	}
	return start, fmt.Errorf("unterminated grouping")
}

func isNumberStart(q string, i int) bool {
	if i >= len(q) {
		return false
	}
	if q[i] >= '0' && q[i] <= '9' {
		return true
	}
	if q[i] == '.' && i+1 < len(q) && q[i+1] >= '0' && q[i+1] <= '9' {
		return true
	}
	return false
}

func skipNumber(q string, i int) int {
	for i < len(q) && q[i] >= '0' && q[i] <= '9' {
		i++
	}
	if i < len(q) && q[i] == '.' {
		i++
		for i < len(q) && q[i] >= '0' && q[i] <= '9' {
			i++
		}
	}
	if i < len(q) && (q[i] == 'e' || q[i] == 'E') {
		j := i + 1
		if j < len(q) && (q[j] == '+' || q[j] == '-') {
			j++
		}
		if j < len(q) && q[j] >= '0' && q[j] <= '9' {
			i = j
			for i < len(q) && q[i] >= '0' && q[i] <= '9' {
				i++
			}
		}
	}
	return i
}

func skipQuoted(q string, start int) (int, error) {
	if start >= len(q) {
		return start, fmt.Errorf("unterminated string")
	}
	quote := q[start]
	for i := start + 1; i < len(q); i++ {
		if q[i] == '\\' && i+1 < len(q) {
			i++
			continue
		}
		if q[i] == quote {
			return i + 1, nil
		}
	}
	return start, fmt.Errorf("unterminated string")
}

func readIdent(q string, start int) (string, int) {
	i := start
	for i < len(q) {
		r := rune(q[i])
		if i == start {
			if !isIdentStart(r) {
				break
			}
		} else if !isIdentCont(r) {
			break
		}
		i++
	}
	return q[start:i], i
}

func skipSpace(q string, i int) int {
	for i < len(q) && (q[i] == ' ' || q[i] == '\t' || q[i] == '\n' || q[i] == '\r') {
		i++
	}
	return i
}

func isIdentStart(r rune) bool {
	return r == '_' || r == ':' || unicode.IsLetter(r)
}

func isIdentCont(r rune) bool {
	return isIdentStart(r) || unicode.IsDigit(r)
}
