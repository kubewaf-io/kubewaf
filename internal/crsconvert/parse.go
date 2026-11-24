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

// Package crsconvert turns upstream CRS conf into v1alpha1 SecRule and SecAction.
// It does not use crslang. Directives other than SecRule, SecAction, and SecMarker are skipped.
package crsconvert

import (
	"fmt"
	"strconv"
	"strings"

	seclangv1alpha1 "github.com/kubewaf-io/kubewaf/api/seclang/v1alpha1"
)

// Object is one converted rule or action.
type Object struct {
	Rule   *seclangv1alpha1.SecRule
	Action *seclangv1alpha1.SecAction
}

// Parse reads one CRS conf file. SecMarker is stored on the preceding object as markerAfter.
func Parse(src, namePrefix string) ([]Object, error) {
	lines, err := directives(src)
	if err != nil {
		return nil, err
	}
	var out []Object
	var open *seclangv1alpha1.SecRule
	for _, line := range lines {
		switch {
		case strings.HasPrefix(line, "SecRule "):
			link, meta, chained, err := parseRule(line)
			if err != nil {
				return nil, err
			}
			if open != nil {
				open.Spec.Chain = append(open.Spec.Chain, link)
				if !chained {
					open = nil
				}
				continue
			}
			rule := &seclangv1alpha1.SecRule{Spec: seclangv1alpha1.SecRuleSpec{
				Metadata: meta,
				Chain:    []seclangv1alpha1.ChainLink{link},
			}}
			out = append(out, Object{Rule: rule})
			if chained {
				open = rule
			}
		case strings.HasPrefix(line, "SecAction "):
			if open != nil {
				return nil, fmt.Errorf("SecAction while a chain is open")
			}
			action, err := parseAction(line)
			if err != nil {
				return nil, err
			}
			out = append(out, Object{Action: action})
		case strings.HasPrefix(line, "SecMarker "):
			name, err := markerName(line)
			if err != nil {
				return nil, err
			}
			if err := setMarker(out, name); err != nil {
				return nil, err
			}
		default:
			if open != nil {
				return nil, fmt.Errorf("unsupported directive while a chain is open: %s", head(line))
			}
		}
	}
	if open != nil {
		return nil, fmt.Errorf("chain was not closed")
	}
	for i := range out {
		if err := nameObject(&out[i], namePrefix); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func directives(src string) ([]string, error) {
	var out []string
	var b strings.Builder
	continuing := false
	for _, raw := range strings.Split(src, "\n") {
		trim := strings.TrimSpace(strings.TrimRight(raw, "\r"))
		if !continuing && (trim == "" || strings.HasPrefix(trim, "#")) {
			continue
		}
		if strings.HasSuffix(trim, `\`) {
			b.WriteString(strings.TrimSpace(trim[:len(trim)-1]))
			continuing = true
			continue
		}
		b.WriteString(trim)
		out = append(out, strings.TrimSpace(b.String()))
		b.Reset()
		continuing = false
	}
	if continuing {
		return nil, fmt.Errorf("file ends with a continuation")
	}
	return out, nil
}

func parseRule(line string) (seclangv1alpha1.ChainLink, seclangv1alpha1.Metadata, bool, error) {
	rest := strings.TrimSpace(strings.TrimPrefix(line, "SecRule"))
	opAt := strings.Index(rest, `"`)
	if opAt < 0 {
		return seclangv1alpha1.ChainLink{}, seclangv1alpha1.Metadata{}, false, fmt.Errorf("SecRule has no quoted operator")
	}
	targets, err := parseTargets(strings.TrimSpace(rest[:opAt]))
	if err != nil {
		return seclangv1alpha1.ChainLink{}, seclangv1alpha1.Metadata{}, false, err
	}
	operator, rest, err := takeQuoted(strings.TrimSpace(rest[opAt:]))
	if err != nil {
		return seclangv1alpha1.ChainLink{}, seclangv1alpha1.Metadata{}, false, err
	}
	body := ""
	if strings.TrimSpace(rest) != "" {
		body, _, err = takeQuoted(strings.TrimSpace(rest))
		if err != nil {
			return seclangv1alpha1.ChainLink{}, seclangv1alpha1.Metadata{}, false, err
		}
	}
	op, err := parseOperator(operator)
	if err != nil {
		return seclangv1alpha1.ChainLink{}, seclangv1alpha1.Metadata{}, false, err
	}
	link := seclangv1alpha1.ChainLink{Targets: targets, Operator: op}
	meta, chained, err := fillActions(body, &link)
	return link, meta, chained, err
}

func parseAction(line string) (*seclangv1alpha1.SecAction, error) {
	rest := strings.TrimSpace(strings.TrimPrefix(line, "SecAction"))
	body, _, err := takeQuoted(rest)
	if err != nil {
		return nil, err
	}
	link := seclangv1alpha1.ChainLink{}
	meta, chained, err := fillActions(body, &link)
	if err != nil {
		return nil, err
	}
	if chained {
		return nil, fmt.Errorf("SecAction cannot chain")
	}
	return &seclangv1alpha1.SecAction{Spec: seclangv1alpha1.SecActionSpec{
		Metadata:        meta,
		Transformations: link.Transformations,
		Actions:         link.Actions,
	}}, nil
}

func parseTargets(s string) ([]seclangv1alpha1.Target, error) {
	parts, err := splitTargets(s)
	if err != nil {
		return nil, err
	}
	var out []seclangv1alpha1.Target
	for _, part := range parts {
		t := seclangv1alpha1.Target{}
		if strings.HasPrefix(part, "&") {
			t.Count = true
			part = part[1:]
		}
		if strings.HasPrefix(part, "!") {
			t.Exclude = true
			part = part[1:]
		}
		name, sel, _ := strings.Cut(part, ":")
		if name == "" {
			return nil, fmt.Errorf("empty target")
		}
		t.Name = seclangv1alpha1.VariableName(name)
		t.Selector = sel
		out = append(out, t)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("SecRule has no targets")
	}
	return out, nil
}

func splitTargets(s string) ([]string, error) {
	var out []string
	var b strings.Builder
	regex := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !regex && c == '/' && i > 0 && s[i-1] == ':' && closingSlash(s, i+1) {
			regex = true
		} else if regex && c == '/' && s[i-1] != '\\' {
			regex = false
		}
		if c == '|' && !regex {
			out = append(out, strings.TrimSpace(b.String()))
			b.Reset()
			continue
		}
		b.WriteByte(c)
	}
	if regex {
		return nil, fmt.Errorf("unclosed target regex in %s", s)
	}
	if strings.TrimSpace(b.String()) != "" {
		out = append(out, strings.TrimSpace(b.String()))
	}
	return out, nil
}

func closingSlash(s string, from int) bool {
	for j := from; j < len(s); j++ {
		if s[j] == '/' && s[j-1] != '\\' {
			return true
		}
	}
	return false
}

func parseOperator(s string) (seclangv1alpha1.Operator, error) {
	op := seclangv1alpha1.Operator{}
	if strings.HasPrefix(s, "!") {
		op.Negate = true
		s = s[1:]
	}
	if !strings.HasPrefix(s, "@") {
		return op, fmt.Errorf("operator %q does not start with @", s)
	}
	name, value, _ := strings.Cut(s[1:], " ")
	token, ok := seclangv1alpha1.CanonicalOperator(seclangv1alpha1.OperatorName(name))
	if !ok {
		return op, fmt.Errorf("unknown operator %q", name)
	}
	op.Name = seclangv1alpha1.OperatorName(token)
	op.Value = strings.TrimSpace(value)
	return op, nil
}

func fillActions(body string, link *seclangv1alpha1.ChainLink) (seclangv1alpha1.Metadata, bool, error) {
	var meta seclangv1alpha1.Metadata
	var trans []seclangv1alpha1.Transformation
	actions := &seclangv1alpha1.Actions{}
	chained := false
	for _, raw := range splitList(body) {
		name, value, hasValue := strings.Cut(raw, ":")
		name = strings.TrimSpace(name)
		if hasValue {
			value = unquote(strings.TrimSpace(value))
		}
		switch name {
		case "id":
			id, err := strconv.Atoi(value)
			if err != nil {
				return meta, false, fmt.Errorf("id %q", value)
			}
			meta.ID = id
		case "phase":
			phase, err := strconv.Atoi(value)
			if err != nil {
				return meta, false, fmt.Errorf("phase %q", value)
			}
			meta.Phase = phase
		case "msg":
			meta.Message = value
		case "severity":
			meta.Severity = value
		case "tag":
			meta.Tags = append(meta.Tags, value)
		case "rev":
			meta.Revision = value
		case "ver":
			meta.Version = value
		case "maturity":
			meta.Maturity = value
		case "accuracy":
			meta.Accuracy = value
		case "t":
			token, ok := seclangv1alpha1.CanonicalTransformation(seclangv1alpha1.Transformation(value))
			if !ok {
				return meta, false, fmt.Errorf("unknown transformation %q", value)
			}
			trans = append(trans, seclangv1alpha1.Transformation(token))
		case "chain":
			chained = true
		case "deny", "drop", "block", "pass":
			actions.Disruptive = &seclangv1alpha1.DisruptiveAction{Type: seclangv1alpha1.DisruptiveActionType(name)}
		case "allow":
			actions.Disruptive = &seclangv1alpha1.DisruptiveAction{Type: seclangv1alpha1.Allow, Value: value}
		case "pause", "proxy", "redirect":
			actions.Disruptive = &seclangv1alpha1.DisruptiveAction{Type: seclangv1alpha1.DisruptiveActionType(name), Value: value}
		case "status", "xmlns":
			actions.Data = append(actions.Data, seclangv1alpha1.DataAction{Type: seclangv1alpha1.DataActionType(name), Value: value})
		case "skip", "skipAfter":
			actions.Flow = append(actions.Flow, seclangv1alpha1.FlowAction{Type: seclangv1alpha1.FlowActionType(name), Value: value})
		default:
			token, ok := seclangv1alpha1.CanonicalNonDisruptive(seclangv1alpha1.NonDisruptiveActionType(name))
			if !ok {
				return meta, false, fmt.Errorf("unknown action %q", name)
			}
			actions.NonDisruptive = append(actions.NonDisruptive, seclangv1alpha1.NonDisruptiveAction{
				Type: seclangv1alpha1.NonDisruptiveActionType(token), Value: value,
			})
		}
	}
	link.Transformations = trans
	if actions.Disruptive != nil || len(actions.Data) > 0 || len(actions.Flow) > 0 || len(actions.NonDisruptive) > 0 {
		link.Actions = actions
	}
	return meta, chained, nil
}

func splitList(s string) []string {
	var out []string
	var b strings.Builder
	var quote byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		if quote != 0 {
			b.WriteByte(c)
			if c == quote && (i == 0 || s[i-1] != '\\') {
				quote = 0
			}
			continue
		}
		if c == '\'' || c == '"' {
			quote = c
			b.WriteByte(c)
			continue
		}
		if c == ',' {
			out = append(out, strings.TrimSpace(b.String()))
			b.Reset()
			continue
		}
		b.WriteByte(c)
	}
	if strings.TrimSpace(b.String()) != "" {
		out = append(out, strings.TrimSpace(b.String()))
	}
	return out
}

func unquote(s string) string {
	if len(s) >= 2 {
		if (s[0] == '\'' && s[len(s)-1] == '\'') || (s[0] == '"' && s[len(s)-1] == '"') {
			s = s[1 : len(s)-1]
		}
	}
	s = strings.ReplaceAll(s, `\'`, `'`)
	s = strings.ReplaceAll(s, `\"`, `"`)
	return s
}

func takeQuoted(s string) (string, string, error) {
	if s == "" || s[0] != '"' {
		return "", "", fmt.Errorf("expected a quoted string in %s", head(s))
	}
	var b strings.Builder
	for i := 1; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			b.WriteByte(s[i+1])
			i++
			continue
		}
		if s[i] == '"' {
			return b.String(), s[i+1:], nil
		}
		b.WriteByte(s[i])
	}
	return "", "", fmt.Errorf("unterminated quote")
}

func markerName(line string) (string, error) {
	rest := strings.TrimSpace(strings.TrimPrefix(line, "SecMarker"))
	if rest == "" {
		return "", fmt.Errorf("SecMarker has no name")
	}
	if rest[0] == '"' {
		name, _, err := takeQuoted(rest)
		return name, err
	}
	return rest, nil
}

func setMarker(out []Object, name string) error {
	if len(out) == 0 {
		return fmt.Errorf("SecMarker %s has no preceding rule", name)
	}
	last := &out[len(out)-1]
	if last.Rule != nil {
		last.Rule.Spec.MarkerAfter = name
		return nil
	}
	last.Action.Spec.MarkerAfter = name
	return nil
}

func nameObject(obj *Object, prefix string) error {
	if obj.Rule != nil {
		if obj.Rule.Spec.Metadata.ID < 1 {
			return fmt.Errorf("SecRule has no id")
		}
		obj.Rule.Name = strings.ToLower(fmt.Sprintf("%s%d", prefix, obj.Rule.Spec.Metadata.ID))
		return nil
	}
	if obj.Action.Spec.Metadata.ID < 1 {
		return fmt.Errorf("SecAction has no id")
	}
	obj.Action.Name = strings.ToLower(fmt.Sprintf("%saction-%d", prefix, obj.Action.Spec.Metadata.ID))
	return nil
}

func head(s string) string {
	if len(s) > 80 {
		return s[:80]
	}
	return s
}
