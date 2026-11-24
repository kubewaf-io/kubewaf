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

package compile

import (
	"fmt"
	"regexp"
	"strings"

	seclangv1alpha1 "github.com/kubewaf-io/kubewaf/api/seclang/v1alpha1"
)

var markerName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_-]*$`)

// EmitRule renders one SecRule. Operator file names are left as the user wrote them.
func EmitRule(rule *seclangv1alpha1.SecRule) (string, error) {
	return emitRule(rule, nil)
}

// EmitAction renders one SecAction.
func EmitAction(action *seclangv1alpha1.SecAction) (string, error) {
	if action == nil {
		return "", fmt.Errorf("nil SecAction")
	}
	if err := checkMarker(action.Spec.MarkerAfter); err != nil {
		return "", err
	}
	body, err := actionList(true, action.Spec.Metadata, action.Spec.Transformations, false, action.Spec.Actions)
	if err != nil {
		return "", err
	}
	if body == "" {
		return "", fmt.Errorf("SecAction has no actions")
	}
	return withMarker("SecAction "+quoteDirectiveArg(body), action.Spec.MarkerAfter), nil
}

// EmitInclude renders one Include.
// ConfigMap-backed includes use /etc/kubewaf/seclang/<key> so the object stays
// free of a policy name. Build rewrites that path into the policy's file key.
func EmitInclude(inc *seclangv1alpha1.Include) (string, error) {
	if inc == nil {
		return "", fmt.Errorf("nil Include")
	}
	path, err := includePath(inc, "")
	if err != nil {
		return "", err
	}
	if err := checkMarker(inc.Spec.MarkerAfter); err != nil {
		return "", err
	}
	return withMarker("Include "+path, inc.Spec.MarkerAfter), nil
}

func emitRule(rule *seclangv1alpha1.SecRule, files map[string]string) (string, error) {
	if rule == nil {
		return "", fmt.Errorf("nil SecRule")
	}
	if len(rule.Spec.Chain) == 0 {
		return "", fmt.Errorf("chain must contain at least one link")
	}
	if len(rule.Spec.Chain) > 16 {
		return "", fmt.Errorf("chain has more than 16 links")
	}
	if err := checkMarker(rule.Spec.MarkerAfter); err != nil {
		return "", err
	}
	lines := make([]string, 0, len(rule.Spec.Chain))
	for i, link := range rule.Spec.Chain {
		if i > 0 && link.Actions != nil && link.Actions.Disruptive != nil {
			return "", fmt.Errorf("only the first chain link may set a disruptive action")
		}
		line, err := emitLink(i == 0, i < len(rule.Spec.Chain)-1 && len(rule.Spec.Chain) > 1, rule.Spec.Metadata, link, files)
		if err != nil {
			return "", err
		}
		lines = append(lines, line)
	}
	return withMarker(strings.Join(lines, "\n"), rule.Spec.MarkerAfter), nil
}

func emitLink(first, chained bool, meta seclangv1alpha1.Metadata, link seclangv1alpha1.ChainLink, files map[string]string) (string, error) {
	if len(link.Targets) == 0 {
		return "", fmt.Errorf("chain link has no targets")
	}
	targets := make([]string, 0, len(link.Targets))
	for _, t := range link.Targets {
		text, err := emitTarget(t)
		if err != nil {
			return "", err
		}
		targets = append(targets, text)
	}
	op, err := emitOperator(link.Operator, files)
	if err != nil {
		return "", err
	}
	var metaOut seclangv1alpha1.Metadata
	if first {
		metaOut = meta
	}
	body, err := actionList(first, metaOut, link.Transformations, chained, link.Actions)
	if err != nil {
		return "", err
	}
	line := "SecRule " + strings.Join(targets, "|") + " " + op
	if body != "" {
		line += " " + quoteDirectiveArg(body)
	}
	return line, nil
}

func emitTarget(t seclangv1alpha1.Target) (string, error) {
	if t.Name == "" {
		return "", fmt.Errorf("target name is empty")
	}
	if t.Exclude && t.Count {
		return "", fmt.Errorf("target %s sets exclude and count", t.Name)
	}
	var b strings.Builder
	if t.Count {
		b.WriteByte('&')
	}
	if t.Exclude {
		b.WriteByte('!')
	}
	b.WriteString(string(t.Name))
	if t.Selector != "" {
		b.WriteByte(':')
		b.WriteString(t.Selector)
	}
	return b.String(), nil
}

func emitOperator(op seclangv1alpha1.Operator, files map[string]string) (string, error) {
	token, ok := seclangv1alpha1.CanonicalOperator(op.Name)
	if !ok {
		return "", fmt.Errorf("unknown operator %q", op.Name)
	}
	forbidden, optional, _ := seclangv1alpha1.OperatorValueMode(op.Name)
	if strings.ContainsAny(op.Value, "\n\r") {
		return "", fmt.Errorf("operator value contains a newline")
	}
	if forbidden && op.Value != "" {
		return "", fmt.Errorf("operator %s does not take a value", token)
	}
	if !forbidden && !optional && op.Value == "" {
		return "", fmt.Errorf("operator %s requires a value", token)
	}
	value := op.Value
	if files != nil && (token == "pmFromFile" || token == "ipMatchFromFile") {
		if abs, ok := files[value]; ok {
			value = abs
		}
	}
	neg := ""
	if op.Negate {
		neg = "!"
	}
	if value == "" {
		return quoteDirectiveArg(neg + "@" + token), nil
	}
	return quoteDirectiveArg(neg + "@" + token + " " + value), nil
}

func actionList(first bool, meta seclangv1alpha1.Metadata, trans []seclangv1alpha1.Transformation, chained bool, actions *seclangv1alpha1.Actions) (string, error) {
	var parts []string
	if first {
		if meta.ID < 1 {
			return "", fmt.Errorf("metadata.id must be positive")
		}
		if meta.Phase < 1 || meta.Phase > 5 {
			return "", fmt.Errorf("metadata.phase must be 1 through 5")
		}
		parts = append(parts, fmt.Sprintf("id:%d", meta.ID), fmt.Sprintf("phase:%d", meta.Phase))
	}
	for _, t := range trans {
		token, ok := seclangv1alpha1.CanonicalTransformation(t)
		if !ok {
			return "", fmt.Errorf("unknown transformation %q", t)
		}
		parts = append(parts, "t:"+token)
	}
	if chained {
		parts = append(parts, "chain")
	}
	if actions != nil && actions.Disruptive != nil {
		text, err := emitDisruptive(*actions.Disruptive)
		if err != nil {
			return "", err
		}
		parts = append(parts, text)
	}
	if actions != nil {
		for _, d := range actions.Data {
			text, err := emitData(d)
			if err != nil {
				return "", err
			}
			parts = append(parts, text)
		}
		for _, f := range actions.Flow {
			text, err := emitFlow(f)
			if err != nil {
				return "", err
			}
			parts = append(parts, text)
		}
	}
	if first {
		metaParts, err := emitMetadata(meta)
		if err != nil {
			return "", err
		}
		parts = append(parts, metaParts...)
	}
	if actions != nil {
		for _, n := range actions.NonDisruptive {
			text, err := emitNonDisruptive(n)
			if err != nil {
				return "", err
			}
			parts = append(parts, text)
		}
	}
	return strings.Join(parts, ","), nil
}

func emitMetadata(meta seclangv1alpha1.Metadata) ([]string, error) {
	var parts []string
	if meta.Message != "" {
		q, err := quoteActionValue(meta.Message)
		if err != nil {
			return nil, err
		}
		parts = append(parts, "msg:"+q)
	}
	if meta.Severity != "" {
		q, err := quoteActionValue(meta.Severity)
		if err != nil {
			return nil, err
		}
		parts = append(parts, "severity:"+q)
	}
	for _, tag := range meta.Tags {
		q, err := quoteActionValue(tag)
		if err != nil {
			return nil, err
		}
		parts = append(parts, "tag:"+q)
	}
	for _, item := range []struct {
		name, value string
	}{
		{"rev", meta.Revision},
		{"ver", meta.Version},
		{"maturity", meta.Maturity},
		{"accuracy", meta.Accuracy},
	} {
		if item.value == "" {
			continue
		}
		q, err := quoteActionValue(item.value)
		if err != nil {
			return nil, err
		}
		parts = append(parts, item.name+":"+q)
	}
	return parts, nil
}

func emitDisruptive(d seclangv1alpha1.DisruptiveAction) (string, error) {
	switch d.Type {
	case seclangv1alpha1.Deny, seclangv1alpha1.Drop, seclangv1alpha1.Block, seclangv1alpha1.Pass:
		if d.Value != "" {
			return "", fmt.Errorf("%s does not take a value", d.Type)
		}
		return string(d.Type), nil
	case seclangv1alpha1.Allow:
		switch d.Value {
		case "":
			return "allow", nil
		case "phase", "request":
			return "allow:" + d.Value, nil
		default:
			return "", fmt.Errorf("allow value must be empty, phase, or request")
		}
	case seclangv1alpha1.Pause:
		if d.Value == "" || strings.Trim(d.Value, "0123456789") != "" {
			return "", fmt.Errorf("pause requires a millisecond count")
		}
		return "pause:" + d.Value, nil
	case seclangv1alpha1.Proxy, seclangv1alpha1.Redirect:
		if d.Value == "" {
			return "", fmt.Errorf("%s requires a value", d.Type)
		}
		q, err := quoteActionValue(d.Value)
		if err != nil {
			return "", err
		}
		return string(d.Type) + ":" + q, nil
	default:
		return "", fmt.Errorf("unknown disruptive action %q", d.Type)
	}
}

func emitData(d seclangv1alpha1.DataAction) (string, error) {
	switch d.Type {
	case seclangv1alpha1.Status:
		if len(d.Value) != 3 || d.Value[0] < '1' || d.Value[0] > '5' || strings.Trim(d.Value, "0123456789") != "" {
			return "", fmt.Errorf("status requires an HTTP code")
		}
		return "status:" + d.Value, nil
	case seclangv1alpha1.Xmlns:
		if !strings.Contains(d.Value, "=") || strings.HasPrefix(d.Value, "=") {
			return "", fmt.Errorf("xmlns requires prefix=url")
		}
		q, err := quoteActionValue(d.Value)
		if err != nil {
			return "", err
		}
		return "xmlns:" + q, nil
	default:
		return "", fmt.Errorf("unknown data action %q", d.Type)
	}
}

func emitFlow(f seclangv1alpha1.FlowAction) (string, error) {
	switch f.Type {
	case seclangv1alpha1.Chain:
		return "", fmt.Errorf("flow action chain is emitted by the compiler and cannot be set")
	case seclangv1alpha1.Skip:
		if f.Value == "" || f.Value == "0" || strings.Trim(f.Value, "0123456789") != "" {
			return "", fmt.Errorf("skip requires a positive integer")
		}
		return "skip:" + f.Value, nil
	case seclangv1alpha1.SkipAfter:
		if err := checkMarker(f.Value); err != nil {
			return "", fmt.Errorf("skipAfter: %w", err)
		}
		return "skipAfter:" + f.Value, nil
	default:
		return "", fmt.Errorf("unknown flow action %q", f.Type)
	}
}

func emitNonDisruptive(n seclangv1alpha1.NonDisruptiveAction) (string, error) {
	token, ok := seclangv1alpha1.CanonicalNonDisruptive(n.Type)
	if !ok {
		return "", fmt.Errorf("unknown action %q", n.Type)
	}
	forbidden, optional, _ := seclangv1alpha1.NonDisruptiveValueMode(n.Type)
	if forbidden && n.Value != "" {
		return "", fmt.Errorf("%s does not take a value", token)
	}
	if !forbidden && !optional && n.Value == "" {
		return "", fmt.Errorf("%s requires a value", token)
	}
	if token == "ctl" {
		if err := checkCtl(n.Value); err != nil {
			return "", err
		}
	}
	if n.Value == "" {
		return token, nil
	}
	q, err := quoteActionValue(n.Value)
	if err != nil {
		return "", err
	}
	return token + ":" + q, nil
}

func checkCtl(value string) error {
	prefix, rest, ok := strings.Cut(value, "=")
	if !ok || prefix == "" || rest == "" {
		return fmt.Errorf("ctl value must be prefix=argument")
	}
	for _, allowed := range seclangv1alpha1.CtlPrefixes {
		if prefix == allowed {
			return nil
		}
	}
	return fmt.Errorf("unknown ctl prefix %q", prefix)
}

func checkMarker(name string) error {
	if name == "" {
		return nil
	}
	if len(name) > 64 || !markerName.MatchString(name) {
		return fmt.Errorf("marker %q is not a SecMarker name", name)
	}
	return nil
}

func withMarker(text, marker string) string {
	if marker == "" {
		return text
	}
	return text + "\nSecMarker " + marker
}

func includePath(inc *seclangv1alpha1.Include, policyFile string) (string, error) {
	hasVirtual := inc.Spec.VirtualPath != ""
	hasCM := inc.Spec.ConfigMapRef != nil
	if hasVirtual == hasCM {
		return "", fmt.Errorf("include %s needs exactly one of virtualPath and configMapRef", inc.Name)
	}
	if hasVirtual {
		if err := checkVirtualPath(inc.Spec.VirtualPath); err != nil {
			return "", err
		}
		return inc.Spec.VirtualPath, nil
	}
	if strings.Contains(inc.Spec.ConfigMapRef.Key, "*") {
		return "", fmt.Errorf("configMap key cannot contain a glob")
	}
	if policyFile != "" {
		return policyFile, nil
	}
	return MountDir + "/" + inc.Spec.ConfigMapRef.Key, nil
}

func checkVirtualPath(path string) error {
	if len(path) < 2 || path[0] != '@' {
		return fmt.Errorf("virtual path %q must start with @", path)
	}
	if strings.Count(path, "*") > 1 {
		return fmt.Errorf("virtual path %q has more than one glob", path)
	}
	return nil
}
