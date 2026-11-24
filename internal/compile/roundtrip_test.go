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
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	seclangv1alpha1 "github.com/kubewaf-io/kubewaf/api/seclang/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestEnumConstantsRoundTrip(t *testing.T) {
	update := os.Getenv("UPDATE_GOLDENS") == "1"
	consts := loadConsts(t)
	var unsupported []string

	check := func(rel, text string) {
		t.Helper()
		path := filepath.Join("testdata", rel)
		if update {
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(text+"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		if got := readGolden(t, path); got != text {
			t.Fatalf("%s\n got %s\nwant %s", rel, text, got)
		}
		if err := Parse(text); err != nil {
			unsupported = append(unsupported, rel+"\t"+flatten(err))
		}
	}

	for _, name := range consts["VariableName"] {
		rule := baseRule()
		rule.Spec.Chain[0].Targets[0].Name = seclangv1alpha1.VariableName(name)
		text, err := EmitRule(&rule)
		if err != nil {
			t.Fatalf("variable %s: %v", name, err)
		}
		check(filepath.Join("enum", "variable", name+".seclang"), text)
	}
	for _, name := range consts["OperatorName"] {
		rule := baseRule()
		op := seclangv1alpha1.Operator{Name: seclangv1alpha1.OperatorName(name)}
		forbidden, optional, ok := seclangv1alpha1.OperatorValueMode(op.Name)
		if !ok {
			t.Fatalf("operator %s has no value mode", name)
		}
		if !forbidden {
			op.Value = "x"
			if optional {
				op.Value = "1"
			}
		}
		switch name {
		case "validateByteRange":
			op.Value = "1,255"
		case "ipMatch":
			op.Value = "192.168.0.0/16"
		case "pmFromFile", "pmf", "ipMatchFromFile", "ipMatchF":
			op.Value = "/etc/kubewaf/seclang/sample.data"
		}
		rule.Spec.Chain[0].Operator = op
		text, err := EmitRule(&rule)
		if err != nil {
			t.Fatalf("operator %s: %v", name, err)
		}
		check(filepath.Join("enum", "operator", name+".seclang"), text)
	}
	for _, name := range consts["Transformation"] {
		rule := baseRule()
		rule.Spec.Chain[0].Transformations = []seclangv1alpha1.Transformation{seclangv1alpha1.Transformation(name)}
		text, err := EmitRule(&rule)
		if err != nil {
			t.Fatalf("transformation %s: %v", name, err)
		}
		check(filepath.Join("enum", "transformation", name+".seclang"), text)
	}
	for _, name := range consts["DisruptiveActionType"] {
		rule := baseRule()
		d := seclangv1alpha1.DisruptiveAction{Type: seclangv1alpha1.DisruptiveActionType(name)}
		switch d.Type {
		case seclangv1alpha1.Pause:
			d.Value = "10"
		case seclangv1alpha1.Proxy, seclangv1alpha1.Redirect:
			d.Value = "http://example.com/blocked"
		case seclangv1alpha1.Allow:
			d.Value = "phase"
		}
		rule.Spec.Chain[0].Actions = &seclangv1alpha1.Actions{Disruptive: &d}
		text, err := EmitRule(&rule)
		if err != nil {
			t.Fatalf("disruptive %s: %v", name, err)
		}
		check(filepath.Join("enum", "disruptive", name+".seclang"), text)
	}
	for _, name := range consts["FlowActionType"] {
		if name == "chain" {
			rule := baseRule()
			rule.Spec.Chain[0].Actions.Flow = []seclangv1alpha1.FlowAction{{Type: seclangv1alpha1.Chain, Value: "1"}}
			_, err := EmitRule(&rule)
			if err == nil || !strings.Contains(err.Error(), "cannot be set") {
				t.Fatalf("chain: %v", err)
			}
			continue
		}
		rule := baseRule()
		f := seclangv1alpha1.FlowAction{Type: seclangv1alpha1.FlowActionType(name), Value: "1"}
		if name == "skipAfter" {
			f.Value = "END_SCANNERS"
		}
		rule.Spec.Chain[0].Actions.Flow = []seclangv1alpha1.FlowAction{f}
		text, err := EmitRule(&rule)
		if err != nil {
			t.Fatalf("flow %s: %v", name, err)
		}
		check(filepath.Join("enum", "flow", name+".seclang"), text)
	}
	for _, name := range consts["DataActionType"] {
		rule := baseRule()
		d := seclangv1alpha1.DataAction{Type: seclangv1alpha1.DataActionType(name), Value: "403"}
		if name == "xmlns" {
			d.Value = "a=http://example.com/ns"
		}
		rule.Spec.Chain[0].Actions.Data = []seclangv1alpha1.DataAction{d}
		text, err := EmitRule(&rule)
		if err != nil {
			t.Fatalf("data %s: %v", name, err)
		}
		check(filepath.Join("enum", "data", name+".seclang"), text)
	}
	for _, name := range consts["NonDisruptiveActionType"] {
		rule := baseRule()
		n := seclangv1alpha1.NonDisruptiveAction{Type: seclangv1alpha1.NonDisruptiveActionType(name)}
		forbidden, optional, ok := seclangv1alpha1.NonDisruptiveValueMode(n.Type)
		if !ok {
			t.Fatalf("action %s", name)
		}
		if !forbidden {
			n.Value = sampleActionValue(name, optional)
		}
		rule.Spec.Chain[0].Actions.NonDisruptive = []seclangv1alpha1.NonDisruptiveAction{n}
		text, err := EmitRule(&rule)
		if err != nil {
			t.Fatalf("action %s: %v", name, err)
		}
		check(filepath.Join("enum", "action", name+".seclang"), text)
	}
	for _, prefix := range seclangv1alpha1.CtlPrefixes {
		rule := baseRule()
		rule.Spec.Chain[0].Actions.NonDisruptive = []seclangv1alpha1.NonDisruptiveAction{{
			Type: seclangv1alpha1.Ctl, Value: prefix + "=" + ctlSample(prefix),
		}}
		text, err := EmitRule(&rule)
		if err != nil {
			t.Fatalf("ctl %s: %v", prefix, err)
		}
		check(filepath.Join("ctl", prefix+".seclang"), text)
	}

	walkGoldens(t, func(rel, text string) {
		if strings.HasPrefix(rel, "enum/") || strings.HasPrefix(rel, "ctl/") || strings.HasPrefix(rel, "crs/") {
			return
		}
		if err := Parse(text); err != nil {
			unsupported = append(unsupported, rel+"\t"+flatten(err))
		}
	})
	sort.Strings(unsupported)
	got := strings.Join(unsupported, "\n")
	if got != "" {
		got += "\n"
	}
	path := "testdata/unsupported.txt"
	if update {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	have, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read unsupported.txt (%d entries). Run UPDATE_GOLDENS=1: %v", len(unsupported), err)
	}
	if string(have) != got {
		t.Fatalf("unsupported.txt does not match Coraza. Run UPDATE_GOLDENS=1 to review %d entries", len(unsupported))
	}
}

func TestCRS942100Tokens(t *testing.T) {
	rule := crs942100()
	got, err := EmitRule(&rule)
	if err != nil {
		t.Fatal(err)
	}
	if update := os.Getenv("UPDATE_GOLDENS") == "1"; update {
		if err := os.WriteFile("testdata/crs/942100.seclang", []byte(got+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if readGolden(t, "testdata/crs/942100.seclang") != got {
		t.Fatalf("canonical\n%s", got)
	}
	upstream := collapse(readGolden(t, "testdata/crs/942100.upstream"))
	if err := sameDirective(got, upstream); err != nil {
		t.Fatal(err)
	}
	if err := Parse(got); err != nil {
		t.Fatal(err)
	}
}

func crs942100() seclangv1alpha1.SecRule {
	targets := []seclangv1alpha1.Target{
		{Name: seclangv1alpha1.REQUEST_COOKIES},
		{Name: seclangv1alpha1.REQUEST_COOKIES_NAMES},
		{Name: seclangv1alpha1.REQUEST_HEADERS, Selector: "User-Agent"},
		{Name: seclangv1alpha1.REQUEST_HEADERS, Selector: "Referer"},
		{Name: seclangv1alpha1.ARGS_NAMES},
		{Name: seclangv1alpha1.ARGS},
		{Name: seclangv1alpha1.XML, Selector: "/*"},
	}
	return seclangv1alpha1.SecRule{
		ObjectMeta: metav1.ObjectMeta{Name: "crs-942100"},
		Spec: seclangv1alpha1.SecRuleSpec{
			Metadata: seclangv1alpha1.Metadata{
				ID: 942100, Phase: 2,
				Message:  "SQL Injection Attack Detected via libinjection",
				Severity: "CRITICAL",
				Version:  "OWASP_CRS/4.25.0",
				Tags: []string{
					"application-multi", "language-multi", "platform-multi", "attack-sqli",
					"paranoia-level/1", "OWASP_CRS", "OWASP_CRS/ATTACK-SQLI", "capec/1000/152/248/66",
				},
			},
			Chain: []seclangv1alpha1.ChainLink{{
				Targets:         targets,
				Operator:        seclangv1alpha1.Operator{Name: seclangv1alpha1.DetectSQLi},
				Transformations: []seclangv1alpha1.Transformation{seclangv1alpha1.None, seclangv1alpha1.Utf8toUnicode, seclangv1alpha1.UrlDecodeUni, seclangv1alpha1.RemoveNulls},
				Actions: &seclangv1alpha1.Actions{
					Disruptive: &seclangv1alpha1.DisruptiveAction{Type: seclangv1alpha1.Block},
					NonDisruptive: []seclangv1alpha1.NonDisruptiveAction{
						{Type: seclangv1alpha1.Capture},
						{Type: seclangv1alpha1.Logdata, Value: "Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}"},
						{Type: seclangv1alpha1.MultiMatch},
						{Type: seclangv1alpha1.Setvar, Value: "tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}"},
						{Type: seclangv1alpha1.Setvar, Value: "tx.sql_injection_score=+%{tx.critical_anomaly_score}"},
					},
				},
			}},
		},
	}
}

func sampleActionValue(name string, optional bool) string {
	if optional {
		return "4"
	}
	switch name {
	case "ctl":
		return "ruleEngine=Off"
	case "append", "prepend":
		return "tail"
	case "logdata":
		return "matched"
	default:
		return "tx.a=1"
	}
}

func ctlSample(prefix string) string {
	switch prefix {
	case "ruleEngine", "auditEngine", "hashEngine", "hashEnforcement", "forceRequestBodyVariable", "requestBodyAccess", "responseBodyAccess", "forceResponseBodyVariable":
		return "Off"
	case "ruleRemoveById":
		return "920100"
	case "ruleRemoveByTag":
		return "attack-xss"
	case "ruleRemoveByMsg":
		return "Failed SQLi"
	case "ruleRemoveTargetById":
		return "942100;ARGS:password"
	case "ruleRemoveTargetByTag":
		return "attack-sqli;ARGS:csrf"
	case "ruleRemoveTargetByMsg":
		return "Failed;ARGS:csrf"
	case "auditLogParts":
		return "ABCFHZ"
	case "requestBodyProcessor":
		return "JSON"
	case "requestBodyLimit", "responseBodyLimit":
		return "131072"
	case "debugLogLevel":
		return "3"
	default:
		return "On"
	}
}

func loadConsts(t *testing.T) map[string][]string {
	t.Helper()
	b, err := os.ReadFile("../../api/seclang/v1alpha1/tokens.go")
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`(?m)^\t\w+\s+(VariableName|OperatorName|Transformation|DisruptiveActionType|FlowActionType|DataActionType|NonDisruptiveActionType)\s+=\s+"([^"]+)"`)
	out := map[string][]string{}
	for _, m := range re.FindAllStringSubmatch(string(b), -1) {
		out[m[1]] = append(out[m[1]], m[2])
	}
	for _, typ := range []string{"VariableName", "OperatorName", "Transformation", "DisruptiveActionType", "FlowActionType", "DataActionType", "NonDisruptiveActionType"} {
		if len(out[typ]) == 0 {
			t.Fatalf("no constants for %s", typ)
		}
	}
	return out
}

func walkGoldens(t *testing.T, fn func(rel, text string)) {
	t.Helper()
	err := filepath.Walk("testdata", func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".seclang") {
			return err
		}
		rel := strings.TrimPrefix(path, "testdata/")
		fn(rel, readGolden(t, path))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func flatten(err error) string {
	return strings.Join(strings.Fields(err.Error()), " ")
}

func collapse(s string) string {
	s = strings.ReplaceAll(s, "\\\n", "")
	return strings.Join(strings.Fields(s), " ")
}

func sameDirective(canonical, upstream string) error {
	cTargets, cOp, cActions := splitDirective(collapse(canonical))
	uTargets, uOp, uActions := splitDirective(collapse(upstream))
	if cTargets != uTargets || cOp != uOp {
		return fmt.Errorf("targets or operator\n got %s %s\nwant %s %s", cTargets, cOp, uTargets, uOp)
	}
	if !sameTokens(cActions, uActions) {
		return fmt.Errorf("actions\n got %s\nwant %s", cActions, uActions)
	}
	return nil
}

func splitDirective(line string) (targets, operator, actions string) {
	line = strings.TrimPrefix(line, "SecRule ")
	i := strings.Index(line, ` "`)
	if i < 0 {
		return line, "", ""
	}
	targets = line[:i]
	rest := strings.TrimSpace(line[i:])
	operator, rest = takeQuoted(rest)
	rest = strings.TrimSpace(rest)
	if rest != "" {
		actions, _ = takeQuoted(rest)
	}
	return targets, operator, actions
}

func takeQuoted(s string) (string, string) {
	if len(s) == 0 || s[0] != '"' {
		return "", s
	}
	var b strings.Builder
	for i := 1; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			b.WriteByte(s[i+1])
			i++
			continue
		}
		if s[i] == '"' {
			return b.String(), s[i+1:]
		}
		b.WriteByte(s[i])
	}
	return b.String(), ""
}

func sameTokens(a, b string) bool {
	as := normTokens(a)
	bs := normTokens(b)
	if len(as) != len(bs) {
		return false
	}
	sort.Strings(as)
	sort.Strings(bs)
	for i := range as {
		if as[i] != bs[i] {
			return false
		}
	}
	return true
}

func normTokens(list string) []string {
	var out []string
	var cur bytes.Buffer
	quote := byte(0)
	for i := 0; i < len(list); i++ {
		c := list[i]
		if quote != 0 {
			if c == '\\' && i+1 < len(list) {
				cur.WriteByte(list[i+1])
				i++
				continue
			}
			if c == quote {
				quote = 0
				continue
			}
			cur.WriteByte(c)
			continue
		}
		if c == '\'' || c == '"' {
			quote = c
			continue
		}
		if c == ',' {
			out = append(out, strings.TrimSpace(cur.String()))
			cur.Reset()
			continue
		}
		cur.WriteByte(c)
	}
	if strings.TrimSpace(cur.String()) != "" {
		out = append(out, strings.TrimSpace(cur.String()))
	}
	return out
}
