/*
Copyright 2025 Buzz-IT GmbH.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

    10|Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package compile

import (
	"os"
	"strings"
	"testing"

	coreruleset "github.com/corazawaf/coraza-coreruleset"
	"github.com/corazawaf/coraza/v3"
	seclangv1alpha1 "github.com/kubewaf-io/kubewaf/api/seclang/v1alpha1"
	wafv1alpha1 "github.com/kubewaf-io/kubewaf/api/waf/v1alpha1"
	"sigs.k8s.io/yaml"
)

func TestQuoteRoundTripInCoraza(t *testing.T) {
	rule := seclangv1alpha1.SecRule{Spec: seclangv1alpha1.SecRuleSpec{
		Metadata: seclangv1alpha1.Metadata{ID: 100001, Phase: 1, Message: "it's a scanner"},
		Chain: []seclangv1alpha1.ChainLink{{
			Targets:  []seclangv1alpha1.Target{{Name: seclangv1alpha1.REQUEST_HEADERS, Selector: "User-Agent"}},
			Operator: seclangv1alpha1.Operator{Name: seclangv1alpha1.Rx, Value: `\bfoo`},
			Actions:  &seclangv1alpha1.Actions{Disruptive: &seclangv1alpha1.DisruptiveAction{Type: seclangv1alpha1.Deny}},
		}},
	}}
	rule.Name = "quoted"
	text, err := EmitRule(&rule)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(text, `\bfoo`) && strings.Contains(text, `\\bfoo`) {
		t.Fatalf("regex backslash was doubled:\n%s", text)
	}
	if !strings.Contains(text, `@rx \bfoo`) {
		t.Fatalf("operator text:\n%s", text)
	}
	quoted := seclangv1alpha1.SecRule{Spec: seclangv1alpha1.SecRuleSpec{
		Metadata: seclangv1alpha1.Metadata{ID: 100002, Phase: 1, Message: "quoted operator"},
		Chain: []seclangv1alpha1.ChainLink{{
			Targets:  []seclangv1alpha1.Target{{Name: seclangv1alpha1.ARGS}},
			Operator: seclangv1alpha1.Operator{Name: seclangv1alpha1.Contains, Value: `say "hi"`},
			Actions:  &seclangv1alpha1.Actions{Disruptive: &seclangv1alpha1.DisruptiveAction{Type: seclangv1alpha1.Deny}},
		}},
	}}
	quotedText, err := EmitRule(&quoted)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(quotedText, `\\"`) {
		t.Fatalf("quote escape was doubled:\n%s", quotedText)
	}
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives("SecRuleEngine On\n" + text + "\n" + quotedText))
	if err != nil {
		t.Fatal(err)
	}
	tx := waf.NewTransaction()
	defer func() { _ = tx.Close() }()
	tx.ProcessURI("http://example.com/", "GET", "HTTP/1.1")
	tx.AddRequestHeader("User-Agent", "foo")
	tx.AddRequestHeader("Host", "example.com")
	tx.ProcessRequestHeaders()
	if !tx.IsInterrupted() {
		t.Fatal(`regex \bfoo did not match foo`)
	}
	msg := ""
	for _, m := range tx.MatchedRules() {
		if m.Rule().ID() == 100001 {
			msg = m.Message()
		}
	}
	if msg != "it's a scanner" {
		t.Fatalf("message %q", msg)
	}

	waf, err = coraza.NewWAF(coraza.NewWAFConfig().WithDirectives("SecRuleEngine On\n" + quotedText))
	if err != nil {
		t.Fatal(err)
	}
	tx = waf.NewTransaction()
	defer func() { _ = tx.Close() }()
	tx.ProcessURI("http://example.com/", "GET", "HTTP/1.1")
	tx.AddRequestHeader("Host", "example.com")
	tx.AddGetRequestArgument("q", `say "hi"`)
	tx.ProcessRequestHeaders()
	if !tx.IsInterrupted() {
		t.Fatal(`contains say "hi" did not match`)
	}
	msg = ""
	for _, m := range tx.MatchedRules() {
		if m.Rule().ID() == 100002 {
			msg = m.Message()
		}
	}
	if msg != "quoted operator" {
		t.Fatalf("message %q", msg)
	}
}

func TestActionValueDoubleQuoteIsRejected(t *testing.T) {
	rule := seclangv1alpha1.SecRule{Spec: seclangv1alpha1.SecRuleSpec{
		Metadata: seclangv1alpha1.Metadata{ID: 1, Phase: 1, Message: `say "hi"`},
		Chain: []seclangv1alpha1.ChainLink{{
			Targets:  []seclangv1alpha1.Target{{Name: seclangv1alpha1.ARGS}},
			Operator: seclangv1alpha1.Operator{Name: seclangv1alpha1.Contains, Value: "x"},
			Actions:  &seclangv1alpha1.Actions{Disruptive: &seclangv1alpha1.DisruptiveAction{Type: seclangv1alpha1.Deny}},
		}},
	}}
	if _, err := EmitRule(&rule); err == nil || !strings.Contains(err.Error(), "double quote") {
		t.Fatal(err)
	}
}

func TestOddBackslashBeforeQuoteIsRejected(t *testing.T) {
	rule := seclangv1alpha1.SecRule{Spec: seclangv1alpha1.SecRuleSpec{
		Metadata: seclangv1alpha1.Metadata{ID: 1, Phase: 1},
		Chain: []seclangv1alpha1.ChainLink{{
			Targets:  []seclangv1alpha1.Target{{Name: seclangv1alpha1.ARGS}},
			Operator: seclangv1alpha1.Operator{Name: seclangv1alpha1.Contains, Value: `odd \" quote`},
			Actions:  &seclangv1alpha1.Actions{Disruptive: &seclangv1alpha1.DisruptiveAction{Type: seclangv1alpha1.Deny}},
		}},
	}}
	if _, err := EmitRule(&rule); err == nil || !strings.Contains(err.Error(), "odd number of backslashes") {
		t.Fatal(err)
	}
}

func TestProtectionEdgeSampleLoadsWithCRS(t *testing.T) {
	raw, err := os.ReadFile("../../config/samples/waf/protection-edge.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var protection wafv1alpha1.Protection
	if err := yaml.Unmarshal(raw, &protection); err != nil {
		t.Fatal(err)
	}
	rule := seclangv1alpha1.SecRule{Spec: seclangv1alpha1.SecRuleSpec{
		Order:    10,
		Metadata: seclangv1alpha1.Metadata{ID: 100001, Phase: 1, Message: "scanner user-agent"},
		Chain: []seclangv1alpha1.ChainLink{{
			Targets:  []seclangv1alpha1.Target{{Name: seclangv1alpha1.REQUEST_HEADERS, Selector: "User-Agent"}},
			Operator: seclangv1alpha1.Operator{Name: seclangv1alpha1.Rx, Value: "(?i)sqlmap"},
			Actions: &seclangv1alpha1.Actions{
				Disruptive: &seclangv1alpha1.DisruptiveAction{Type: seclangv1alpha1.Deny},
				Data:       []seclangv1alpha1.DataAction{{Type: seclangv1alpha1.Status, Value: "403"}},
			},
		}},
	}}
	rule.Name = "block-sqlmap"
	bundle, err := BuildProtection(ProtectionInput{
		Namespace: protection.Namespace,
		Name:      protection.Name,
		Spec:      protection.Spec,
		Rules:     []seclangv1alpha1.SecRule{rule},
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Index(bundle.After, "Include @owasp_crs/*.conf") > strings.Index(bundle.After, "id:100001") {
		t.Fatalf("custom rule before CRS\n%s", bundle.After)
	}
	if strings.Index(bundle.After, "SecRuleUpdateTargetById") > strings.Index(bundle.After, "SecRuleRemoveById") {
		t.Fatalf("update follows removal\n%s", bundle.After)
	}
	directives := "SecRuleEngine On\nSecRequestBodyAccess On\n" + bundle.Before + "\n" + bundle.After + "\n"
	// This library names the setup file @crs-setup.conf.example. Composer ships it as @crs-setup.conf.
	directives = strings.ReplaceAll(directives, "Include @crs-setup.conf", "Include @crs-setup.conf.example")
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithRootFS(coreruleset.FS).WithDirectives(directives))
	if err != nil {
		t.Fatalf("CRS load: %v\n%s", err, directives)
	}
	tx := waf.NewTransaction()
	defer func() { _ = tx.Close() }()
	tx.ProcessURI("http://www.example.com/", "GET", "HTTP/1.1")
	tx.AddRequestHeader("Host", "www.example.com")
	tx.AddRequestHeader("User-Agent", "sqlmap/1.0")
	tx.ProcessRequestHeaders()
	if !tx.IsInterrupted() {
		t.Fatal("sqlmap user-agent was not denied")
	}
}
