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
	"fmt"
	"strings"

	seclangv1beta1 "github.com/kubewaf-io/kubewaf/api/seclang/v1beta1"
	"github.com/kubewaf-io/kubewaf/api/seclang/v1beta1/convert"
)

// AssemblyResult is a Coraza-safe SecLang document plus assembly counters.
type AssemblyResult struct {
	// Directives is the full SecLang document (preamble + rules).
	Directives string
	// RulesLoaded counts user rule lines (excluding preamble/stamp).
	RulesLoaded int
	// ActionsLoaded is reserved for SecAction counts (0 in SecRule path).
	ActionsLoaded int
	// DirectivesCount is non-empty lines in Directives.
	DirectivesCount int
	// DataFileBasenames referenced by the document (before ResolveDataFiles).
	DataFileBasenames []string
}

// AssembleSecRule builds a Coraza-safe document for a single SecRule (K26/K27/K29).
// Applies AssignedIDs, converts via convert package, prepends frozen preamble.
func AssembleSecRule(sr *seclangv1beta1.SecRule) (*AssemblyResult, error) {
	if sr == nil {
		return nil, fmt.Errorf("nil SecRule")
	}
	withIDs := ApplyAssignedIDs(sr, nil)
	if err := EnsureRuleIDs(withIDs); err != nil {
		return nil, err
	}
	dirs, err := convert.ConvertSecRule(*withIDs)
	if err != nil {
		return nil, fmt.Errorf("convert SecRule: %w", err)
	}
	ruleText := convert.ConvertToSecLangString(dirs)
	ruleLines := splitLines(ruleText)
	doc := JoinDocument(Preamble(), ruleLines)
	return &AssemblyResult{
		Directives:        doc,
		RulesLoaded:       len(ruleLines),
		DirectivesCount:   CountNonEmptyLines(doc),
		DataFileBasenames: ScanPmFromFileBasenames(append(Preamble(), ruleLines...)),
	}, nil
}

// AssembleFromRuleLines builds a document from pre-converted SecLang rule lines
// (e.g. RuleSet/WAF leaf join). Always stamps 900990 after preamble for Path B safety.
func AssembleFromRuleLines(ruleLines []string, stamp bool, crs *CRSTuning) *AssemblyResult {
	parts := [][]string{Preamble()}
	if crs != nil {
		parts = append(parts, CRSSetupActions(crs))
	} else if stamp {
		parts = append(parts, []string{StampOnly900990()})
	}
	parts = append(parts, ruleLines)
	if crs != nil {
		parts = append(parts, CRSExclusions(crs))
	}
	doc := JoinDocument(parts...)
	return &AssemblyResult{
		Directives:        doc,
		RulesLoaded:       countNonEmpty(ruleLines),
		DirectivesCount:   CountNonEmptyLines(doc),
		DataFileBasenames: ScanPmFromFileBasenames(ruleLines),
	}
}

func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	raw := strings.Split(s, "\n")
	out := make([]string, 0, len(raw))
	for _, line := range raw {
		if strings.TrimSpace(line) == "" {
			continue
		}
		out = append(out, line)
	}
	return out
}

func countNonEmpty(lines []string) int {
	n := 0
	for _, line := range lines {
		if strings.TrimSpace(line) != "" && !strings.HasPrefix(strings.TrimSpace(line), "#") {
			n++
		}
	}
	return n
}
