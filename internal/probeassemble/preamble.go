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

// Package probeassemble builds Coraza-safe SecLang documents for probe evaluation.
// It does not run go-coraza request evaluation and must not import internal/coraza.
package probeassemble

import (
	"fmt"
	"strings"
)

// CRSSetupVersionStamp is the tx.crs_setup_version value expected by OWASP CRS 4.x.
// Copied from internal/dataplane/config (do not import that package).
const CRSSetupVersionStamp = 427

// Frozen probe preamble lines (K27). Always SecRuleEngine On for would-block (K28).
var probePreamble = []string{
	"SecRuleEngine On",
	"SecRequestBodyAccess On",
	"SecResponseBodyAccess Off",
}

// Preamble returns the frozen ordered Coraza probe setup lines (K27).
func Preamble() []string {
	out := make([]string, len(probePreamble))
	copy(out, probePreamble)
	return out
}

// PreambleString returns preamble lines joined with newlines (no trailing newline).
func PreambleString() string {
	return strings.Join(probePreamble, "\n")
}

// StampOnly900990 emits the minimal CRS setup-version SecAction (K27b).
func StampOnly900990() string {
	return fmt.Sprintf(
		`SecAction "id:900990,phase:1,nolog,pass,setvar:tx.crs_setup_version=%d"`,
		CRSSetupVersionStamp,
	)
}

// CRSSetupActions returns CRS setup SecAction lines for WAF.spec.crs.
// Pure copy of dataplane/config.CRSSetupActions semantics (no import).
// crs may be nil → stamp-only when includeStampAlways is true via StampOnly900990.
type CRSTuning struct {
	ParanoiaLevel            *int
	InboundAnomalyThreshold  *int
	OutboundAnomalyThreshold *int
	RemoveByID               []int
	RemoveByTag              []string
	UpdateTargetByID         []CRSUpdateTarget
}

// CRSUpdateTarget is a SecRuleUpdateTargetById exclusion.
type CRSUpdateTarget struct {
	ID            int
	RemoveTargets []string
}

// CRSSetupActions emits setup SecAction when crs is non-nil (K27b).
func CRSSetupActions(crs *CRSTuning) []string {
	if crs == nil {
		return nil
	}
	sets := []string{fmt.Sprintf("setvar:tx.crs_setup_version=%d", CRSSetupVersionStamp)}
	if crs.ParanoiaLevel != nil {
		pl := *crs.ParanoiaLevel
		sets = append(sets,
			fmt.Sprintf("setvar:tx.detection_paranoia_level=%d", pl),
			fmt.Sprintf("setvar:tx.blocking_paranoia_level=%d", pl),
		)
	}
	if crs.InboundAnomalyThreshold != nil {
		sets = append(sets, fmt.Sprintf("setvar:tx.inbound_anomaly_score_threshold=%d", *crs.InboundAnomalyThreshold))
	}
	if crs.OutboundAnomalyThreshold != nil {
		sets = append(sets, fmt.Sprintf("setvar:tx.outbound_anomaly_score_threshold=%d", *crs.OutboundAnomalyThreshold))
	}
	action := fmt.Sprintf(`SecAction "id:900990,phase:1,nolog,pass,%s"`, strings.Join(sets, ","))
	return []string{action}
}

// CRSExclusions returns removal / target-update directives after user rules.
func CRSExclusions(crs *CRSTuning) []string {
	if crs == nil {
		return nil
	}
	var out []string
	for _, id := range crs.RemoveByID {
		out = append(out, fmt.Sprintf("SecRuleRemoveById %d", id))
	}
	for _, tag := range crs.RemoveByTag {
		out = append(out, fmt.Sprintf("SecRuleRemoveByTag %s", tag))
	}
	for _, te := range crs.UpdateTargetByID {
		if len(te.RemoveTargets) == 0 {
			continue
		}
		quoted := make([]string, len(te.RemoveTargets))
		for i, t := range te.RemoveTargets {
			quoted[i] = "!" + t
		}
		out = append(out, fmt.Sprintf(`SecRuleUpdateTargetById %d "%s"`, te.ID, strings.Join(quoted, "|")))
	}
	return out
}

// JoinDocument joins preamble + optional CRS stamp + rule lines + exclusions into one SecLang string.
func JoinDocument(parts ...[]string) string {
	var lines []string
	for _, p := range parts {
		for _, line := range p {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			lines = append(lines, line)
		}
	}
	return strings.Join(lines, "\n")
}

// CountNonEmptyLines counts non-empty, non-comment SecLang lines.
func CountNonEmptyLines(doc string) int {
	n := 0
	for _, line := range strings.Split(doc, "\n") {
		trim := strings.TrimSpace(line)
		if trim == "" || strings.HasPrefix(trim, "#") {
			continue
		}
		n++
	}
	return n
}
