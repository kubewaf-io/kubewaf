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

// Package observability maps Envoy Wasm stats to the kubewaf.waf.* catalog
// and converts OTel access-log records into waf.eval span fixtures.
package observability

import (
	"regexp"
	"strings"
)

// StatTag is one bootstrap stats_config.stats_tags extractor.
type StatTag struct {
	Name  string
	Regex string
}

// StatsTags is the production extractor set (KD-14).
var StatsTags = []StatTag{
	// tag before phase: the tag regex is anchored on `_phase=`.
	// Do not consume `_phase=` so the phase extractor still matches.
	{Name: "tag", Regex: `(_tag=([0-9a-zA-Z.-]+))`},
	{Name: "phase", Regex: `(_phase=(http_request_headers|http_request_body|http_response_headers|http_response_body|http_logging|unknown))`},
	{Name: "rule_id", Regex: `(_ruleid=([0-9]+))`},
	{Name: "severity", Regex: `(_severity=([0-9]+))`},
	{Name: "waf_namespace", Regex: `(_waf_namespace=([0-9A-Za-z.-]+))`},
	{Name: "waf_name", Regex: `(_waf_name=([0-9A-Za-z.-]+))`},
	{Name: "engine", Regex: `(_engine=([0-9A-Za-z.-]+))`},
	{Name: "owner", Regex: `(_owner=([0-9a-z.:_-]+?))(?:_|$)`},
}

// CatalogName is the OTel metric name after ConversionAction.
const (
	CatalogTxTotal                = "kubewaf.waf.tx.total"
	CatalogTxAllowed              = "kubewaf.waf.tx.allowed"
	CatalogTxInterruptions        = "kubewaf.waf.tx.interruptions"
	CatalogTxInterruptionsByRule  = "kubewaf.waf.tx.interruptions_by_rule"
	CatalogRuleMatches            = "kubewaf.waf.rule.matches"
	CatalogRuleMatchesByPhase     = "kubewaf.waf.rule.matches_by_phase"
	CatalogRuleMatchesDisruptive  = "kubewaf.waf.rule.matches_disruptive"
	CatalogRuleMatchesByRule      = "kubewaf.waf.rule.matches_by_rule"
	CatalogRuleMatchesByTag       = "kubewaf.waf.rule.matches_by_tag"
	CatalogMemoryHeap             = "kubewaf.waf.memory.wasm_heap_bytes"
	CatalogConfigureFallbackRules = "kubewaf.waf.configure.fallback_rules"
)

// ExtractedStat is a /stats line after tag extractors run.
type ExtractedStat struct {
	FullName      string
	ExtractedName string
	Tags          map[string]string
	Value         float64
}

var compiledTags []compiledTag

type compiledTag struct {
	name string
	re   *regexp.Regexp
}

func init() {
	compiledTags = make([]compiledTag, 0, len(StatsTags))
	for _, t := range StatsTags {
		compiledTags = append(compiledTags, compiledTag{name: t.Name, re: regexp.MustCompile(t.Regex)})
	}
}

// ExtractTags applies production stats_tags to a full Envoy stat name.
func ExtractTags(full string) ExtractedStat {
	out := ExtractedStat{FullName: full, ExtractedName: full, Tags: map[string]string{}}
	name := full
	for _, t := range compiledTags {
		loc := t.re.FindStringSubmatchIndex(name)
		if loc == nil {
			continue
		}
		// Capture group 2 is the value when present; else group 1.
		val := ""
		if len(loc) >= 6 && loc[4] >= 0 {
			val = name[loc[4]:loc[5]]
		} else if len(loc) >= 4 && loc[2] >= 0 {
			val = name[loc[2]:loc[3]]
		}
		if val != "" {
			out.Tags[t.name] = val
		}
		// Strip the matched suffix fragment (group 0 / first group including _key=).
		if loc[0] >= 0 {
			name = name[:loc[0]] + name[loc[1]:]
		}
	}
	out.ExtractedName = name
	return out
}

func isWAFStat(full string) bool {
	return strings.Contains(full, "kubewaf_waf.") ||
		strings.Contains(full, "modsecurity_proxy_wasm.") ||
		strings.Contains(full, "wasmcustom.")
}

func isLegacyPrefix(full string) bool {
	return strings.Contains(full, "modsecurity_proxy_wasm.")
}

// CatalogConversion is the sink ConversionAction / DropAction result.
type CatalogConversion struct {
	Drop        bool
	CatalogName string
	Tags        map[string]string
}

// ConvertStat maps a full Envoy stat name to the product catalog (KD-8).
// dual_prefix: keep kubewaf_waf.* and drop modsecurity_proxy_wasm.* duplicates.
func ConvertStat(full string) CatalogConversion {
	if !isWAFStat(full) {
		return CatalogConversion{Drop: true}
	}
	if isLegacyPrefix(full) {
		return CatalogConversion{Drop: true}
	}
	ex := ExtractTags(full)
	cat := catalogFromExtracted(ex)
	if cat == "" {
		return CatalogConversion{Drop: true}
	}
	return CatalogConversion{Drop: false, CatalogName: cat, Tags: ex.Tags}
}

func catalogFromExtracted(ex ExtractedStat) string {
	n := ex.ExtractedName
	switch {
	case strings.Contains(n, "tx.total"):
		return CatalogTxTotal
	case strings.Contains(n, "tx.allowed"):
		return CatalogTxAllowed
	case strings.Contains(n, "tx.interruptions"):
		if ex.Tags["rule_id"] != "" {
			return CatalogTxInterruptionsByRule
		}
		return CatalogTxInterruptions
	case strings.Contains(n, "rule.matches_disruptive") || strings.Contains(n, "matches_disruptive"):
		return CatalogRuleMatchesDisruptive
	case strings.Contains(n, "rule.matches"):
		if ex.Tags["rule_id"] != "" {
			return CatalogRuleMatchesByRule
		}
		if ex.Tags["tag"] != "" {
			return CatalogRuleMatchesByTag
		}
		if ex.Tags["phase"] != "" || ex.Tags["severity"] != "" {
			return CatalogRuleMatchesByPhase
		}
		return CatalogRuleMatches
	case strings.Contains(n, "memory.wasm_heap_bytes"):
		return CatalogMemoryHeap
	case strings.Contains(n, "configure.fallback_rules"):
		return CatalogConfigureFallbackRules
	default:
		return ""
	}
}
