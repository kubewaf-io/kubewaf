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

package v1beta1

// SecRuleMetadata contains all the identification, versioning, and descriptive
// metadata of a ModSecurity/Coraza SecRule.
//
// In classic SecRule syntax this is everything that appears before the actions
// (e.g. id:900100, msg:'SQL Injection Attempt', phase:2, severity:CRITICAL, ...).
//
// These fields are used for:
//   - Unique rule identification and referencing (SecRuleRemoveById, etc.)
//   - Logging and alerting (msg, severity, tags)
//   - Rule-set management (rev, ver, maturity — especially in OWASP CRS)
//   - Execution control (phase)
//
// ModSecurity: https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-%28v3.x%29#secrule
// Coraza:     https://coraza.io/docs/seclang/directives (metadata/phase) + https://coraza.io/docs/seclang/syntax
type SecRuleMetadata struct {
	// OnlyPhaseMetadata embeds phase and comment for rules that only need
	// phase information (common in SecAction / SecMarker).
	OnlyPhaseMetadata `json:",inline" yaml:",inline"`

	// Id is the unique numeric identifier of the rule.
	// Used for rule updates, removal, and referencing (SecRuleRemoveById, …).
	//
	// Optional: when omitted (or 0), the SecRule controller allocates a cluster-unique
	// id from the SecRuleIDPool singleton (default range 100000–999999) and records it
	// on status.ruleId / status.assignedIds. Prefer explicit ids for CRS/shared rules;
	// omit for custom rules and let the pool assign.
	//
	// Example: id:900100
	Id int `json:"id,omitempty" yaml:"id,omitempty" mapstructure:"id,omitempty"`

	// Msg is the human-readable message describing what the rule detects.
	// Appears in audit logs and alerts when the rule matches.
	//
	// Example: msg:'SQL Injection Attempt'
	Msg string `json:"message,omitempty" yaml:"message,omitempty" mapstructure:"message,omitempty"`

	// Maturity indicates the maturity level of the rule (CRS-specific).
	// Range: 0–9 (9 = production-ready, extensively tested).
	// Used by OWASP Core Rule Set to manage rule stability and false-positive risk.
	//
	// Example: maturity:9
	Maturity string `json:"maturity,omitempty" yaml:"maturity,omitempty" mapstructure:"maturity,omitempty"`

	// Rev is the revision of this specific rule (CRS-specific).
	// Allows the same id to be updated over time while tracking changes.
	//
	// Example: rev:'2.1.3'
	Rev string `json:"revision,omitempty" yaml:"revision,omitempty" mapstructure:"revision,omitempty"`

	// Severity defines how serious a match is (used for alert prioritization).
	// Can be numeric (0–7) or text (CRITICAL, ERROR, WARNING, NOTICE, INFO).
	//
	// Example: severity:CRITICAL or severity:2
	Severity string `json:"severity,omitempty" yaml:"severity,omitempty" mapstructure:"severity,omitempty"`

	// Tags categorise the rule (multiple allowed). Used for filtering,
	// grouping, and removal (SecRuleRemoveByTag).
	// Common CRS tags: WEB_ATTACK/XSS, OWASP_CRS, paranoia-level/1, etc.
	//
	// The SecRule controller also mirrors each tag onto the CR's Kubernetes
	// labels as seclang.kubewaf.io/tag.<sanitized>=true for RuleSet selectors.
	//
	// Example: tag:'WEB_ATTACK/SQL_INJECTION', tag:'paranoia-level/1'
	Tags []string `json:"tags,omitempty" yaml:"tags,omitempty" mapstructure:"tags,omitempty" copier:"Tags"`

	// Ver is the version of the rule set this rule belongs to (CRS-specific).
	//
	// Example: ver:'CRS/4.0.0'
	Ver string `json:"version,omitempty" yaml:"version,omitempty" mapstructure:"version,omitempty"`
}

// OnlyPhaseMetadata contains the minimal metadata needed when a rule
// only specifies a phase (commonly used with SecAction and SecMarker).
type OnlyPhaseMetadata struct {
	CommentMetadata `json:",inline" yaml:",inline"`

	// Phase defines in which processing phase the rule executes.
	// Valid values: 1 (Request Headers), 2 (Request Body),
	// 3 (Response Headers), 4 (Response Body), 5 (Logging).
	//
	// Example: phase:2
	Phase string `json:"phase,omitempty" yaml:"phase,omitempty" mapstructure:"phase,omitempty"`
}

// CommentMetadata holds an optional free-text comment for the rule.
// This is a non-standard extension supported by many parsers (including Coraza
// and crslang) for human-readable documentation inside the rule.
type CommentMetadata struct {
	// Comment is an arbitrary human-readable note attached to the rule.
	// Not sent to the engine; used only for documentation and tooling.
	//
	// Example: comment:'This rule protects against CVE-2023-1234'
	Comment string `json:"comment,omitempty" yaml:"comment,omitempty" mapstructure:"comment,omitempty"`
}
