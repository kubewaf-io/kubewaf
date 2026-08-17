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

import (
	"github.com/coreruleset/crslang/types"
)

type SecRuleActions struct {

	// DataActionTypes are not executed themselves; they provide parameters or values
	// that other actions use.
	//
	// The only commonly seen one is status (e.g., status:403 or status:429),
	// which specifies the HTTP response code for blocking/redirect actions.
	// +kubebuilder:validation:Optional
	Data []DataAction `json:"data,omitempty" yaml:"data,omitempty" mapstructure:"data,omitempty"`

	// DisruptiveAction specifies an action that interrupts, blocks, allows, or otherwise alters
	// the normal flow of the HTTP transaction when a rule matches.
	//
	// These are the core "decision" actions in ModSecurity/Coraza rulesets.
	// Only one disruptive action is allowed per rule/chain (the last one specified wins).
	//
	// +kubebuilder:validation:Optional
	// omitempty: chain children must omit this field entirely. Emitting
	// `disruptive: null` fails OpenAPI validation (type object, not nullable).
	DisruptiveAction *DisruptiveAction `json:"disruptive,omitempty" yaml:"disruptive,omitempty" mapstructure:"disruptive,omitempty"`

	// FlowActionTypes control how rule evaluation proceeds within the current processing phase.
	//
	// The most frequently used is chain, which links multiple conditions together
	// (creating AND logic across rules). In chained rules, only the first rule should
	// contain a disruptive action.
	//
	// Other examples: skip (skip the next N rules), skipAfter (jump to a marker).
	// +kubebuilder:validation:Optional
	Flow []FlowAction `json:"flow,omitempty" yaml:"flow,omitempty" mapstructure:"flow,omitempty"`

	// NonDisruptiveActionTypes are side-effect actions that run whenever a rule matches,
	// without ever changing the rule evaluation flow or transaction outcome.
	//
	// These actions always execute — including inside chained rules and in detection-only mode.
	// They handle logging, scoring, tagging, variable updates, transformations, metadata,
	// and other utility tasks.
	//
	// Most real-world rules contain many of these (often the majority of the action list).
	// Common examples: msg, tag, severity, setvar, capture, log / nolog, t:*, ctl, initcol, exec.
	// +kubebuilder:validation:Optional
	NonDisruptive []NonDisruptiveAction `json:"non-disruptive,omitempty" yaml:"non-disruptive,omitempty" mapstructure:"non-disruptive,omitempty"`
}

type DisruptiveAction struct {
	Type  DisruptiveActionType `json:"disruptiveActionType"`
	Value string               `json:"value,omitempty"`
}

func (a DisruptiveAction) GetType() string {
	return string(a.Type)

}
func (a DisruptiveAction) GetValue() string {
	return a.Value
}

func (a DisruptiveAction) GetKind() string {
	return "DisruptiveAction"
}

// DisruptiveActionType specifies an action that interrupts, blocks, allows, or otherwise alters
// the normal flow of the HTTP transaction when a rule matches.
//
// These are the core "decision" actions in ModSecurity/Coraza rulesets.
// Only one disruptive action is allowed per rule/chain (the last one specified wins).
//
// ModSecurity: https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-%28v3.x%29#actions
// Coraza:     https://coraza.io/docs/seclang/actions
//
// Allowed values:
//
//   - allow     : explicitly allows the transaction (whitelisting / bypass)
//   - block     : applies the default blocking behavior (SecDefaultAction, usually deny/403)
//   - deny      : blocks with an error response (e.g. 403)
//   - drop      : silently drops the TCP connection (no response sent)
//   - pass      : continues processing without blocking (match logged/scored but no interrupt)
//   - pause     : delays processing for milliseconds (throttling/testing, rarely used)
//   - proxy     : proxies/redirects request to another backend (limited support)
//   - redirect  : issues an HTTP redirect to a new URL
//
// +kubebuilder:validation:Required
// +kubebuilder:validation:Enum=allow;block;deny;drop;pass;pause;proxy;redirect
type DisruptiveActionType string

const (
	// Allow terminates rule processing for the current phase (or transaction) and allows
	// the request to continue without applying any blocking action.
	// Commonly used for explicit whitelisting (trusted IPs, safe paths, false positives).
	// Overrides previous disruptive actions in some contexts.
	//
	// Example: SecRule REMOTE_ADDR "^192\.168\.1\.1$" "phase:1,id:100,allow"
	//
	// ModSecurity: https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-%28v3.x%29#allow
	// Coraza:     https://coraza.io/docs/seclang/actions#allow
	Allow DisruptiveActionType = "allow"

	// Block applies the default blocking behavior defined by SecDefaultAction
	// (most often deny + status:403 + log/auditlog).
	// Recommended in modern rulesets (e.g. OWASP CRS) as it respects global config
	// and is easy to override centrally.
	//
	// Example: SecRule ARGS "@contains attack" "phase:2,block,id:200"
	//
	// ModSecurity: https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-%28v3.x%29#block
	// Coraza:     https://coraza.io/docs/seclang/actions#block
	Block DisruptiveActionType = "block"

	// Deny immediately interrupts the transaction and returns an error response
	// (HTTP status from "status" action or engine default, usually 403).
	// Classic blocking action.
	//
	// Example: SecRule REQUEST_URI "@rx /admin" "phase:1,deny,status:403,id:300"
	//
	// ModSecurity: https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-%28v3.x%29#deny
	// Coraza:     https://coraza.io/docs/seclang/actions#deny
	Deny DisruptiveActionType = "deny"

	// Drop forcefully terminates the TCP connection without sending any response
	// (silent drop). Ideal for aggressive blocking (e.g. DoS, brute-force) to avoid
	// leaking information or wasting bandwidth.
	// In v3.x often behaves similarly to deny (engine-dependent).
	//
	// Example: SecRule IP:attempts "@gt 10" "phase:1,drop,id:400,msg:'Brute force'"
	//
	// ModSecurity: https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-%28v3.x%29#drop
	// Coraza:     https://coraza.io/docs/seclang/actions#drop
	Drop DisruptiveActionType = "drop"

	// Pass continues rule processing without applying any disruptive/blocking action.
	// The match is still logged, scored, or tagged if other actions present,
	// but the transaction proceeds normally.
	//
	// Example: SecRule ARGS "@rx safe" "phase:2,pass,setvar:TX.scored=1,id:500"
	//
	// ModSecurity: https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-%28v3.x%29#pass
	// Coraza:     https://coraza.io/docs/seclang/actions#pass
	Pass DisruptiveActionType = "pass"

	// Pause delays further processing of the transaction for the specified number
	// of milliseconds (e.g. pause:500).
	// Rarely used in production; mainly for testing, rate-limiting suspicious clients,
	// or simulating latency. Limited practical use.
	//
	// Example: SecRule REMOTE_ADDR "@ipMatch 1.2.3.0/24" "phase:1,pause:1000,id:600"
	//
	// ModSecurity: https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-%28v3.x%29#pause
	// Coraza:     https://coraza.io/docs/seclang/actions (limited mention/support)
	Pause DisruptiveActionType = "pause"

	// Proxy forwards/redirects the request to another backend server (reverse proxy mode).
	// Requires engine support for proxying. Useful for WAF-as-proxy, honeypots,
	// or rerouting bad traffic. Support is partial/engine-dependent in Coraza.
	//
	// Example: SecRule ARGS "@contains malicious" "phase:2,proxy:http://sandbox.example.com,id:700"
	//
	// ModSecurity: https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-%28v3.x%29#proxy
	// Coraza:     https://coraza.io/docs/seclang/actions#proxy (partial/engine-dependent)
	Proxy DisruptiveActionType = "proxy"

	// Redirect issues an HTTP redirect response (usually 302) to the client,
	// pointing to a specified URL (e.g. redirect:https://example.com/blocked).
	// Status code can be overridden with "status" action (e.g. 301/307).
	//
	// Example: SecRule REQUEST_URI "@rx /blocked" "phase:1,redirect:https://example.com/error,id:800"
	//
	// ModSecurity: https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-%28v3.x%29#redirect
	// Coraza:     https://coraza.io/docs/seclang/actions#redirect
	Redirect DisruptiveActionType = "redirect"
)

type NonDisruptiveAction struct {
	Type  NonDisruptiveActionType `json:"nonDisruptiveActionType"`
	Value string                  `json:"value,omitempty"`
}

func (a NonDisruptiveAction) GetType() string {
	return string(a.Type)

}
func (a NonDisruptiveAction) GetValue() string {
	return a.Value
}

func (a NonDisruptiveAction) GetKind() string {
	return "NonDisruptiveAction"
}

// NonDisruptiveActionType specifies a non-disruptive action as defined in ModSecurity / Coraza.
//
// ModSecurity: https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-%28v3.x%29#actions
// Coraza:     https://coraza.io/docs/seclang/actions
//
// Allowed values:
//
//   - append          : appends a value to a collection variable (TX, SESSION, IP, ...)
//   - auditlog        : forces logging of the rule match to the audit log
//   - capture         : stores regex capture groups into TX.0 … TX.9
//   - ctl             : runtime control (ruleEngine, auditEngine, requestBodyAccess, …)
//   - deprecatevar    : marks a persistent variable for removal at end of phase
//   - exec            : executes an external script/binary
//   - expirevar       : sets expiration time on a persistent collection variable
//   - initcol         : initializes a persistent collection (IP, SESSION, …)
//   - log             : enables normal (non-audit) logging
//   - logdata         : adds custom data to the audit log entry
//   - multimatch      : tests every occurrence of a variable (instead of stopping at first match)
//   - noauditlog      : prevents this rule from being written to the audit log
//   - nolog           : prevents normal logging of this rule
//   - sanitiseArg / sanitiseMatched / sanitiseMatchedBytes / sanitiseRequestHeader / sanitiseResponseHeader : various sanitization actions
//   - setenv          : sets an environment variable
//   - setrsc          : sets the RESOURCE collection identifier
//   - setsid          : sets the session identifier
//   - setuid          : sets the user identifier
//   - setvar          : creates, modifies, increments or deletes variables
//
// +kubebuilder:validation:Required
// +kubebuilder:validation:Enum=append;auditlog;capture;ctl;deprecatevar;exec;expirevar;initcol;log;logdata;multiMatch;noauditlog;nolog;sanitiseArg;sanitiseMatched;sanitiseMatchedBytes;sanitiseRequestHeader;sanitiseResponseHeader;setenv;setrsc;setsid;setuid;setvar
type NonDisruptiveActionType string

const (
	// Append appends a value to an existing collection variable (most often TX, SESSION or IP).
	// Example: append:TX:custom_list=%{MATCHED_VAR_NAME}
	//
	// ModSecurity: https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-%28v3.x%29#append
	// Coraza:     https://coraza.io/docs/seclang/actions#append
	Append NonDisruptiveActionType = "append"

	// AuditLog forces logging of the rule match to the audit log
	// (overrides global audit settings for this specific rule).
	//
	// ModSecurity: https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-%28v3.x%29#auditlog
	// Coraza:     https://coraza.io/docs/seclang/actions#auditlog
	AuditLog NonDisruptiveActionType = "auditlog"

	// Capture stores regex capture groups (0–9) into TX.0 … TX.9 variables
	// for use in subsequent actions or chained rules.
	//
	// ModSecurity: https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-%28v3.x%29#capture
	// Coraza:     https://coraza.io/docs/seclang/actions#capture
	Capture NonDisruptiveActionType = "capture"

	// Ctl dynamically changes engine behaviour for the current transaction
	// (e.g. ctl:ruleEngine=Off, ctl:auditEngine=RelevantOnly, ctl:requestBodyAccess=On).
	//
	// ModSecurity: https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-%28v3.x%29#ctl
	// Coraza:     https://coraza.io/docs/seclang/actions#ctl
	Ctl NonDisruptiveActionType = "ctl"

	// DeprecateVar marks a persistent variable for removal at the end of the phase.
	// Used to clean up temporary scoring or tracking variables.
	//
	// ModSecurity: https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-%28v3.x%29#deprecatevar
	// Coraza:     https://coraza.io/docs/seclang/actions#deprecatevar
	DeprecateVar NonDisruptiveActionType = "deprecatevar"

	// Exec executes an external script or program when the rule matches.
	// Example: exec:/usr/local/bin/notify.sh %{TX.rule_id}
	//
	// ModSecurity: https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-%28v3.x%29#exec
	// Coraza:     https://coraza.io/docs/seclang/actions#exec
	Exec NonDisruptiveActionType = "exec"

	// ExpireVar sets an expiration time on a persistent collection variable.
	// Example: expirevar:IP.blocked=3600 (expires in 1 hour)
	//
	// ModSecurity: https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-%28v3.x%29#expirevar
	// Coraza:     https://coraza.io/docs/seclang/actions#expirevar
	ExpireVar NonDisruptiveActionType = "expirevar"

	// InitCol initializes a persistent collection if it doesn't already exist
	// (IP, SESSION, USER, RESOURCE, GLOBAL, etc.).
	//
	// ModSecurity: https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-%28v3.x%29#initcol
	// Coraza:     https://coraza.io/docs/seclang/actions#initcol
	InitCol NonDisruptiveActionType = "initcol"

	// Log enables normal (non-audit) logging of the rule match.
	//
	// ModSecurity: https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-%28v3.x%29#log
	// Coraza:     https://coraza.io/docs/seclang/actions#log
	Log NonDisruptiveActionType = "log"

	// LogData adds custom key-value or free-form data to the audit log entry.
	// Example: logdata:'User-Agent: %{REQUEST_HEADERS:User-Agent}'
	//
	// ModSecurity: https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-%28v3.x%29#logdata
	// Coraza:     https://coraza.io/docs/seclang/actions#logdata
	LogData NonDisruptiveActionType = "logdata"

	// MultiMatch instructs the operator to test every possible occurrence of the variable
	// instead of stopping at the first match (useful for collections like ARGS_NAMES).
	//
	// ModSecurity: https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-%28v3.x%29#multimatch
	// Coraza:     https://coraza.io/docs/seclang/actions#multimatch
	MultiMatch NonDisruptiveActionType = "multiMatch"

	// NoAuditLog prevents this rule match from being written to the audit log.
	//
	// ModSecurity: https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-%28v3.x%29#noauditlog
	// Coraza:     https://coraza.io/docs/seclang/actions#noauditlog
	NoAuditLog NonDisruptiveActionType = "noauditlog"

	// NoLog prevents normal (non-audit) logging of this rule match.
	//
	// ModSecurity: https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-%28v3.x%29#nolog
	// Coraza:     https://coraza.io/docs/seclang/actions#nolog
	NoLog NonDisruptiveActionType = "nolog"

	// SanitiseArg hides the value of a named argument in both normal and audit logs.
	//
	// ModSecurity: https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-%28v3.x%29#sanitiseArg
	// Coraza:     https://coraza.io/docs/seclang/actions#sanitisearg
	SanitiseArg NonDisruptiveActionType = "sanitiseArg"

	// SanitiseMatched hides the matched substring/value in log output.
	//
	// ModSecurity: https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-%28v3.x%29#sanitiseMatched
	// Coraza:     https://coraza.io/docs/seclang/actions#sanitisedmatched
	SanitiseMatched NonDisruptiveActionType = "sanitiseMatched"

	// SanitiseMatchedBytes hides the matched bytes (in hex) in log output.
	//
	// ModSecurity: https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-%28v3.x%29#sanitiseMatchedBytes
	// Coraza:     https://coraza.io/docs/seclang/actions#sanitisedmatchedbytes
	SanitiseMatchedBytes NonDisruptiveActionType = "sanitiseMatchedBytes"

	// SanitiseRequestHeader hides the value of a named request header in logs.
	//
	// ModSecurity: https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-%28v3.x%29#sanitiseRequestHeader
	// Coraza:     https://coraza.io/docs/seclang/actions#sanitisedrequestheader
	SanitiseRequestHeader NonDisruptiveActionType = "sanitiseRequestHeader"

	// SanitiseResponseHeader hides the value of a named response header in logs.
	//
	// ModSecurity: https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-%28v3.x%29#sanitiseResponseHeader
	// Coraza:     https://coraza.io/docs/seclang/actions#sanitisedresponseheader
	SanitiseResponseHeader NonDisruptiveActionType = "sanitiseResponseHeader"

	// SetEnv sets an environment variable accessible to scripts run via exec.
	//
	// ModSecurity: https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-%28v3.x%29#setenv
	// Coraza:     https://coraza.io/docs/seclang/actions#setenv
	SetEnv NonDisruptiveActionType = "setenv"

	// SetRsc sets the RESOURCE collection identifier for persistent storage.
	//
	// ModSecurity: https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-%28v3.x%29#setrsc
	// Coraza:     https://coraza.io/docs/seclang/actions#setrsc
	SetRsc NonDisruptiveActionType = "setrsc"

	// SetSid sets the session identifier for the SESSION collection.
	//
	// ModSecurity: https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-%28v3.x%29#setsid
	// Coraza:     https://coraza.io/docs/seclang/actions#setsid
	SetSid NonDisruptiveActionType = "setsid"

	// SetUid sets the user identifier for the USER collection.
	//
	// ModSecurity: https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-%28v3.x%29#setuid
	// Coraza:     https://coraza.io/docs/seclang/actions#setuid
	SetUid NonDisruptiveActionType = "setuid"

	// SetVar creates, increments, decrements, or deletes variables in collections.
	// Example: setvar:TX.anomaly_score=+5, setvar:IP.blocked=1
	//
	// ModSecurity: https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-%28v3.x%29#setvar
	// Coraza:     https://coraza.io/docs/seclang/actions#setvar
	SetVar NonDisruptiveActionType = "setvar"
)

type FlowAction struct {
	Type  FlowActionType `json:"flowActionType"`
	Value string         `json:"value"`
}

func (a FlowAction) GetType() string {
	return string(a.Type)

}
func (a FlowAction) GetValue() string {
	return a.Value
}

func (a FlowAction) GetKind() string {
	return "FlowAction"
}

// FlowActionType specifies a flow-control (rule chaining / skipping) action as defined in ModSecurity / Coraza.
//
// These actions influence rule evaluation order and chaining rather than directly blocking or logging.
//
// ModSecurity: https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-%28v3.x%29#actions
// Coraza:     https://coraza.io/docs/seclang/actions
//
// Allowed values:
//
//   - chain     : links this rule to the next one(s), creating AND logic (only first rule in chain can be disruptive)
//   - skip      : skips the next N rules in the current phase on match
//   - skipAfter : jumps forward to after a SecMarker with the given label on match
//
// +kubebuilder:validation:Required
// +kubebuilder:validation:Enum=chain;skip;skipAfter
type FlowActionType string

const (
	// Chain links the current rule to the next one(s), creating AND logic between conditions.
	// Only the first rule in a chain may contain a disruptive action.
	// All subsequent chained rules are evaluated only if the previous ones match.
	// Chain allows simulating complex conditions that must all be true.
	//
	// Example:
	//   SecRule REQUEST_METHOD "^POST$" "phase:1,chain,id:100"
	//   SecRule &REQUEST_HEADERS:Content-Length "@eq 0" "deny"
	//
	// ModSecurity: https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-%28v3.x%29#chain
	// Coraza:     https://coraza.io/docs/seclang/actions#chain
	Chain FlowActionType = "chain"

	// Skip skips the next N rules (or chains) in the current phase when this rule matches.
	// N is a positive integer (e.g. skip:5).
	// Useful to bypass cleanup/low-priority rules after a strong match.
	// Operates within the same phase only (does not skip across phases).
	//
	// Example:
	//   SecRule REMOTE_ADDR "^127\.0\.0\.1$" "phase:1,skip:1,id:200"
	//   SecRule &REQUEST_HEADERS:Accept "@eq 0" "deny"
	//
	// ModSecurity: https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-%28v3.x%29#skip
	// Coraza:     https://coraza.io/docs/seclang/actions#skip
	Skip FlowActionType = "skip"

	// SkipAfter jumps rule evaluation forward to the first rule after the SecMarker with the given label
	// when this rule matches.
	// Very useful in large rule sets to skip entire blocks once a threat category is confirmed.
	// Requires a corresponding SecMarker directive.
	//
	// Example:
	//   SecRule REMOTE_ADDR "^127\.0\.0\.1$" "phase:1,skipAfter:IGNORE_LOCALHOST,id:300"
	//   SecRule &REQUEST_HEADERS:Accept "@eq 0" "deny"
	//   SecMarker IGNORE_LOCALHOST
	//
	// ModSecurity: https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-%28v3.x%29#skipafter
	// Coraza:     https://coraza.io/docs/seclang/actions#skipafter
	SkipAfter FlowActionType = "skipAfter"

	FlowUnknown FlowActionType = "flowUnknown"
)

type DataAction struct {
	Type  DataActionType `json:"dataActionType"`
	Value string         `json:"value,omitempty"`
}

func (a DataAction) GetType() string {
	return string(a.Type)

}
func (a DataAction) GetValue() string {
	return a.Value
}

func (a DataAction) GetKind() string {
	return "DataAction"
}

// DataActionType specifies actions that deal with data manipulation, response control,
// or namespace registration — typically used in very specific contexts.
//
// These are less common than disruptive or non-disruptive actions.
//
// ModSecurity: https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-%28v3.x%29#actions
// Coraza:     https://coraza.io/docs/seclang/actions
//
// Allowed values:
//
//   - status  : sets the HTTP response status code when a disruptive action is triggered
//   - xlmns   : registers an XML namespace prefix for XPath expressions
//
// +kubebuilder:validation:Required
// +kubebuilder:validation:Enum=status;xmlns
type DataActionType string

const (
	// Status specifies the HTTP response status code to return when a disruptive
	// action (e.g. deny, block, redirect) is triggered by the rule.
	//
	// Commonly used values:
	//   - 403  (Forbidden – default in most engines)
	//   - 429  (Too Many Requests – rate limiting)
	//   - 500  (Internal Server Error)
	//   - 302  (Found – for redirects)
	//
	// If not specified, falls back to the engine's default (usually 403).
	//
	// Example in rule:
	//   SecRule ARGS "@contains blockme" "phase:2,deny,status:429,id:9001"
	//
	// ModSecurity: https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-%28v3.x%29#status
	// Coraza:     https://coraza.io/docs/seclang/actions#status
	Status DataActionType = "status"

	// XLMNS registers a namespace prefix for use in XPath expressions when processing XML bodies.
	//
	// Required when using XPath in variables or operators (validateDTD, validateSchema, etc.)
	// to target namespaced elements/attributes.
	//
	// Syntax example (classic SecRule style):
	//   SecRule XML:/soap:Envelope/soap:Body "@contains malicious" \
	//           "phase:2,deny,xmlns:soap='http://schemas.xmlsoap.org/soap/envelope/'"
	//
	// Only relevant for rules inspecting XML request or response bodies.
	// Very rarely used in modern APIs (most traffic is JSON nowadays).
	//
	// ModSecurity: https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-%28v3.x%29#xmlns
	// Coraza:     https://coraza.io/docs/seclang/actions#xmlns
	XLMNS DataActionType = "xmlns"
)

//go:generate goverter gen .

// +kubebuilder:object:generate=false
// goverter:converter
// goverter:output:file ./convert/zz_generated_actions.go
// goverter:enum:unknown DataUnknown
type DataActionTypeMapper interface {
	Convert(source DataActionType) types.DataAction
}

// +kubebuilder:object:generate=false
// goverter:converter
// goverter:output:file ./convert/zz_generated_actions.go
// goverter:enum:unknown FlowUnknown
type FlowActionTypeMapper interface {
	Convert(source FlowActionType) types.FlowAction
}

// +kubebuilder:object:generate=false
// goverter:converter
// goverter:output:file ./convert/zz_generated_actions.go
// goverter:enum:unknown @ignore
type FlowActionTypeReverseMapper interface {
	Convert(source types.FlowAction) FlowActionType
}

// +kubebuilder:object:generate=false
// goverter:converter
// goverter:output:file ./convert/zz_generated_actions.go
// goverter:enum:unknown NonDisruptiveUnknown
type NonDisruptiveActionTypeMapper interface {
	Convert(source NonDisruptiveActionType) types.NonDisruptiveAction
}

// +kubebuilder:object:generate=false
// goverter:converter
// goverter:output:file ./convert/zz_generated_actions.go
// goverter:enum:unknown Unknown
type DisruptiveActionMapper interface {
	Convert(source DisruptiveActionType) types.DisruptiveAction
}
