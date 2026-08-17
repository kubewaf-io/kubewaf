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

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Condition types reported on ProbeStatus.
const (
	ConditionAssembled      = "Assembled"
	ConditionEvaluated      = "Evaluated"
	ConditionEvalEngineMode = "EvalEngineMode"
	ConditionEngineParity   = "EngineParity"
)

// Condition reasons.
const (
	ReasonRulesResolved        = "RulesResolved"
	ReasonComplete             = "Complete"
	ReasonSecRuleEngineOn      = "SecRuleEngineOn"
	ReasonCorazaNotModSecurity = "CorazaNotModSecurity"
)

// ProbePhase is the high-level lifecycle of a one-shot probe evaluation.
type ProbePhase string

const (
	// ProbePhaseComplete means evaluation finished (including would-block).
	ProbePhaseComplete ProbePhase = "Complete"
	// ProbePhaseFailed means assembly or evaluation failed (rarely used when
	// errors are returned as metav1.Status instead).
	ProbePhaseFailed ProbePhase = "Failed"
)

// ProbeRequestedMode is the mode echo from X-KubeWAF-Probe-Mode (K28).
// It does not change evaluation engine mode (always SecRuleEngine On).
type ProbeRequestedMode string

const (
	// ProbeModeDetectionOnly is the default mode echo.
	ProbeModeDetectionOnly ProbeRequestedMode = "DetectionOnly"
	// ProbeModeBlocking is an alternate mode echo.
	ProbeModeBlocking ProbeRequestedMode = "Blocking"
)

// Probe is the JSON result returned on HTTP 200 for a successful pass-through probe.
// It is not stored in etcd. There is no user-facing ProbeSpec request body (K32).
//
// +kubebuilder:object:root=true
type Probe struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Status holds evaluation outcome. Spec is intentionally omitted (no request envelope).
	// +optional
	Status ProbeStatus `json:"status,omitempty"`
}

// ProbeStatus is the evaluation result.
type ProbeStatus struct {
	// Phase is Complete when evaluation finished.
	// +optional
	Phase ProbePhase `json:"phase,omitempty"`

	// Engine identifies the probe evaluation engine (always "Coraza" for go-coraza).
	// +optional
	Engine string `json:"engine,omitempty"`

	// EngineVersion is the go-coraza module version string.
	// +optional
	EngineVersion string `json:"engineVersion,omitempty"`

	// RequestedMode echoes X-KubeWAF-Probe-Mode (default DetectionOnly). Evaluation
	// always uses SecRuleEngine On (K28).
	// +optional
	RequestedMode ProbeRequestedMode `json:"requestedMode,omitempty"`

	// Target identifies the parent object that was probed.
	// +optional
	Target *ProbeTarget `json:"target,omitempty"`

	// RequestEcho is a safe subset of the derived simulated request.
	// +optional
	RequestEcho *ProbeRequestEcho `json:"requestEcho,omitempty"`

	// Assembly counters (no directive dump in v1 — K22).
	// +optional
	Assembly *ProbeAssembly `json:"assembly,omitempty"`

	// Interruption is set when go-coraza disrupted the transaction.
	// +optional
	Interruption *ProbeInterruption `json:"interruption,omitempty"`

	// Anomaly scores when available from the engine.
	// +optional
	Anomaly *ProbeAnomaly `json:"anomaly,omitempty"`

	// Matches lists rules that fired (capped by maxMatches).
	// +optional
	Matches []ProbeMatch `json:"matches,omitempty"`

	// HTTP summarizes would-block status for authoring UX.
	// +optional
	HTTP *ProbeHTTPView `json:"http,omitempty"`

	// Conditions include Assembled, Evaluated, EvalEngineMode, EngineParity.
	// +optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// ProbeTarget identifies the parent CR that was probed.
type ProbeTarget struct {
	// Kind is SecRule, RuleSet, or WAF.
	Kind string `json:"kind"`
	// Name of the parent object.
	Name string `json:"name"`
	// Namespace of the parent object.
	Namespace string `json:"namespace"`
	// Group is the storage API group (seclang.kubewaf.io or waf.kubewaf.io).
	// +optional
	Group string `json:"group,omitempty"`
	// UID of the parent object when known.
	// +optional
	UID string `json:"uid,omitempty"`
}

// ProbeRequestEcho is a safe subset of the pass-through derived request.
type ProbeRequestEcho struct {
	// Method is the simulated HTTP method.
	Method string `json:"method"`
	// Path is the simulated application path.
	Path string `json:"path"`
	// RawQuery is the client query string (unparsed).
	// +optional
	RawQuery string `json:"rawQuery,omitempty"`
}

// ProbeAssembly holds assembly counters (no directives field in v1).
type ProbeAssembly struct {
	// RulesLoaded is the number of SecRule-like lines / rules loaded.
	// +optional
	RulesLoaded int `json:"rulesLoaded,omitempty"`
	// ActionsLoaded is the number of SecAction-like lines when known.
	// +optional
	ActionsLoaded int `json:"actionsLoaded,omitempty"`
	// DirectivesCount is non-empty SecLang lines after preamble join.
	// +optional
	DirectivesCount int `json:"directivesCount,omitempty"`
	// DataFilesCount is the number of resolved data files sent to the engine.
	// +optional
	DataFilesCount int `json:"dataFilesCount,omitempty"`
	// DroppedDataFiles lists basenames dropped under IgnoreUnknown policy.
	// +optional
	DroppedDataFiles []string `json:"droppedDataFiles,omitempty"`
}

// ProbeInterruption mirrors go-coraza interruption for the probe result.
type ProbeInterruption struct {
	// Disrupted is true when the engine interrupted the transaction.
	Disrupted bool `json:"disrupted"`
	// Action is the disruptive action name (deny, drop, …) or "pass".
	// +optional
	Action string `json:"action,omitempty"`
	// Status is the interruption HTTP status when set.
	// +optional
	Status int `json:"status,omitempty"`
	// RuleID is the interrupting rule id when available.
	// +optional
	RuleID int `json:"ruleId,omitempty"`
}

// ProbeAnomaly holds anomaly scores when readable from the engine.
type ProbeAnomaly struct {
	// Inbound anomaly score.
	// +optional
	Inbound int `json:"inbound,omitempty"`
	// Outbound anomaly score.
	// +optional
	Outbound int `json:"outbound,omitempty"`
}

// ProbeMatch is one matched rule in the evaluation result.
type ProbeMatch struct {
	// RuleID is the matched rule id.
	RuleID int `json:"ruleId"`
	// Msg is the rule message when available.
	// +optional
	Msg string `json:"msg,omitempty"`
	// Phase is the SecLang phase when known.
	// +optional
	Phase int `json:"phase,omitempty"`
	// Severity is the rule severity string when known.
	// +optional
	Severity string `json:"severity,omitempty"`
	// Tags are rule tags.
	// +optional
	Tags []string `json:"tags,omitempty"`
	// MatchedData is a short matched value (may be truncated).
	// +optional
	MatchedData string `json:"matchedData,omitempty"`
	// Variable is the matched variable name when known.
	// +optional
	Variable string `json:"variable,omitempty"`
}

// ProbeHTTPView summarizes would-block for authoring UX (K28).
type ProbeHTTPView struct {
	// WouldStatus is 200 when not disrupted; deny/drop → interruption status or 403.
	WouldStatus int `json:"wouldStatus"`
	// WouldBody is a short body hint (e.g. "Forbidden") when disrupted.
	// +optional
	WouldBody string `json:"wouldBody,omitempty"`
}
