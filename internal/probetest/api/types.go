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

// Package api holds internal EvalRequest/EvalResponse wire types for the
// Subresource API Server → Test HTTP Server hop (K25). Not a Kubernetes API.
package api

// EvalRequest is a self-contained evaluation job. No kube object references.
type EvalRequest struct {
	// Directives is a single SecLang document (joined lines) already Coraza-safe.
	Directives string `json:"directives"`

	// DataFiles maps basenames → file bodies for @pmFromFile / @ipMatchFromFile.
	DataFiles map[string][]byte `json:"dataFiles,omitempty"`

	Request EvalHTTPRequest `json:"request"`

	Options EvalOptions `json:"options,omitempty"`

	// TraceID for log correlation (optional; API server generates).
	TraceID string `json:"traceId,omitempty"`
}

// EvalHTTPRequest is the simulated application HTTP request.
type EvalHTTPRequest struct {
	Method     string            `json:"method"`
	Path       string            `json:"path"`
	RawQuery   string            `json:"rawQuery,omitempty"`
	Headers    map[string]string `json:"headers,omitempty"`
	Body       []byte            `json:"body,omitempty"`
	RemoteAddr string            `json:"remoteAddr,omitempty"`
	ClientPort int               `json:"clientPort,omitempty"`
	ServerAddr string            `json:"serverAddr,omitempty"`
	ServerPort int               `json:"serverPort,omitempty"`
}

// EvalOptions controls evaluation bounds.
type EvalOptions struct {
	// MaxMatches defaults to 50, max 500.
	MaxMatches int `json:"maxMatches,omitempty"`
	// TimeoutSeconds defaults to 5, max 30.
	TimeoutSeconds int `json:"timeoutSeconds,omitempty"`
	// PreferNoCache forces a fresh compile even if caching is enabled.
	PreferNoCache bool `json:"preferNoCache,omitempty"`
}

// EvalResponse is the evaluation outcome from the Test HTTP Server.
type EvalResponse struct {
	Engine        string         `json:"engine"`
	EngineVersion string         `json:"engineVersion"`
	RulesLoaded   int            `json:"rulesLoaded"`
	Interruption  *EvalInterrupt `json:"interruption,omitempty"`
	Matches       []EvalMatch    `json:"matches,omitempty"`
	Anomaly       *EvalAnomaly   `json:"anomaly,omitempty"`
	HTTP          EvalHTTPView   `json:"http"`
	DurationMs    int64          `json:"durationMs"`
	CacheHit      bool           `json:"cacheHit,omitempty"`
}

// EvalInterrupt mirrors a go-coraza interruption.
type EvalInterrupt struct {
	Disrupted bool   `json:"disrupted"`
	Action    string `json:"action"`
	Status    int    `json:"status,omitempty"`
	RuleID    int    `json:"ruleId,omitempty"`
}

// EvalMatch is one matched rule.
type EvalMatch struct {
	RuleID      int      `json:"ruleId"`
	Msg         string   `json:"msg,omitempty"`
	Phase       int      `json:"phase,omitempty"`
	Severity    string   `json:"severity,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	MatchedData string   `json:"matchedData,omitempty"`
	Variable    string   `json:"variable,omitempty"`
}

// EvalAnomaly holds anomaly scores when available.
type EvalAnomaly struct {
	Inbound  int `json:"inbound"`
	Outbound int `json:"outbound"`
}

// EvalHTTPView summarizes would-block status.
type EvalHTTPView struct {
	WouldStatus int    `json:"wouldStatus"`
	WouldBody   string `json:"wouldBody,omitempty"`
}

// Wire error class codes (redacted; never echo full directives).
const (
	ErrClassCompileFailed  = "compile_failed"
	ErrClassTimeout        = "timeout"
	ErrClassInvalidRequest = "invalid_request"
	ErrClassTooLarge       = "too_large"
	ErrClassBusy           = "busy"
	ErrClassInternal       = "internal"
)

// ErrorBody is a redacted error response from the Test HTTP Server.
type ErrorBody struct {
	// Class is a short machine-readable code.
	Class string `json:"class"`
	// Message is a short human-readable description without secrets/directives.
	Message string `json:"message,omitempty"`
}
