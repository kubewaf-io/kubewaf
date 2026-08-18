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

package observability

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
	"time"
)

const (
	hardcodedTraceID = "00000000000000000000000000000001"
	hardcodedSpanID  = "a1b2c3d4e5f60708"
)

// EvalIDs is the uniqueness/parent contract for waf.eval spans.
type EvalIDs struct {
	TraceID string
	SpanID  string
	Parent  string
}

// MintEvalIDs returns unique hex IDs. A valid W3C traceparent supplies tid+parent;
// a new span ID is always minted.
func MintEvalIDs(requestID, traceparent string, now time.Time) EvalIDs {
	seed := requestID + "\x00" + now.UTC().Format(time.RFC3339Nano)
	sum := sha256.Sum256([]byte(seed))
	tid := hex.EncodeToString(sum[:16])
	sid := hex.EncodeToString(sum[16:24])
	parent := ""
	if tp := parseTraceparentParts(traceparent); tp.valid {
		tid = tp.traceID
		parent = tp.parent
	}
	if tid == hardcodedTraceID {
		tid = hex.EncodeToString(sum[:16])
	}
	if sid == hardcodedSpanID {
		sid = hex.EncodeToString(sum[16:24])
	}
	return EvalIDs{TraceID: tid, SpanID: sid, Parent: parent}
}

type traceparentParts struct {
	valid   bool
	traceID string
	parent  string
}

func parseTraceparentParts(tp string) traceparentParts {
	parts := strings.Split(strings.TrimSpace(tp), "-")
	if len(parts) < 4 {
		return traceparentParts{}
	}
	if len(parts[1]) != 32 || len(parts[2]) != 16 {
		return traceparentParts{}
	}
	return traceparentParts{valid: true, traceID: parts[1], parent: parts[2]}
}

// EncodeEvalOTLPJSON builds a parseable resourceSpans body (events included).
func EncodeEvalOTLPJSON(span EvalSpan, ids EvalIDs) ([]byte, error) {
	events := make([]any, 0, len(span.Events))
	for _, ev := range span.Events {
		name := ev.Event
		if name == "" {
			name = "waf.rule_match"
		}
		attrs := []map[string]any{
			otlpStr("rule_id", strconv.FormatInt(ev.RuleID, 10)),
			otlpStr("phase", ev.Phase),
			otlpStr("severity", strconv.Itoa(ev.Severity)),
			otlpStr("disruptive", strconv.FormatBool(ev.Disruptive)),
		}
		if ev.AnomalyScore > 0 {
			attrs = append(attrs, otlpStr("anomaly_score", strconv.FormatInt(ev.AnomalyScore, 10)))
		}
		if ev.Msg != "" {
			attrs = append(attrs, otlpStr("msg", ev.Msg))
		}
		if ev.Data != "" {
			attrs = append(attrs, otlpStr("data", ev.Data))
		}
		events = append(events, map[string]any{
			"name":       name,
			"attributes": attrs,
		})
	}
	statusCode := 1
	if span.Status == "Error" {
		statusCode = 2
	}
	start := span.Start
	if start.IsZero() {
		start = time.Now().UTC()
	}
	end := span.End
	if end.IsZero() {
		end = start
	}
	attrs := make([]map[string]any, 0, len(span.Attributes))
	for k, v := range span.Attributes {
		attrs = append(attrs, otlpStr(k, v))
	}
	resAttrs := make([]map[string]any, 0, len(span.Resource))
	for k, v := range span.Resource {
		resAttrs = append(resAttrs, otlpStr(k, v))
	}
	doc := map[string]any{
		"resourceSpans": []any{
			map[string]any{
				"resource": map[string]any{"attributes": resAttrs},
				"scopeSpans": []any{
					map[string]any{
						"scope": map[string]any{"name": "kubewaf"},
						"spans": []any{
							map[string]any{
								"name":              span.Name,
								"kind":              1,
								"traceId":           ids.TraceID,
								"spanId":            ids.SpanID,
								"parentSpanId":      ids.Parent,
								"startTimeUnixNano": strconv.FormatInt(start.UnixNano(), 10),
								"endTimeUnixNano":   strconv.FormatInt(end.UnixNano(), 10),
								"status":            map[string]any{"code": statusCode},
								"attributes":        attrs,
								"events":            events,
							},
						},
					},
				},
			},
		},
	}
	return json.Marshal(doc)
}

func otlpStr(key, val string) map[string]any {
	return map[string]any{"key": key, "value": map[string]any{"stringValue": val}}
}

// PinnedFilterStateKey is written by Wasm via setFilterState and read by the
// Envoy OTel access logger as %FILTER_STATE(wasm.kubewaf.event:PLAIN)%.
const PinnedFilterStateKey = "wasm.kubewaf.event"

// PinnedMetadataFilter / path is the access-log metadata filter.
const (
	PinnedMetadataFilter = "envoy.filters.http.wasm"
	PinnedMetadataExport = "kubewaf.export"
)

// AccessLogRecord is the OTLP log body JSON (filter-state rollup) plus HCM attributes.
type AccessLogRecord struct {
	Body       string            `json:"body"`
	Attributes map[string]string `json:"attributes"`
}

// EventRollup is the Wasm request-level JSON stored in filter state.
type EventRollup struct {
	Interrupted  bool         `json:"interrupted"`
	Action       string       `json:"action"`
	Phase        string       `json:"phase,omitempty"`
	ConfigID     string       `json:"config_id,omitempty"`
	WAFNamespace string       `json:"waf_namespace,omitempty"`
	WAFName      string       `json:"waf_name,omitempty"`
	Engine       string       `json:"engine,omitempty"`
	ClientAddr   string       `json:"client.address,omitempty"`
	AnomalyScore int64        `json:"anomaly_score,omitempty"`
	Matches      []MatchEvent `json:"matches"`
}

// MatchEvent is one span event (cap 16 + interrupting rule).
type MatchEvent struct {
	Event        string `json:"event"`
	RuleID       int64  `json:"rule_id,omitempty"`
	Phase        string `json:"phase,omitempty"`
	Severity     int    `json:"severity,omitempty"`
	AnomalyScore int64  `json:"anomaly_score,omitempty"`
	Msg          string `json:"msg,omitempty"`
	Data         string `json:"data,omitempty"`
	Disruptive   bool   `json:"disruptive,omitempty"`
}

// EvalSpan is the product query surface (Collector transform contract; not a live otelcol path).
type EvalSpan struct {
	Name       string
	Kind       string
	Status     string
	Parent     string
	Start      time.Time
	End        time.Time
	Resource   map[string]string
	Attributes map[string]string
	Events     []MatchEvent
}

// LogToEvalSpan converts one Envoy OTel access-log record into a waf.eval span.
func LogToEvalSpan(rec AccessLogRecord) (EvalSpan, error) {
	var roll EventRollup
	if err := json.Unmarshal([]byte(rec.Body), &roll); err != nil {
		return EvalSpan{}, err
	}
	status := "Unset"
	if roll.Interrupted {
		status = "Error"
	}
	attrs := map[string]string{
		"waf.namespace":   roll.WAFNamespace,
		"waf.name":        roll.WAFName,
		"waf.interrupted": strconv.FormatBool(roll.Interrupted),
		"waf.action":      roll.Action,
		"waf.phase":       roll.Phase,
	}
	for k, v := range rec.Attributes {
		if v != "" {
			attrs[k] = v
		}
	}
	if roll.ClientAddr != "" {
		attrs["client.address"] = roll.ClientAddr
	}
	if roll.AnomalyScore > 0 {
		attrs["waf.anomaly_score"] = strconv.FormatInt(roll.AnomalyScore, 10)
	}
	res := map[string]string{
		"service.name":      "kubewaf",
		"service.namespace": roll.WAFNamespace,
		"waf.namespace":     roll.WAFNamespace,
		"waf.name":          roll.WAFName,
		"waf.engine":        firstNonEmpty(roll.Engine, "modsecurity"),
		"waf.config_id":     roll.ConfigID,
	}
	events := capMatches(roll.Matches)
	parent := parseTraceparent(rec.Attributes["traceparent"])
	now := time.Now().UTC()
	return EvalSpan{
		Name:       "waf.eval",
		Kind:       "INTERNAL",
		Status:     status,
		Parent:     parent,
		Start:      now,
		End:        now,
		Resource:   res,
		Attributes: attrs,
		Events:     events,
	}, nil
}

func capMatches(in []MatchEvent) []MatchEvent {
	if len(in) <= 16 {
		return in
	}
	out := append([]MatchEvent(nil), in[:16]...)
	for _, ev := range in[16:] {
		if ev.Event == "waf.tx_interrupt" || ev.Disruptive {
			out[15] = ev
		}
	}
	return out
}

func parseTraceparent(tp string) string {
	// W3C: version-traceid-parentid-flags
	parts := strings.Split(strings.TrimSpace(tp), "-")
	if len(parts) >= 3 && len(parts[2]) == 16 {
		return parts[2]
	}
	return ""
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
