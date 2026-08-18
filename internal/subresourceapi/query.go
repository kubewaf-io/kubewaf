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

package subresourceapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	wafv1beta1 "github.com/kubewaf-io/kubewaf/api/waf/v1beta1"
)

const (
	defaultTraceLimit    = 50
	maxTraceLimit        = 200
	defaultTraceLookback = time.Hour
	maxTraceLookback     = 24 * time.Hour
	maxPromQLBytes       = 8 * 1024
	maxQueryRangeSec     = 24 * 3600
	minQueryStepSec      = 15
	maxQueryPoints       = 120
	// defaultMetricsSelector is used when ?query= is omitted: all series for
	// the requested WAF (or SAR-authorized WAFs on clustermetrics). ScopePromQL
	// injects waf_namespace/waf_name into the empty selector.
	defaultMetricsSelector = "{}"
)

func (s *Server) handleWAFMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		WriteMethodNotAllowed(w)
		return
	}
	if !s.cfg.EnableQuery {
		WriteStatus(w, &MappedError{HTTPStatus: 404, Reason: ReasonNotFound, Message: "metrics subresource is disabled"})
		return
	}
	user, groups, authErr := s.authenticate(r)
	if authErr != nil {
		WriteStatus(w, authErr)
		return
	}
	route, err := ParseWAFSubresourcePath(r.URL.Path)
	if err != nil {
		WriteStatus(w, mapPathError(err))
		return
	}
	if merr := s.sar.CanGetParent(r.Context(), user, groups, ParentWAF, route.Namespace, route.Name); merr != nil {
		WriteStatus(w, merr)
		return
	}
	q := strings.TrimSpace(r.URL.Query().Get("query"))
	if q == "" {
		q = defaultMetricsSelector
	}
	if len(q) > maxPromQLBytes {
		WriteStatus(w, &MappedError{HTTPStatus: 400, Reason: ReasonBadRequest, Message: "query exceeds size limit"})
		return
	}
	if !s.acquireQuerySlot(route.Namespace) {
		WriteStatus(w, &MappedError{HTTPStatus: 429, Reason: ReasonTooManyRequests, Message: "query concurrency limit exceeded"})
		return
	}
	defer s.releaseQuerySlot(route.Namespace)
	scoped, err := ScopePromQL(q, route.Namespace, route.Name)
	if err != nil {
		WriteStatus(w, &MappedError{HTTPStatus: 400, Reason: "UnscopedQuery", Message: err.Error()})
		return
	}
	s.proxyMetrics(w, r, scoped)
}

func (s *Server) handleWAFTraces(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		WriteMethodNotAllowed(w)
		return
	}
	if !s.cfg.EnableQuery {
		WriteStatus(w, &MappedError{HTTPStatus: 404, Reason: ReasonNotFound, Message: "traces subresource is disabled"})
		return
	}
	user, groups, authErr := s.authenticate(r)
	if authErr != nil {
		WriteStatus(w, authErr)
		return
	}
	route, err := ParseWAFSubresourcePath(r.URL.Path)
	if err != nil {
		WriteStatus(w, mapPathError(err))
		return
	}
	if merr := s.sar.CanGetParent(r.Context(), user, groups, ParentWAF, route.Namespace, route.Name); merr != nil {
		WriteStatus(w, merr)
		return
	}
	if s.query == nil {
		WriteStatus(w, &MappedError{HTTPStatus: 503, Reason: "NoTracesBackend", Message: "traces backend is not configured"})
		return
	}
	if !s.acquireQuerySlot(route.Namespace) {
		WriteStatus(w, &MappedError{HTTPStatus: 429, Reason: ReasonTooManyRequests, Message: "query concurrency limit exceeded"})
		return
	}
	defer s.releaseQuerySlot(route.Namespace)
	if route.Extra != "" {
		body, ct, merr := s.query.jaegerTraceByID(r.Context(), route.Extra)
		if merr != nil {
			WriteStatus(w, merr)
			return
		}
		filtered, ok := filterJaegerToWAF(body, route.Namespace, route.Name)
		if !ok {
			WriteStatus(w, &MappedError{HTTPStatus: 404, Reason: ReasonNotFound, Message: "trace not found for this WAF"})
			return
		}
		writeRaw(w, ct, filtered)
		return
	}
	if _, err := scopedTraceTags(r.URL.Query().Get("tags"), route.Namespace, route.Name); err != nil {
		WriteStatus(w, &MappedError{HTTPStatus: 400, Reason: "UnscopedQuery", Message: err.Error()})
		return
	}
	tags, _ := json.Marshal(map[string]string{
		"waf.namespace": route.Namespace,
		"waf.name":      route.Name,
	})
	startUs, endUs, limit := parseTraceWindow(r)
	body, ct, merr := s.query.jaegerTraces(r.Context(), string(tags), startUs, endUs, limit)
	if merr != nil {
		WriteStatus(w, merr)
		return
	}
	filtered, _ := filterJaegerToWAF(body, route.Namespace, route.Name)
	writeRaw(w, ct, filtered)
}

func (s *Server) handleClusterMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		WriteMethodNotAllowed(w)
		return
	}
	if !s.cfg.EnableQuery {
		WriteStatus(w, &MappedError{HTTPStatus: 404, Reason: ReasonNotFound, Message: "clustermetrics is disabled"})
		return
	}
	user, groups, authErr := s.authenticate(r)
	if authErr != nil {
		WriteStatus(w, authErr)
		return
	}
	q := strings.TrimSpace(r.URL.Query().Get("query"))
	if q == "" {
		q = defaultMetricsSelector
	}
	if len(q) > maxPromQLBytes {
		WriteStatus(w, &MappedError{HTTPStatus: 400, Reason: ReasonBadRequest, Message: "query exceeds size limit"})
		return
	}
	if !s.acquireQuerySlot("") {
		WriteStatus(w, &MappedError{HTTPStatus: 429, Reason: ReasonTooManyRequests, Message: "query concurrency limit exceeded"})
		return
	}
	defer s.releaseQuerySlot("")
	ids, merr := s.authorizedWAFIdentities(r, user, groups)
	if merr != nil {
		WriteStatus(w, merr)
		return
	}
	scoped, err := ScopePromQLToWAFs(q, ids)
	if err != nil {
		WriteStatus(w, &MappedError{HTTPStatus: 400, Reason: "UnscopedQuery", Message: err.Error()})
		return
	}
	s.proxyMetrics(w, r, scoped)
}

func (s *Server) proxyMetrics(w http.ResponseWriter, r *http.Request, scoped string) {
	if s.query == nil {
		WriteStatus(w, &MappedError{HTTPStatus: 503, Reason: "NoMetricsBackend", Message: "metrics backend is not configured"})
		return
	}
	start := r.URL.Query().Get("start")
	end := r.URL.Query().Get("end")
	step := r.URL.Query().Get("step")
	var (
		body []byte
		ct   string
		merr *MappedError
	)
	if start != "" || end != "" || step != "" {
		if start == "" || end == "" || step == "" {
			WriteStatus(w, &MappedError{HTTPStatus: 400, Reason: ReasonBadRequest, Message: "query_range requires start, end, and step"})
			return
		}
		if err := validateQueryRange(start, end, step); err != nil {
			WriteStatus(w, &MappedError{HTTPStatus: 400, Reason: ReasonBadRequest, Message: err.Error()})
			return
		}
		body, ct, merr = s.query.rangeQuery(r.Context(), scoped, start, end, step)
	} else {
		body, ct, merr = s.query.instantQuery(r.Context(), scoped)
	}
	if merr != nil {
		WriteStatus(w, merr)
		return
	}
	writeRaw(w, ct, body)
}

func (s *Server) authorizedWAFIdentities(r *http.Request, user string, groups []string) ([]WAFIdentity, *MappedError) {
	if s.client == nil {
		return nil, &MappedError{HTTPStatus: 503, Reason: ReasonInternalError, Message: "kube client not configured"}
	}
	var list wafv1beta1.WAFList
	if err := s.client.List(r.Context(), &list); err != nil {
		return nil, &MappedError{HTTPStatus: 503, Reason: ReasonInternalError, Message: "failed to list WAFs"}
	}
	ids := make([]WAFIdentity, 0, len(list.Items))
	for i := range list.Items {
		waf := &list.Items[i]
		if merr := s.sar.CanGetParent(r.Context(), user, groups, ParentWAF, waf.Namespace, waf.Name); merr != nil {
			if merr.HTTPStatus >= 500 {
				return nil, merr
			}
			continue
		}
		ids = append(ids, WAFIdentity{Namespace: waf.Namespace, Name: waf.Name})
	}
	return ids, nil
}

func scopedTraceTags(raw, ns, name string) (map[string]string, error) {
	if strings.TrimSpace(raw) == "" {
		return map[string]string{"waf.namespace": ns, "waf.name": name}, nil
	}
	var tags map[string]string
	if err := json.Unmarshal([]byte(raw), &tags); err != nil {
		return nil, err
	}
	if v, ok := tags["waf.namespace"]; ok && v != ns {
		return nil, errUnscoped("waf.namespace")
	}
	if v, ok := tags["waf.name"]; ok && v != name {
		return nil, errUnscoped("waf.name")
	}
	if v, ok := tags["waf_namespace"]; ok && v != ns {
		return nil, errUnscoped("waf_namespace")
	}
	if v, ok := tags["waf_name"]; ok && v != name {
		return nil, errUnscoped("waf_name")
	}
	return map[string]string{"waf.namespace": ns, "waf.name": name}, nil
}

func errUnscoped(field string) error {
	return &PathError{Reason: "UnscopedQuery", Message: field + " escapes authorized WAF scope"}
}

func parseTraceWindow(r *http.Request) (startUs, endUs int64, limit int) {
	limit = defaultTraceLimit
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	if limit > maxTraceLimit {
		limit = maxTraceLimit
	}
	nowUs := time.Now().UnixMicro()
	endUs = nowUs
	if v := r.URL.Query().Get("end"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			endUs = n
		}
	}
	startUs = endUs - defaultTraceLookback.Microseconds()
	if v := r.URL.Query().Get("start"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			startUs = n
		}
	}
	if endUs-startUs > maxTraceLookback.Microseconds() {
		startUs = endUs - maxTraceLookback.Microseconds()
	}
	if startUs < 0 {
		startUs = 0
	}
	return startUs, endUs, limit
}

func (s *Server) acquireQuerySlot(ns string) bool {
	select {
	case s.queryGlobalSem <- struct{}{}:
	default:
		return false
	}
	if ns == "" {
		return true
	}
	if s.acquireQueryNS(ns) == nil {
		<-s.queryGlobalSem
		return false
	}
	return true
}

func (s *Server) releaseQuerySlot(ns string) {
	if ns != "" {
		s.nsMu.Lock()
		sem := s.queryNSSem[ns]
		s.nsMu.Unlock()
		if sem != nil {
			s.releaseNS(ns, sem)
		}
	}
	select {
	case <-s.queryGlobalSem:
	default:
	}
}

func validateQueryRange(start, end, step string) error {
	st, err1 := strconv.ParseFloat(start, 64)
	en, err2 := strconv.ParseFloat(end, 64)
	if err1 != nil || err2 != nil || en <= st {
		return fmt.Errorf("invalid start/end")
	}
	if en-st > float64(maxQueryRangeSec) {
		return fmt.Errorf("query_range window exceeds 24h")
	}
	stepSec := parseStepSeconds(step)
	if stepSec < minQueryStepSec {
		return fmt.Errorf("step must be at least %ds", minQueryStepSec)
	}
	if (en-st)/stepSec > float64(maxQueryPoints) {
		return fmt.Errorf("query_range exceeds %d points", maxQueryPoints)
	}
	return nil
}

func parseStepSeconds(step string) float64 {
	step = strings.TrimSpace(step)
	if n, err := strconv.ParseFloat(step, 64); err == nil && n > 0 {
		return n
	}
	if len(step) < 2 {
		return 0
	}
	unit := step[len(step)-1]
	n, err := strconv.ParseFloat(step[:len(step)-1], 64)
	if err != nil || n <= 0 {
		return 0
	}
	switch unit {
	case 's':
		return n
	case 'm':
		return n * 60
	case 'h':
		return n * 3600
	default:
		return 0
	}
}

type jaegerTag struct {
	Key   string `json:"key"`
	Value any    `json:"value"`
}

func filterJaegerToWAF(body []byte, ns, name string) ([]byte, bool) {
	// Preserve unknown envelope fields (errors, limit, …) by rewriting only "data".
	var root map[string]json.RawMessage
	if err := json.Unmarshal(body, &root); err != nil {
		return []byte(`{"data":[]}`), false
	}
	dataRaw, ok := root["data"]
	if !ok || len(dataRaw) == 0 || string(dataRaw) == "null" {
		return []byte(`{"data":[]}`), false
	}
	var traces []json.RawMessage
	if err := json.Unmarshal(dataRaw, &traces); err != nil {
		return []byte(`{"data":[]}`), false
	}
	kept := make([]json.RawMessage, 0, len(traces))
	for _, tr := range traces {
		if ft, ok := filterTraceRaw(tr, ns, name); ok {
			kept = append(kept, ft)
		}
	}
	keptBytes, err := json.Marshal(kept)
	if err != nil {
		return []byte(`{"data":[]}`), false
	}
	root["data"] = keptBytes
	out, err := json.Marshal(root)
	if err != nil {
		return []byte(`{"data":[]}`), false
	}
	return out, len(kept) > 0
}

func filterTraceRaw(tr json.RawMessage, ns, name string) (json.RawMessage, bool) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(tr, &fields); err != nil {
		return nil, false
	}
	var procs map[string]json.RawMessage
	if raw, ok := fields["processes"]; ok && len(raw) > 0 && string(raw) != "null" {
		_ = json.Unmarshal(raw, &procs)
	}
	keepProc := map[string]bool{}
	for id, p := range procs {
		if processRawMatchesWAF(p, ns, name) {
			keepProc[id] = true
		}
	}
	var spans []json.RawMessage
	if raw, ok := fields["spans"]; ok && len(raw) > 0 && string(raw) != "null" {
		_ = json.Unmarshal(raw, &spans)
	}
	keptSpans := make([]json.RawMessage, 0, len(spans))
	used := map[string]bool{}
	for _, sp := range spans {
		pid := spanProcessID(sp)
		if keepProc[pid] || spanRawMatchesWAF(sp, ns, name) {
			// Keep original span bytes so startTime/operationName/references survive.
			keptSpans = append(keptSpans, sp)
			if pid != "" {
				used[pid] = true
			}
		}
	}
	if len(keptSpans) == 0 {
		return nil, false
	}
	newProcs := map[string]json.RawMessage{}
	for id, p := range procs {
		if used[id] && keepProc[id] {
			newProcs[id] = p
		}
	}
	sb, err := json.Marshal(keptSpans)
	if err != nil {
		return nil, false
	}
	pb, err := json.Marshal(newProcs)
	if err != nil {
		return nil, false
	}
	fields["spans"] = sb
	fields["processes"] = pb
	out, err := json.Marshal(fields)
	if err != nil {
		return nil, false
	}
	return out, true
}

func spanProcessID(sp json.RawMessage) string {
	var tmp struct {
		ProcessID string `json:"processID"`
	}
	_ = json.Unmarshal(sp, &tmp)
	return tmp.ProcessID
}

func processRawMatchesWAF(p json.RawMessage, ns, name string) bool {
	var tmp struct {
		Tags []jaegerTag `json:"tags"`
	}
	if err := json.Unmarshal(p, &tmp); err != nil {
		return false
	}
	gotNS, gotName := identityFromTags(tmp.Tags)
	return gotNS == ns && gotName == name
}

func spanRawMatchesWAF(sp json.RawMessage, ns, name string) bool {
	var tmp struct {
		Tags []jaegerTag `json:"tags"`
	}
	if err := json.Unmarshal(sp, &tmp); err != nil {
		return false
	}
	gotNS, gotName := identityFromTags(tmp.Tags)
	return gotNS == ns && gotName == name
}

func identityFromTags(tags []jaegerTag) (ns, name string) {
	for _, t := range tags {
		v := tagString(t.Value)
		switch t.Key {
		case "waf.namespace", "waf_namespace":
			ns = v
		case "waf.name", "waf_name":
			name = v
		}
	}
	return ns, name
}

func tagString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case fmt.Stringer:
		return t.String()
	default:
		return fmt.Sprint(v)
	}
}

func writeRaw(w http.ResponseWriter, contentType string, body []byte) {
	if contentType == "" {
		contentType = "application/json"
	}
	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}
