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

// Package probetest implements go-coraza load/process/unload for probe evaluation.
// Used by cmd/probe-test-server; no kube client (K7d).
package probetest

import (
	"context"
	"fmt"
	"io/fs"
	"strings"
	"testing/fstest"
	"time"

	"github.com/corazawaf/coraza/v3"
	ctypes "github.com/corazawaf/coraza/v3/types"

	"github.com/kubewaf-io/kubewaf/internal/probetest/api"
)

const (
	// EngineName is the probe evaluation engine label.
	EngineName = "coraza-go"
	// EngineVersion is the pinned go-coraza module version.
	EngineVersion = "coraza/v3.7.0"

	defaultMaxMatches     = 50
	maxMaxMatches         = 500
	defaultTimeoutSeconds = 5
	maxTimeoutSeconds     = 30
	maxDirectivesBytes    = 2 * 1024 * 1024
	maxDataFilesBytes     = 2 * 1024 * 1024
	maxBodyBytes          = 1 * 1024 * 1024

	msgEvalTimeout = "eval timeout"
)

// LoadSeclangWithFS creates a Coraza WAF from directives and optional root FS.
// This is the Test HTTP Server load path — not internal/coraza validation.
func LoadSeclangWithFS(directives string, root fs.FS) (coraza.WAF, error) {
	if strings.TrimSpace(directives) == "" {
		return nil, fmt.Errorf("empty directives")
	}
	cfg := coraza.NewWAFConfig().WithDirectives(directives)
	if root != nil {
		cfg = cfg.WithRootFS(root)
	}
	return coraza.NewWAF(cfg)
}

// MapFSFrom builds an fstest.MapFS from basename → body.
func MapFSFrom(files map[string][]byte) fs.FS {
	if len(files) == 0 {
		return nil
	}
	m := make(fstest.MapFS, len(files))
	for k, v := range files {
		// copy to avoid mutation
		body := make([]byte, len(v))
		copy(body, v)
		m[k] = &fstest.MapFile{Data: body}
	}
	return m
}

// Evaluate runs a full request/response pipeline against go-coraza and unloads.
func Evaluate(ctx context.Context, req *api.EvalRequest) (*api.EvalResponse, error) {
	if req == nil {
		return nil, &EvalError{Class: api.ErrClassInvalidRequest, Message: "nil request", HTTPStatus: 400}
	}
	if err := validateEvalRequest(req); err != nil {
		return nil, err
	}

	timeout := req.Options.TimeoutSeconds
	if timeout <= 0 {
		timeout = defaultTimeoutSeconds
	}
	if timeout > maxTimeoutSeconds {
		timeout = maxTimeoutSeconds
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
	defer cancel()

	start := time.Now()

	// Check context before expensive compile.
	if err := ctx.Err(); err != nil {
		return nil, &EvalError{Class: api.ErrClassTimeout, Message: msgEvalTimeout, HTTPStatus: 504}
	}

	waf, err := LoadSeclangWithFS(req.Directives, MapFSFrom(req.DataFiles))
	if err != nil {
		return nil, &EvalError{Class: api.ErrClassCompileFailed, Message: "compile failed", HTTPStatus: 500}
	}

	tx := waf.NewTransaction()
	defer func() { _ = tx.Close() }()

	// Honor cancel between phases (best-effort; coraza is not fully cancelable mid-phase).
	if err := ctx.Err(); err != nil {
		return nil, &EvalError{Class: api.ErrClassTimeout, Message: msgEvalTimeout, HTTPStatus: 504}
	}

	processConnectionAndURI(tx, req)

	interruption, err := processRequestPhases(tx, req)
	if err != nil {
		return nil, err
	}
	interruption = processSyntheticResponse(tx, interruption)
	tx.ProcessLogging()

	if err := ctx.Err(); err != nil {
		return nil, &EvalError{Class: api.ErrClassTimeout, Message: msgEvalTimeout, HTTPStatus: 504}
	}

	maxMatches := req.Options.MaxMatches
	if maxMatches <= 0 {
		maxMatches = defaultMaxMatches
	}
	if maxMatches > maxMaxMatches {
		maxMatches = maxMaxMatches
	}

	resp := &api.EvalResponse{
		Engine:        EngineName,
		EngineVersion: EngineVersion,
		RulesLoaded:   countSecRuleLines(req.Directives),
		Matches:       mapMatches(tx.MatchedRules(), maxMatches),
		DurationMs:    time.Since(start).Milliseconds(),
		HTTP:          mapHTTPView(interruption),
	}
	if interruption != nil {
		resp.Interruption = &api.EvalInterrupt{
			Disrupted: true,
			Action:    interruption.Action,
			Status:    interruption.Status,
			RuleID:    interruption.RuleID,
		}
	} else {
		resp.Interruption = &api.EvalInterrupt{Disrupted: false, Action: "pass"}
	}
	return resp, nil
}

func processConnectionAndURI(tx ctypes.Transaction, req *api.EvalRequest) {
	clientIP := req.Request.RemoteAddr
	if clientIP == "" {
		clientIP = "0.0.0.0"
	}
	serverIP := req.Request.ServerAddr
	if serverIP == "" {
		serverIP = "0.0.0.0"
	}
	serverPort := req.Request.ServerPort
	if serverPort <= 0 {
		serverPort = 80
	}
	tx.ProcessConnection(clientIP, req.Request.ClientPort, serverIP, serverPort)

	uri := req.Request.Path
	if uri == "" {
		uri = "/"
	}
	if req.Request.RawQuery != "" {
		uri = uri + "?" + req.Request.RawQuery
	}
	method := req.Request.Method
	if method == "" {
		method = "GET"
	}
	tx.ProcessURI(uri, method, "HTTP/1.1")
	for k, v := range req.Request.Headers {
		tx.AddRequestHeader(k, v)
	}
	if _, ok := headerLookup(req.Request.Headers, "Host"); !ok {
		tx.AddRequestHeader("Host", "localhost")
	}
}

func processRequestPhases(tx ctypes.Transaction, req *api.EvalRequest) (*ctypes.Interruption, error) {
	var interruption *ctypes.Interruption
	if it := tx.ProcessRequestHeaders(); it != nil {
		return it, nil
	}
	if len(req.Request.Body) > 0 {
		it, _, werr := tx.WriteRequestBody(req.Request.Body)
		if werr != nil {
			return nil, &EvalError{Class: api.ErrClassInternal, Message: "request body write failed", HTTPStatus: 500}
		}
		if it != nil {
			return it, nil
		}
	}
	it, berr := tx.ProcessRequestBody()
	if berr != nil {
		return nil, &EvalError{Class: api.ErrClassInternal, Message: "request body process failed", HTTPStatus: 500}
	}
	if it != nil {
		interruption = it
	}
	return interruption, nil
}

func processSyntheticResponse(tx ctypes.Transaction, interruption *ctypes.Interruption) *ctypes.Interruption {
	if interruption != nil {
		return interruption
	}
	tx.AddResponseHeader("Content-Type", "text/plain")
	if it := tx.ProcessResponseHeaders(200, "HTTP/1.1"); it != nil {
		return it
	}
	if it, _, werr := tx.WriteResponseBody([]byte("")); werr == nil && it != nil {
		return it
	}
	if it, berr := tx.ProcessResponseBody(); berr == nil && it != nil {
		return it
	}
	return interruption
}

// EvalError is a classified evaluation error for HTTP mapping.
type EvalError struct {
	Class      string
	Message    string
	HTTPStatus int
}

func (e *EvalError) Error() string {
	if e.Message != "" {
		return e.Message
	}
	return e.Class
}

func validateEvalRequest(req *api.EvalRequest) *EvalError {
	if strings.TrimSpace(req.Directives) == "" {
		return &EvalError{Class: api.ErrClassInvalidRequest, Message: "directives required", HTTPStatus: 400}
	}
	if len(req.Directives) > maxDirectivesBytes {
		return &EvalError{Class: api.ErrClassTooLarge, Message: "directives too large", HTTPStatus: 413}
	}
	var dataSize int
	for _, v := range req.DataFiles {
		dataSize += len(v)
	}
	if dataSize > maxDataFilesBytes {
		return &EvalError{Class: api.ErrClassTooLarge, Message: "dataFiles too large", HTTPStatus: 413}
	}
	if len(req.Request.Body) > maxBodyBytes {
		return &EvalError{Class: api.ErrClassTooLarge, Message: "body too large", HTTPStatus: 413}
	}
	if req.Request.Method == "" {
		return &EvalError{Class: api.ErrClassInvalidRequest, Message: "method required", HTTPStatus: 400}
	}
	return nil
}

func mapMatches(rules []ctypes.MatchedRule, max int) []api.EvalMatch {
	if len(rules) == 0 {
		return nil
	}
	out := make([]api.EvalMatch, 0, min(len(rules), max))
	for _, mr := range rules {
		if len(out) >= max {
			break
		}
		m := api.EvalMatch{
			Msg: mr.Message(),
		}
		if r := mr.Rule(); r != nil {
			m.RuleID = r.ID()
			m.Phase = int(r.Phase())
			m.Severity = r.Severity().String()
			m.Tags = append([]string(nil), r.Tags()...)
		}
		if datas := mr.MatchedDatas(); len(datas) > 0 {
			d := datas[0]
			m.MatchedData = truncate(d.Value(), 256)
			key := d.Key()
			if key != "" {
				m.Variable = d.Variable().Name() + ":" + key
			} else {
				m.Variable = d.Variable().Name()
			}
		}
		out = append(out, m)
	}
	return out
}

func mapHTTPView(it *ctypes.Interruption) api.EvalHTTPView {
	if it == nil {
		return api.EvalHTTPView{WouldStatus: 200}
	}
	action := strings.ToLower(it.Action)
	switch action {
	case "deny", "drop", "block":
		st := it.Status
		if st <= 0 {
			st = 403
		}
		return api.EvalHTTPView{WouldStatus: st, WouldBody: "Forbidden"}
	case "redirect":
		st := it.Status
		if st <= 0 {
			st = 302
		}
		return api.EvalHTTPView{WouldStatus: st}
	default:
		// Non-deny interrupt → 200 (or supplied status)
		if it.Status > 0 {
			return api.EvalHTTPView{WouldStatus: it.Status}
		}
		return api.EvalHTTPView{WouldStatus: 200}
	}
}

func countSecRuleLines(directives string) int {
	n := 0
	for _, line := range strings.Split(directives, "\n") {
		trim := strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToLower(trim), "secrule ") || strings.HasPrefix(strings.ToLower(trim), "secaction ") {
			n++
		}
	}
	return n
}

func headerLookup(h map[string]string, name string) (string, bool) {
	for k, v := range h {
		if strings.EqualFold(k, name) {
			return v, true
		}
	}
	return "", false
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
