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

package probetest

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kubewaf-io/kubewaf/internal/probeassemble"
	"github.com/kubewaf-io/kubewaf/internal/probetest/api"
)

func TestEvaluateSimpleDenyRule(t *testing.T) {
	// Preamble + rule that denies when ARGS contains "attack"
	rule := `SecRule ARGS "@rx attack" "id:100001,phase:2,deny,status:403,msg:'blocked'"`
	doc := probeassemble.JoinDocument(probeassemble.Preamble(), []string{rule})

	req := &api.EvalRequest{
		Directives: doc,
		Request: api.EvalHTTPRequest{
			Method:   "GET",
			Path:     "/search",
			RawQuery: "q=attack",
			Headers:  map[string]string{"User-Agent": "test"},
		},
		Options: api.EvalOptions{MaxMatches: 50, TimeoutSeconds: 5},
	}
	resp, err := Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("eval: %v", err)
	}
	if resp.Engine != EngineName {
		t.Fatalf("engine=%s", resp.Engine)
	}
	if resp.Interruption == nil || !resp.Interruption.Disrupted {
		t.Fatalf("expected disruption, got %+v matches=%+v", resp.Interruption, resp.Matches)
	}
	if resp.HTTP.WouldStatus != 403 {
		t.Fatalf("wouldStatus=%d", resp.HTTP.WouldStatus)
	}
	if resp.HTTP.WouldBody != "Forbidden" {
		t.Fatalf("wouldBody=%q", resp.HTTP.WouldBody)
	}
	if len(resp.Matches) == 0 {
		t.Fatal("expected matches")
	}
	found := false
	for _, m := range resp.Matches {
		if m.RuleID == 100001 {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected rule 100001 in matches: %+v", resp.Matches)
	}
}

func TestEvaluatePassNoMatch(t *testing.T) {
	rule := `SecRule ARGS "@rx attack" "id:100001,phase:2,deny,status:403"`
	doc := probeassemble.JoinDocument(probeassemble.Preamble(), []string{rule})
	req := &api.EvalRequest{
		Directives: doc,
		Request: api.EvalHTTPRequest{
			Method:   "GET",
			Path:     "/search",
			RawQuery: "q=hello",
		},
	}
	resp, err := Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("eval: %v", err)
	}
	if resp.Interruption != nil && resp.Interruption.Disrupted {
		t.Fatalf("unexpected disruption: %+v", resp.Interruption)
	}
	if resp.HTTP.WouldStatus != 200 {
		t.Fatalf("wouldStatus=%d", resp.HTTP.WouldStatus)
	}
}

func TestServerEvalAuthAndPipeline(t *testing.T) {
	token := "test-token-secret"
	srv := NewServer(ServerConfig{Token: token})
	h := srv.Handler()

	// healthz unauthenticated
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rr.Code != 200 {
		t.Fatalf("healthz %d", rr.Code)
	}

	// eval without token → 401
	rule := `SecRule ARGS "@rx attack" "id:100001,phase:2,deny,status:403"`
	doc := probeassemble.JoinDocument(probeassemble.Preamble(), []string{rule})
	body, _ := json.Marshal(&api.EvalRequest{
		Directives: doc,
		Request:    api.EvalHTTPRequest{Method: "GET", Path: "/", RawQuery: "q=attack"},
	})
	rr = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/eval", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(rr, req)
	if rr.Code != 401 {
		t.Fatalf("want 401 got %d", rr.Code)
	}

	// with token → 200
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/v1/eval", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	h.ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("want 200 got %d body=%s", rr.Code, rr.Body.String())
	}
	var er api.EvalResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &er); err != nil {
		t.Fatal(err)
	}
	if er.Interruption == nil || !er.Interruption.Disrupted {
		t.Fatalf("expected disrupt: %+v", er)
	}
}

func TestValidateEmptyDirectives(t *testing.T) {
	_, err := Evaluate(context.Background(), &api.EvalRequest{
		Request: api.EvalHTTPRequest{Method: "GET", Path: "/"},
	})
	if err == nil {
		t.Fatal("expected error")
	}
	ee, ok := err.(*EvalError)
	if !ok || ee.HTTPStatus != 400 {
		t.Fatalf("err=%v", err)
	}
}
