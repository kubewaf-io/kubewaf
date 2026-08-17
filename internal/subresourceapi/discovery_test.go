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
	"net/http"
	"net/http/httptest"
	"testing"

	subv1alpha1 "github.com/kubewaf-io/kubewaf/api/subresources/v1alpha1"
)

func TestDiscoveryDocuments(t *testing.T) {
	g := APIGroupDocument()
	if g.Name != subv1alpha1.Group {
		t.Fatalf("group name %q", g.Name)
	}
	if g.PreferredVersion.Version != subv1alpha1.Version {
		t.Fatalf("preferred version %q", g.PreferredVersion.Version)
	}

	list := APIResourceListDocument()
	if list.GroupVersion != subv1alpha1.Group+"/"+subv1alpha1.Version {
		t.Fatalf("gv %q", list.GroupVersion)
	}
	byName := map[string]bool{}
	for _, r := range list.APIResources {
		byName[r.Name] = true
		if r.Name == subv1alpha1.ResourceSecRuleProbes ||
			r.Name == subv1alpha1.ResourceRuleSetProbes ||
			r.Name == subv1alpha1.ResourceWAFProbes {
			if r.Kind != "Probe" {
				t.Errorf("%s kind=%s", r.Name, r.Kind)
			}
			if len(r.Verbs) != len(ProbeSubresourceVerbs) {
				t.Errorf("%s verbs=%v want len %d", r.Name, r.Verbs, len(ProbeSubresourceVerbs))
			}
			for i, v := range ProbeSubresourceVerbs {
				if i >= len(r.Verbs) || r.Verbs[i] != v {
					t.Errorf("%s verbs=%v want exact %v", r.Name, r.Verbs, ProbeSubresourceVerbs)
					break
				}
			}
		}
		if r.Name == subv1alpha1.ResourceWAFDirectives ||
			r.Name == subv1alpha1.ResourceWAFMetrics ||
			r.Name == subv1alpha1.ResourceWAFTraces ||
			r.Name == subv1alpha1.ResourceClusterMetrics {
			if r.SingularName != "" {
				t.Errorf("%s must have empty SingularName", r.Name)
			}
			if len(r.Verbs) != 1 || r.Verbs[0] != "get" {
				t.Errorf("%s verbs=%v", r.Name, r.Verbs)
			}
		}
		if r.Name == subv1alpha1.ResourceSecRules ||
			r.Name == subv1alpha1.ResourceRuleSets ||
			r.Name == subv1alpha1.ResourceWAFs {
			if len(r.Verbs) != 0 {
				t.Errorf("parent %s should have empty verbs, got %v", r.Name, r.Verbs)
			}
			// Must not claim singular/short names that CRDs own (kubectl preference).
			if r.SingularName != "" {
				t.Errorf("parent %s must have empty SingularName, got %q", r.Name, r.SingularName)
			}
			if len(r.ShortNames) != 0 {
				t.Errorf("parent %s must have no ShortNames, got %v", r.Name, r.ShortNames)
			}
		}
	}
	for _, n := range []string{
		subv1alpha1.ResourceSecRules,
		subv1alpha1.ResourceSecRuleProbes,
		subv1alpha1.ResourceRuleSets,
		subv1alpha1.ResourceRuleSetProbes,
		subv1alpha1.ResourceWAFs,
		subv1alpha1.ResourceWAFProbes,
		subv1alpha1.ResourceWAFDirectives,
		subv1alpha1.ResourceWAFMetrics,
		subv1alpha1.ResourceWAFTraces,
		subv1alpha1.ResourceClusterMetrics,
	} {
		if !byName[n] {
			t.Errorf("missing resource %s", n)
		}
	}
	// secactions/probes must be omitted in v1
	if byName["secactions/probes"] {
		t.Error("secactions/probes should not be registered in v1")
	}
}

func TestDiscoveryHTTP(t *testing.T) {
	s := NewServer(Config{
		Auth:       AuthInsecureDev,
		EvalClient: &StubEvalClient{},
	})
	h := s.Handler()

	t.Run("group", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/apis/subresources.kubewaf.io", nil)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != 200 {
			t.Fatalf("status %d body %s", rr.Code, rr.Body.String())
		}
		var doc map[string]any
		if err := json.Unmarshal(rr.Body.Bytes(), &doc); err != nil {
			t.Fatal(err)
		}
		if doc["kind"] != "APIGroup" {
			t.Fatalf("kind=%v", doc["kind"])
		}
	})
	t.Run("version", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/apis/subresources.kubewaf.io/v1alpha1", nil)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != 200 {
			t.Fatalf("status %d", rr.Code)
		}
		var doc map[string]any
		if err := json.Unmarshal(rr.Body.Bytes(), &doc); err != nil {
			t.Fatal(err)
		}
		if doc["kind"] != "APIResourceList" {
			t.Fatalf("kind=%v", doc["kind"])
		}
	})
	t.Run("openapi", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/openapi/v2", nil)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != 200 {
			t.Fatalf("status %d", rr.Code)
		}
	})
	t.Run("probe stub", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet,
			"/apis/subresources.kubewaf.io/v1alpha1/namespaces/shop/secrules/rule-1/probes/http/search?q=1",
			nil)
		req.Header.Set("User-Agent", "evil")
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != 200 {
			t.Fatalf("status %d body %s", rr.Code, rr.Body.String())
		}
		var probe map[string]any
		if err := json.Unmarshal(rr.Body.Bytes(), &probe); err != nil {
			t.Fatal(err)
		}
		if probe["kind"] != "Probe" {
			t.Fatalf("kind=%v", probe["kind"])
		}
		status, _ := probe["status"].(map[string]any)
		if status["phase"] != "Complete" {
			t.Fatalf("phase=%v", status["phase"])
		}
		// EngineParity condition must be present
		conds, _ := status["conditions"].([]any)
		found := false
		for _, c := range conds {
			cm, _ := c.(map[string]any)
			if cm["type"] == "EngineParity" {
				found = true
				if cm["status"] != "False" || cm["reason"] != "CorazaNotModSecurity" {
					t.Fatalf("EngineParity=%v", cm)
				}
			}
		}
		if !found {
			t.Fatal("EngineParity condition missing")
		}
	})
}
