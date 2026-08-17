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
	"net/http"
	"testing"
)

func TestParseProbePath(t *testing.T) {
	const base = "/apis/subresources.kubewaf.io/v1alpha1/namespaces/shop/secrules/rule-1/probes"

	tests := []struct {
		name     string
		path     string
		query    string
		wantPath string
		wantQ    string
		wantErr  bool
		reason   string
	}{
		{"bare probes", base, "", "/", "", false, ""},
		{"bare with query", base, "q=1", "/", "q=1", false, ""},
		{"http only", base + "/http", "", "/", "", false, ""},
		{"http search", base + "/http/search", "q=1", "/search", "q=1", false, ""},
		{"http nested", base + "/http/api/v1/login", "x=1", "/api/v1/login", "x=1", false, ""},
		{"http trailing slash", base + "/http/search/", "", "/search/", "", false, ""},
		{"not-http", base + "/not-http/evil", "", "", "", true, "NotFound"},
		{"empty app segment", base + "/http//x", "", "", "", true, "InvalidProbePath"},
		// Namespace named secactions must not be treated as SecAction parent resource.
		{"ns named secactions", "/apis/subresources.kubewaf.io/v1alpha1/namespaces/secactions/secrules/r1/probes", "", "/", "", false, ""},
		{"ruleset", "/apis/subresources.kubewaf.io/v1alpha1/namespaces/ns/rulesets/rs1/probes", "", "/", "", false, ""},
		{"waf", "/apis/subresources.kubewaf.io/v1alpha1/namespaces/ns/wafs/w1/probes/http/a", "", "/a", "", false, ""},
		{"secaction deferred", "/apis/subresources.kubewaf.io/v1alpha1/namespaces/ns/secactions/a1/probes", "", "", "", true, "SecActionProbesDeferred"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := ParseProbePath(tt.path, tt.query)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				if pe, ok := err.(*PathError); ok && tt.reason != "" && pe.Reason != tt.reason {
					t.Fatalf("reason=%s want %s", pe.Reason, tt.reason)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if r.AppPath != tt.wantPath {
				t.Fatalf("path=%q want %q", r.AppPath, tt.wantPath)
			}
			if r.RawQuery != tt.wantQ {
				t.Fatalf("query=%q want %q", r.RawQuery, tt.wantQ)
			}
			if r.Namespace == "" || r.Name == "" {
				t.Fatalf("missing ns/name: %+v", r)
			}
		})
	}
}

func TestHeaderDenylist(t *testing.T) {
	denied := []string{
		"Authorization",
		"Cookie",
		"X-Remote-User",
		"X-Remote-Group",
		"X-Remote-Extra-foo",
		"Connection",
		"Keep-Alive",
		"Transfer-Encoding",
		"TE",
		"Trailer",
		"Upgrade",
		"Proxy-Authorization",
		"Proxy-Authenticate",
		"X-KubeWAF-Probe-TimeoutSeconds",
		"X-KubeWAF-Probe-Mode",
		"X-KubeWAF-Probe-Trace-Id",
	}
	for _, h := range denied {
		if !IsDeniedHeader(h) {
			t.Errorf("expected denied: %s", h)
		}
	}
	allowed := []string{"User-Agent", "Content-Type", "X-Forwarded-For", "X-Custom-App"}
	for _, h := range allowed {
		if IsDeniedHeader(h) {
			t.Errorf("expected allowed: %s", h)
		}
	}

	hdr := http.Header{}
	hdr.Set("Authorization", "Bearer secret")
	hdr.Set("Cookie", "session=1")
	hdr.Set("User-Agent", "evil-scanner")
	hdr.Set("Content-Type", "application/json")
	hdr.Set("X-KubeWAF-Probe-Mode", "Blocking")
	hdr.Set("X-Remote-User", "alice")
	got := FilterAppHeaders(hdr)
	if _, ok := got["Authorization"]; ok {
		t.Error("Authorization should be stripped")
	}
	if _, ok := got["Cookie"]; ok {
		t.Error("Cookie should be stripped")
	}
	if _, ok := got["X-KubeWAF-Probe-Mode"]; ok {
		t.Error("control header should be stripped")
	}
	if _, ok := got["X-Remote-User"]; ok {
		t.Error("X-Remote-User should be stripped")
	}
	if got["User-Agent"] != "evil-scanner" {
		t.Errorf("User-Agent=%q", got["User-Agent"])
	}
	if got["Content-Type"] != "application/json" {
		t.Errorf("Content-Type=%q", got["Content-Type"])
	}
}

func TestMethodToRBACVerb(t *testing.T) {
	cases := map[string]string{
		http.MethodGet:    "get",
		http.MethodHead:   "get",
		http.MethodPost:   "create",
		http.MethodPut:    "update",
		http.MethodPatch:  "patch",
		http.MethodDelete: "delete",
	}
	for m, v := range cases {
		if got := MethodToRBACVerb(m); got != v {
			t.Errorf("%s -> %s want %s", m, got, v)
		}
	}
}
