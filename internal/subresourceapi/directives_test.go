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
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	seclangv1beta1 "github.com/kubewaf-io/kubewaf/api/seclang/v1beta1"
	wafv1beta1 "github.com/kubewaf-io/kubewaf/api/waf/v1beta1"
)

func TestDirectivesJSONAndPlain(t *testing.T) {
	scheme := testScheme(t)
	waf := &wafv1beta1.WAF{
		TypeMeta:   metav1.TypeMeta{APIVersion: "waf.kubewaf.io/v1beta1", Kind: "WAF"},
		ObjectMeta: metav1.ObjectMeta{Name: "shop-waf", Namespace: "shop"},
		Spec:       wafv1beta1.WAFSpec{Mode: wafv1beta1.WAFModeBlocking},
	}
	waf.SetGroupVersionKind(wafv1beta1.GroupVersion.WithKind("WAF"))
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(waf).Build()
	s := NewServer(Config{Client: cl, Auth: AuthInsecureDev, SAR: AllowAllSAR{}, DisableProbes: true})
	h := s.Handler()

	req := httptest.NewRequest(http.MethodGet,
		"/apis/subresources.kubewaf.io/v1alpha1/namespaces/shop/wafs/shop-waf/directives", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("status %d body %s", rr.Code, rr.Body.String())
	}
	var body DirectivesResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Count == 0 || !strings.HasPrefix(body.ContentHash, "sha256:") {
		t.Fatalf("%+v", body)
	}
	joined := strings.Join(body.Directives, "\n")
	if !strings.Contains(joined, "Include @kubewaf-defaults") {
		t.Fatalf("directives=%v", body.Directives)
	}

	req = httptest.NewRequest(http.MethodGet,
		"/apis/subresources.kubewaf.io/v1alpha1/namespaces/shop/wafs/shop-waf/directives", nil)
	req.Header.Set("Accept", "text/plain")
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), "SecRuleEngine") {
		t.Fatalf("plain %d %s", rr.Code, rr.Body.String())
	}
}

func TestDirectivesFailClosedAndIgnoreUnknown(t *testing.T) {
	scheme := testScheme(t)
	sr := denySecRule("pmf", "shop", 100010, "x")
	sr.Spec.Match = []seclangv1beta1.Match{{
		Collections: []seclangv1beta1.Collection{{Name: seclangv1beta1.ARGS}},
		Operator:    seclangv1beta1.Operator{Name: seclangv1beta1.PmFromFile, Value: "missing-custom.data"},
	}}
	rs := &wafv1beta1.RuleSet{
		TypeMeta:   metav1.TypeMeta{APIVersion: "waf.kubewaf.io/v1beta1", Kind: "RuleSet"},
		ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "shop"},
		Spec:       wafv1beta1.RuleSetSpec{RuleRefs: []wafv1beta1.RuleRef{{Kind: "SecRule", Name: "pmf"}}},
	}
	rs.SetGroupVersionKind(wafv1beta1.GroupVersion.WithKind("RuleSet"))
	waf := &wafv1beta1.WAF{
		TypeMeta:   metav1.TypeMeta{APIVersion: "waf.kubewaf.io/v1beta1", Kind: "WAF"},
		ObjectMeta: metav1.ObjectMeta{Name: "shop-waf", Namespace: "shop"},
		Spec: wafv1beta1.WAFSpec{
			RuleSetRefs:      []wafv1beta1.RuleRef{{Kind: "RuleSet", Name: "app"}},
			PhraseListPolicy: wafv1beta1.PhraseListPolicyFailClosed,
		},
	}
	waf.SetGroupVersionKind(wafv1beta1.GroupVersion.WithKind("WAF"))
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(sr, rs, waf).Build()
	s := NewServer(Config{Client: cl, Auth: AuthInsecureDev, SAR: AllowAllSAR{}})
	req := httptest.NewRequest(http.MethodGet,
		"/apis/subresources.kubewaf.io/v1alpha1/namespaces/shop/wafs/shop-waf/directives", nil)
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != 422 || !strings.Contains(rr.Body.String(), "PhraseFilesFailed") {
		t.Fatalf("failclosed %d %s", rr.Code, rr.Body.String())
	}

	waf.Spec.PhraseListPolicy = wafv1beta1.PhraseListPolicyIgnoreUnknown
	if err := cl.Update(context.Background(), waf); err != nil {
		t.Fatal(err)
	}
	req = httptest.NewRequest(http.MethodGet,
		"/apis/subresources.kubewaf.io/v1alpha1/namespaces/shop/wafs/shop-waf/directives", nil)
	rr = httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("ignore %d %s", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), "missing-custom.data") {
		t.Fatalf("dropped basename still present: %s", rr.Body.String())
	}
}

func TestDirectivesChallengeWithoutSecret(t *testing.T) {
	scheme := testScheme(t)
	en := true
	waf := &wafv1beta1.WAF{
		TypeMeta:   metav1.TypeMeta{APIVersion: "waf.kubewaf.io/v1beta1", Kind: "WAF"},
		ObjectMeta: metav1.ObjectMeta{Name: "shop-waf", Namespace: "shop"},
		Spec: wafv1beta1.WAFSpec{
			Challenge: &wafv1beta1.ChallengeSpec{Enabled: &en},
		},
	}
	waf.SetGroupVersionKind(wafv1beta1.GroupVersion.WithKind("WAF"))
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(waf).Build()
	s := NewServer(Config{Client: cl, Auth: AuthInsecureDev, SAR: AllowAllSAR{}})
	req := httptest.NewRequest(http.MethodGet,
		"/apis/subresources.kubewaf.io/v1alpha1/namespaces/shop/wafs/shop-waf/directives", nil)
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), "Include @kubewaf-defaults") {
		t.Fatalf("challenge no secret %d %s", rr.Code, rr.Body.String())
	}
}

func TestDirectivesDisabledAndTooLargeAndSAR(t *testing.T) {
	scheme := testScheme(t)
	waf := &wafv1beta1.WAF{
		TypeMeta:   metav1.TypeMeta{APIVersion: "waf.kubewaf.io/v1beta1", Kind: "WAF"},
		ObjectMeta: metav1.ObjectMeta{Name: "shop-waf", Namespace: "shop"},
	}
	waf.SetGroupVersionKind(wafv1beta1.GroupVersion.WithKind("WAF"))
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(waf).Build()
	s := NewServer(Config{Client: cl, Auth: AuthInsecureDev, SAR: AllowAllSAR{}, DisableDirectives: true})
	req := httptest.NewRequest(http.MethodGet,
		"/apis/subresources.kubewaf.io/v1alpha1/namespaces/shop/wafs/shop-waf/directives", nil)
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != 404 {
		t.Fatalf("disabled %d", rr.Code)
	}

	old := maxDirectivesBytes
	maxDirectivesBytes = 8
	defer func() { maxDirectivesBytes = old }()
	s = NewServer(Config{Client: cl, Auth: AuthInsecureDev, SAR: AllowAllSAR{}})
	req = httptest.NewRequest(http.MethodGet,
		"/apis/subresources.kubewaf.io/v1alpha1/namespaces/shop/wafs/shop-waf/directives", nil)
	rr = httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != 413 {
		t.Fatalf("too large %d %s", rr.Code, rr.Body.String())
	}

	s = NewServer(Config{Client: cl, Auth: AuthInsecureDev, SAR: DenyAllSAR{}})
	req = httptest.NewRequest(http.MethodGet,
		"/apis/subresources.kubewaf.io/v1alpha1/namespaces/shop/wafs/shop-waf/directives", nil)
	rr = httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != 403 {
		t.Fatalf("sar %d %s", rr.Code, rr.Body.String())
	}
}

func TestDirectivesMissingWAF(t *testing.T) {
	scheme := testScheme(t)
	cl := fake.NewClientBuilder().WithScheme(scheme).Build()
	s := NewServer(Config{Client: cl, Auth: AuthInsecureDev, SAR: AllowAllSAR{}})
	req := httptest.NewRequest(http.MethodGet,
		"/apis/subresources.kubewaf.io/v1alpha1/namespaces/shop/wafs/missing/directives", nil)
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != 404 {
		t.Fatalf("status %d", rr.Code)
	}
}
