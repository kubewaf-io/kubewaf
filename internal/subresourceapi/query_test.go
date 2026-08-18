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
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	wafv1beta1 "github.com/kubewaf-io/kubewaf/api/waf/v1beta1"
)

func TestWAFMetricsScopesQuery(t *testing.T) {
	var gotQuery string
	vm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.Query().Get("query")
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"status":"success","data":{"resultType":"vector","result":[]}}`)
	}))
	defer vm.Close()

	scheme := testScheme(t)
	waf := &wafv1beta1.WAF{
		TypeMeta:   metav1.TypeMeta{APIVersion: "waf.kubewaf.io/v1beta1", Kind: "WAF"},
		ObjectMeta: metav1.ObjectMeta{Name: "shop-waf", Namespace: "shop"},
	}
	waf.SetGroupVersionKind(wafv1beta1.GroupVersion.WithKind("WAF"))
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(waf).Build()
	s := NewServer(Config{
		Client: cl, Auth: AuthInsecureDev, SAR: AllowAllSAR{},
		Query: NewQueryBackend(vm.URL, ""),
	})
	req := httptest.NewRequest(http.MethodGet,
		"/apis/subresources.kubewaf.io/v1alpha1/namespaces/shop/wafs/shop-waf/metrics?query="+url.QueryEscape(`sum(up)`), nil)
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("status %d %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(gotQuery, `waf_namespace="shop"`) || !strings.Contains(gotQuery, `waf_name="shop-waf"`) {
		t.Fatalf("backend query not scoped: %s", gotQuery)
	}
}

func TestWAFMetricsRejectsForeignScope(t *testing.T) {
	vm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("backend should not be called")
	}))
	defer vm.Close()
	s := NewServer(Config{Auth: AuthInsecureDev, SAR: AllowAllSAR{}, Query: NewQueryBackend(vm.URL, "")})
	q := url.QueryEscape(`{waf_namespace="evil",waf_name="x"}`)
	req := httptest.NewRequest(http.MethodGet,
		"/apis/subresources.kubewaf.io/v1alpha1/namespaces/shop/wafs/shop-waf/metrics?query="+q, nil)
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != 400 {
		t.Fatalf("status %d %s", rr.Code, rr.Body.String())
	}
}

func TestWAFTracesRejectsForeignTags(t *testing.T) {
	called := false
	vt := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		called = true
	}))
	defer vt.Close()
	s := NewServer(Config{Auth: AuthInsecureDev, SAR: AllowAllSAR{}, Query: NewQueryBackend("", vt.URL)})
	req := httptest.NewRequest(http.MethodGet,
		"/apis/subresources.kubewaf.io/v1alpha1/namespaces/shop/wafs/shop-waf/traces?tags="+url.QueryEscape(`{"waf.name":"other"}`), nil)
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != 400 {
		t.Fatalf("status %d %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "UnscopedQuery") {
		t.Fatalf("want UnscopedQuery, got %s", rr.Body.String())
	}
	if called {
		t.Fatal("backend invoked for foreign tags")
	}
}

func TestWAFTracesForcesTags(t *testing.T) {
	var gotTags string
	vt := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotTags = r.URL.Query().Get("tags")
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"data":[]}`)
	}))
	defer vt.Close()
	s := NewServer(Config{Auth: AuthInsecureDev, SAR: AllowAllSAR{}, Query: NewQueryBackend("", vt.URL)})
	req := httptest.NewRequest(http.MethodGet,
		"/apis/subresources.kubewaf.io/v1alpha1/namespaces/shop/wafs/shop-waf/traces", nil)
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("status %d %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(gotTags, `"waf.namespace":"shop"`) || !strings.Contains(gotTags, `"waf.name":"shop-waf"`) {
		t.Fatalf("tags=%s", gotTags)
	}
}

func TestClusterMetricsUnionsAuthorizedWAFs(t *testing.T) {
	var gotQuery string
	vm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.Query().Get("query")
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"status":"success","data":{"resultType":"vector","result":[]}}`)
	}))
	defer vm.Close()
	scheme := testScheme(t)
	w1 := &wafv1beta1.WAF{ObjectMeta: metav1.ObjectMeta{Name: "one", Namespace: "a"}}
	w2 := &wafv1beta1.WAF{ObjectMeta: metav1.ObjectMeta{Name: "two", Namespace: "b"}}
	w1.SetGroupVersionKind(wafv1beta1.GroupVersion.WithKind("WAF"))
	w2.SetGroupVersionKind(wafv1beta1.GroupVersion.WithKind("WAF"))
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(w1, w2).Build()
	s := NewServer(Config{
		Client: cl, Auth: AuthInsecureDev, SAR: AllowAllSAR{},
		Query: NewQueryBackend(vm.URL, ""),
	})
	req := httptest.NewRequest(http.MethodGet,
		"/apis/subresources.kubewaf.io/v1alpha1/clustermetrics?query="+url.QueryEscape(`sum(up)`), nil)
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("status %d %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(gotQuery, `waf_name="one"`) || !strings.Contains(gotQuery, `waf_name="two"`) {
		t.Fatalf("cluster query=%s", gotQuery)
	}
}

func TestWAFMetricsRejectsRegexIdentity(t *testing.T) {
	called := false
	vm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))
	defer vm.Close()
	s := NewServer(Config{Auth: AuthInsecureDev, SAR: AllowAllSAR{}, Query: NewQueryBackend(vm.URL, "")})
	for _, q := range []string{
		`{waf_namespace=~".*"}`,
		`{waf_name=~"a|b"}`,
		`{waf_namespace!="x"}`,
	} {
		called = false
		req := httptest.NewRequest(http.MethodGet,
			"/apis/subresources.kubewaf.io/v1alpha1/namespaces/shop/wafs/shop-waf/metrics?query="+url.QueryEscape(q), nil)
		rr := httptest.NewRecorder()
		s.Handler().ServeHTTP(rr, req)
		if rr.Code != 400 || !strings.Contains(rr.Body.String(), "UnscopedQuery") {
			t.Fatalf("q=%s status=%d body=%s", q, rr.Code, rr.Body.String())
		}
		if called {
			t.Fatalf("backend called for %s", q)
		}
	}
}

func TestWAFMetricsEmptyQueryAndRange(t *testing.T) {
	var gotQuery string
	vm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.Query().Get("query")
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"status":"success","data":{"resultType":"vector","result":[]}}`)
	}))
	defer vm.Close()
	s := NewServer(Config{Auth: AuthInsecureDev, SAR: AllowAllSAR{}, Query: NewQueryBackend(vm.URL, "")})
	req := httptest.NewRequest(http.MethodGet,
		"/apis/subresources.kubewaf.io/v1alpha1/namespaces/shop/wafs/shop-waf/metrics", nil)
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("empty query %d %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(gotQuery, `waf_namespace="shop"`) || !strings.Contains(gotQuery, `waf_name="shop-waf"`) {
		t.Fatalf("default selector not scoped: %s", gotQuery)
	}
	req = httptest.NewRequest(http.MethodGet,
		"/apis/subresources.kubewaf.io/v1alpha1/namespaces/shop/wafs/shop-waf/metrics?query=up&start=1", nil)
	rr = httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != 400 || !strings.Contains(rr.Body.String(), "query_range") {
		t.Fatalf("partial range %d %s", rr.Code, rr.Body.String())
	}
}

func TestClusterMetricsEmptyQueryUnionsAuthorizedWAFs(t *testing.T) {
	var gotQuery string
	vm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.Query().Get("query")
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"status":"success","data":{"resultType":"vector","result":[]}}`)
	}))
	defer vm.Close()
	scheme := testScheme(t)
	w1 := &wafv1beta1.WAF{ObjectMeta: metav1.ObjectMeta{Name: "one", Namespace: "a"}}
	w2 := &wafv1beta1.WAF{ObjectMeta: metav1.ObjectMeta{Name: "two", Namespace: "b"}}
	w1.SetGroupVersionKind(wafv1beta1.GroupVersion.WithKind("WAF"))
	w2.SetGroupVersionKind(wafv1beta1.GroupVersion.WithKind("WAF"))
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(w1, w2).Build()
	s := NewServer(Config{
		Client: cl, Auth: AuthInsecureDev, SAR: AllowAllSAR{},
		Query: NewQueryBackend(vm.URL, ""),
	})
	req := httptest.NewRequest(http.MethodGet,
		"/apis/subresources.kubewaf.io/v1alpha1/clustermetrics", nil)
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("status %d %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(gotQuery, `waf_name="one"`) || !strings.Contains(gotQuery, `waf_name="two"`) {
		t.Fatalf("cluster default query=%s", gotQuery)
	}
}

func TestClusterMetricsEmptyQueryDenyAllVectorZero(t *testing.T) {
	var gotQuery string
	vm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.Query().Get("query")
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"status":"success","data":{"resultType":"vector","result":[]}}`)
	}))
	defer vm.Close()
	scheme := testScheme(t)
	w1 := &wafv1beta1.WAF{ObjectMeta: metav1.ObjectMeta{Name: "one", Namespace: "a"}}
	w1.SetGroupVersionKind(wafv1beta1.GroupVersion.WithKind("WAF"))
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(w1).Build()
	s := NewServer(Config{Client: cl, Auth: AuthInsecureDev, SAR: DenyAllSAR{}, Query: NewQueryBackend(vm.URL, "")})
	req := httptest.NewRequest(http.MethodGet,
		"/apis/subresources.kubewaf.io/v1alpha1/clustermetrics", nil)
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("status %d %s", rr.Code, rr.Body.String())
	}
	if gotQuery != "vector(0)" {
		t.Fatalf("want vector(0) got %q", gotQuery)
	}
}

func TestQueryDisabled404(t *testing.T) {
	s := NewServer(Config{Auth: AuthInsecureDev, DisableQuery: true})
	req := httptest.NewRequest(http.MethodGet,
		"/apis/subresources.kubewaf.io/v1alpha1/namespaces/shop/wafs/shop-waf/metrics?query=up", nil)
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != 404 {
		t.Fatalf("status %d", rr.Code)
	}
}

func TestWAFMetricsSARDeny(t *testing.T) {
	called := false
	vm := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	defer vm.Close()
	s := NewServer(Config{Auth: AuthInsecureDev, SAR: DenyAllSAR{}, Query: NewQueryBackend(vm.URL, "")})
	req := httptest.NewRequest(http.MethodGet,
		"/apis/subresources.kubewaf.io/v1alpha1/namespaces/shop/wafs/shop-waf/metrics?query=up", nil)
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != 403 || called {
		t.Fatalf("status %d called=%v %s", rr.Code, called, rr.Body.String())
	}
}

type allowNamesSAR struct{ allow map[string]bool }

func (a allowNamesSAR) CanGetParent(_ context.Context, _ string, _ []string, _ ParentKind, ns, name string) *MappedError {
	if a.allow[ns+"/"+name] {
		return nil
	}
	return &MappedError{HTTPStatus: 403, Reason: "Forbidden", Message: "denied"}
}

type failSAR struct{}

func (failSAR) CanGetParent(context.Context, string, []string, ParentKind, string, string) *MappedError {
	return &MappedError{HTTPStatus: 503, Reason: ReasonInternalError, Message: "sar down"}
}

func TestClusterMetricsPartialSAR(t *testing.T) {
	var gotQuery string
	vm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.Query().Get("query")
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"status":"success","data":{"resultType":"vector","result":[]}}`)
	}))
	defer vm.Close()
	scheme := testScheme(t)
	w1 := &wafv1beta1.WAF{ObjectMeta: metav1.ObjectMeta{Name: "one", Namespace: "a"}}
	w2 := &wafv1beta1.WAF{ObjectMeta: metav1.ObjectMeta{Name: "two", Namespace: "b"}}
	w1.SetGroupVersionKind(wafv1beta1.GroupVersion.WithKind("WAF"))
	w2.SetGroupVersionKind(wafv1beta1.GroupVersion.WithKind("WAF"))
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(w1, w2).Build()
	s := NewServer(Config{
		Client: cl, Auth: AuthInsecureDev,
		SAR:   allowNamesSAR{allow: map[string]bool{"a/one": true}},
		Query: NewQueryBackend(vm.URL, ""),
	})
	req := httptest.NewRequest(http.MethodGet,
		"/apis/subresources.kubewaf.io/v1alpha1/clustermetrics?query="+url.QueryEscape(`sum(up)`), nil)
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("status %d %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(gotQuery, `waf_name="one"`) || strings.Contains(gotQuery, `waf_name="two"`) {
		t.Fatalf("partial SAR query=%s", gotQuery)
	}
}

func TestClusterMetricsDenyAllVectorZero(t *testing.T) {
	var gotQuery string
	vm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.Query().Get("query")
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"status":"success","data":{"resultType":"vector","result":[]}}`)
	}))
	defer vm.Close()
	scheme := testScheme(t)
	w1 := &wafv1beta1.WAF{ObjectMeta: metav1.ObjectMeta{Name: "one", Namespace: "a"}}
	w1.SetGroupVersionKind(wafv1beta1.GroupVersion.WithKind("WAF"))
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(w1).Build()
	s := NewServer(Config{Client: cl, Auth: AuthInsecureDev, SAR: DenyAllSAR{}, Query: NewQueryBackend(vm.URL, "")})
	req := httptest.NewRequest(http.MethodGet,
		"/apis/subresources.kubewaf.io/v1alpha1/clustermetrics?query="+url.QueryEscape(`sum(up)`), nil)
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("status %d %s", rr.Code, rr.Body.String())
	}
	if gotQuery != "vector(0)" {
		t.Fatalf("want vector(0) got %q", gotQuery)
	}
}

func TestClusterMetricsSAR5xx(t *testing.T) {
	called := false
	vm := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	defer vm.Close()
	scheme := testScheme(t)
	w1 := &wafv1beta1.WAF{ObjectMeta: metav1.ObjectMeta{Name: "one", Namespace: "a"}}
	w1.SetGroupVersionKind(wafv1beta1.GroupVersion.WithKind("WAF"))
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(w1).Build()
	s := NewServer(Config{Client: cl, Auth: AuthInsecureDev, SAR: failSAR{}, Query: NewQueryBackend(vm.URL, "")})
	req := httptest.NewRequest(http.MethodGet,
		"/apis/subresources.kubewaf.io/v1alpha1/clustermetrics?query=up", nil)
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != 503 || called {
		t.Fatalf("status %d called=%v %s", rr.Code, called, rr.Body.String())
	}
}

func TestTraceByIDExactIdentity(t *testing.T) {
	payload := `{
	  "data":[{
	    "traceID":"abc",
	    "spans":[
	      {"traceID":"abc","spanID":"1","processID":"p1","operationName":"waf.eval","startTime":111,"tags":[{"key":"url.path","value":"/shop-waf"}]},
	      {"traceID":"abc","spanID":"2","processID":"p2","operationName":"waf.eval","startTime":1700000000000000,"duration":1500,"references":[{"refType":"CHILD_OF","spanID":"parent1"}],"tags":[]}
	    ],
	    "processes":{
	      "p1":{"serviceName":"kubewaf","tags":[{"key":"waf.namespace","value":"other"},{"key":"waf.name","value":"shop-waf-2"}]},
	      "p2":{"serviceName":"kubewaf","tags":[{"key":"waf.namespace","value":"shop"},{"key":"waf.name","value":"shop-waf"}]}
	    }
	  }]
	}`
	vt := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, payload)
	}))
	defer vt.Close()
	s := NewServer(Config{Auth: AuthInsecureDev, SAR: AllowAllSAR{}, Query: NewQueryBackend("", vt.URL)})
	req := httptest.NewRequest(http.MethodGet,
		"/apis/subresources.kubewaf.io/v1alpha1/namespaces/shop/wafs/shop-waf/traces/abc", nil)
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("status %d %s", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), "shop-waf-2") || strings.Contains(rr.Body.String(), `"p1"`) {
		t.Fatalf("foreign span leaked: %s", rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"p2"`) {
		t.Fatalf("own span missing: %s", rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"operationName":"waf.eval"`) {
		t.Fatalf("operationName dropped: %s", rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"startTime":1700000000000000`) {
		t.Fatalf("startTime dropped: %s", rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"refType":"CHILD_OF"`) {
		t.Fatalf("references dropped: %s", rr.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet,
		"/apis/subresources.kubewaf.io/v1alpha1/namespaces/shop/wafs/nope/traces/abc", nil)
	rr = httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != 404 {
		t.Fatalf("foreign identity %d %s", rr.Code, rr.Body.String())
	}
}

func TestVersionPathMuxUsesParsedSubresource(t *testing.T) {
	scheme := testScheme(t)
	waf := &wafv1beta1.WAF{ObjectMeta: metav1.ObjectMeta{Name: "shop-waf", Namespace: "probes"}}
	waf.SetGroupVersionKind(wafv1beta1.GroupVersion.WithKind("WAF"))
	named := &wafv1beta1.WAF{ObjectMeta: metav1.ObjectMeta{Name: "metrics", Namespace: "shop"}}
	named.SetGroupVersionKind(wafv1beta1.GroupVersion.WithKind("WAF"))
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(waf, named).Build()
	var gotQuery string
	vm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.Query().Get("query")
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"status":"success","data":{"resultType":"vector","result":[]}}`)
	}))
	defer vm.Close()
	s := NewServer(Config{Client: cl, Auth: AuthInsecureDev, SAR: AllowAllSAR{}, Query: NewQueryBackend(vm.URL, "")})
	req := httptest.NewRequest(http.MethodGet,
		"/apis/subresources.kubewaf.io/v1alpha1/namespaces/probes/wafs/shop-waf/metrics?query=up", nil)
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("ns=probes status %d %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(gotQuery, `waf_namespace="probes"`) {
		t.Fatalf("query=%s", gotQuery)
	}
	req = httptest.NewRequest(http.MethodGet,
		"/apis/subresources.kubewaf.io/v1alpha1/namespaces/shop/wafs/metrics/directives", nil)
	rr = httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("name=metrics directives %d %s", rr.Code, rr.Body.String())
	}
}

func TestFilterJaegerPreservesUnknownSpanFields(t *testing.T) {
	in := []byte(`{
	  "total": 1,
	  "data":[{
	    "traceID":"abc",
	    "warnings":["keep-me"],
	    "spans":[{
	      "traceID":"abc","spanID":"2","processID":"p2",
	      "operationName":"waf.eval",
	      "startTime":1700000000000000,
	      "duration":1500,
	      "flags":1,
	      "references":[{"refType":"CHILD_OF","traceID":"abc","spanID":"parent1"}],
	      "tags":[{"key":"waf.name","value":"shop-waf"},{"key":"waf.namespace","value":"shop"}],
	      "logs":[{"timestamp":1,"fields":[{"key":"rule_id","value":"942100"}]}]
	    }],
	    "processes":{
	      "p2":{"serviceName":"kubewaf","tags":[{"key":"waf.namespace","value":"shop"},{"key":"waf.name","value":"shop-waf"}]}
	    }
	  }]
	}`)
	out, ok := filterJaegerToWAF(in, "shop", "shop-waf")
	if !ok {
		t.Fatal("expected keep")
	}
	for _, want := range []string{
		`"startTime":1700000000000000`,
		`"operationName":"waf.eval"`,
		`"refType":"CHILD_OF"`,
		`"duration":1500`,
		`"flags":1`,
		`"warnings":["keep-me"]`,
		`"total":1`,
	} {
		if !strings.Contains(string(out), want) {
			t.Fatalf("missing %s in %s", want, out)
		}
	}
	var wrap map[string]any
	if err := json.Unmarshal(out, &wrap); err != nil {
		t.Fatal(err)
	}
}

func TestWAFMetricsQueryRange1h30s(t *testing.T) {
	var gotPath string
	vm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"status":"success","data":{"resultType":"matrix","result":[]}}`)
	}))
	defer vm.Close()
	s := NewServer(Config{Auth: AuthInsecureDev, SAR: AllowAllSAR{}, Query: NewQueryBackend(vm.URL, "")})
	const end = 1_700_003_600
	const start = end - 3600
	req := httptest.NewRequest(http.MethodGet,
		"/apis/subresources.kubewaf.io/v1alpha1/namespaces/shop/wafs/shop-waf/metrics?query=up&start="+
			strconv.Itoa(start)+"&end="+strconv.Itoa(end)+"&step=30s", nil)
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("status %d %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(gotPath, "/api/v1/query_range") {
		t.Fatalf("path=%s", gotPath)
	}
}

func TestWAFMetricsQueryCapsReject(t *testing.T) {
	called := false
	vm := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	defer vm.Close()
	s := NewServer(Config{Auth: AuthInsecureDev, SAR: AllowAllSAR{}, Query: NewQueryBackend(vm.URL, "")})
	cases := []struct {
		name string
		url  string
	}{
		{
			name: "promql oversize",
			url: "/apis/subresources.kubewaf.io/v1alpha1/namespaces/shop/wafs/shop-waf/metrics?query=" +
				url.QueryEscape(strings.Repeat("a", maxPromQLBytes+1)),
		},
		{
			name: "window over 24h",
			url: "/apis/subresources.kubewaf.io/v1alpha1/namespaces/shop/wafs/shop-waf/metrics?query=up&start=0&end=" +
				strconv.Itoa(maxQueryRangeSec+1) + "&step=30s",
		},
		{
			name: "step 1s over 1h",
			url:  "/apis/subresources.kubewaf.io/v1alpha1/namespaces/shop/wafs/shop-waf/metrics?query=up&start=0&end=3600&step=1s",
		},
	}
	for _, tc := range cases {
		called = false
		req := httptest.NewRequest(http.MethodGet, tc.url, nil)
		rr := httptest.NewRecorder()
		s.Handler().ServeHTTP(rr, req)
		if rr.Code != 400 {
			t.Fatalf("%s status %d %s", tc.name, rr.Code, rr.Body.String())
		}
		if called {
			t.Fatalf("%s backend called", tc.name)
		}
	}
}

func TestReadyzWithoutEval(t *testing.T) {
	s := NewServer(Config{Auth: AuthInsecureDev, DisableProbes: true})
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("readyz %d", rr.Code)
	}
}
