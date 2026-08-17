package pipeline

import (
	"context"
	"strings"
	"testing"

	"github.com/go-logr/logr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	seclangv1beta1 "github.com/kubewaf-io/kubewaf/api/seclang/v1beta1"
	wafv1beta1 "github.com/kubewaf-io/kubewaf/api/waf/v1beta1"
	"github.com/kubewaf-io/kubewaf/internal/dataplane/config"
	"github.com/kubewaf-io/kubewaf/internal/dataplane/ecds"
	"github.com/kubewaf-io/kubewaf/internal/dataplane/engine"
)

func pipelineScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := wafv1beta1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	if err := seclangv1beta1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	return s
}

func testBuildOpts() config.BuildOptions {
	return config.BuildOptions{
		DefaultECDSHost: "ecds.svc",
		DefaultECDSPort: 18001,
		DefaultModuleHTTP: map[engine.ModuleID]string{
			engine.ModuleModSecurity: "http://ecds.svc:18002/wasm/modsecurity-proxy-wasm.wasm",
		},
		DefaultModuleSHA256: map[engine.ModuleID]string{
			engine.ModuleModSecurity: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		},
	}
}

func testWAF() *wafv1beta1.WAF {
	return &wafv1beta1.WAF{
		ObjectMeta: metav1.ObjectMeta{Name: "shop", Namespace: "ns1"},
		Spec: wafv1beta1.WAFSpec{
			Provider: &wafv1beta1.WAFProvider{Type: wafv1beta1.ProviderEnvoyGateway},
		},
	}
}

func TestBuildAndPublish_SkipsPublishOnMissingRuleSet(t *testing.T) {
	scheme := pipelineScheme(t)
	waf := testWAF()
	waf.Spec.RuleSetRefs = []wafv1beta1.RuleRef{{Name: "missing-rules"}}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(waf).Build()
	srv := ecds.New(context.Background(), logr.Discard())
	ext := config.ExtensionName(waf.Namespace, waf.Name)

	res, err := BuildAndPublish(context.Background(), c, waf, Publishers{ECDS: srv}, Options{
		BuildOpts:     testBuildOpts(),
		Scheme:        scheme,
		RequireRefsOK: true,
	})
	if err == nil {
		t.Fatal("expected reference error")
	}
	if res == nil || len(res.ReferenceErrors) == 0 {
		t.Fatalf("want ReferenceErrors on result, got %+v", res)
	}
	if srv.Has(ext) {
		t.Fatal("must not publish partial ECDS when RuleSet refs are unresolved")
	}
}

func TestBuildAndPublish_KeepsLastGoodSnapshot(t *testing.T) {
	scheme := pipelineScheme(t)
	waf := testWAF()
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(waf).Build()
	srv := ecds.New(context.Background(), logr.Discard())
	opts := Options{BuildOpts: testBuildOpts(), Scheme: scheme, RequireRefsOK: true}
	pubs := Publishers{ECDS: srv}

	if _, err := BuildAndPublish(context.Background(), c, waf, pubs, opts); err != nil {
		t.Fatalf("initial publish: %v", err)
	}
	ext := config.ExtensionName(waf.Namespace, waf.Name)
	if !srv.Has(ext) {
		t.Fatal("expected initial ECDS snapshot")
	}

	waf.Spec.RuleSetRefs = []wafv1beta1.RuleRef{{Name: "missing-rules"}}
	_, err := BuildAndPublish(context.Background(), c, waf, pubs, opts)
	if err == nil {
		t.Fatal("expected reference error after RuleSet disappeared")
	}
	if !strings.Contains(err.Error(), "reference error") {
		t.Fatalf("want reference error, got %v", err)
	}
	if !srv.Has(ext) {
		t.Fatal("unresolved refs must keep the last good ECDS snapshot")
	}
}

func TestBuildAndPublish_FailClosedWithoutRequireRefsOK(t *testing.T) {
	scheme := pipelineScheme(t)
	waf := testWAF()
	waf.Spec.RuleSetRefs = []wafv1beta1.RuleRef{{Name: "missing-rules"}}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(waf).Build()
	srv := ecds.New(context.Background(), logr.Discard())

	_, err := BuildAndPublish(context.Background(), c, waf, Publishers{ECDS: srv}, Options{
		BuildOpts:     testBuildOpts(),
		Scheme:        scheme,
		RequireRefsOK: false,
	})
	if err == nil {
		t.Fatal("expected publish to refuse unresolved refs even when RequireRefsOK is false")
	}
	if srv.Has(config.ExtensionName(waf.Namespace, waf.Name)) {
		t.Fatal("must not publish partial rules")
	}
}
