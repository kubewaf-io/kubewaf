package config

import (
	"testing"

	wafv1beta1 "github.com/kubewaf-io/kubewaf/api/waf/v1beta1"
	"github.com/kubewaf-io/kubewaf/internal/dataplane/engine"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func boolPtr(b bool) *bool { return &b }
func intPtr(i int) *int    { return &i }

func TestBuildFromWAF_ModSecurityEngine(t *testing.T) {
	waf := &wafv1beta1.WAF{
		ObjectMeta: metav1.ObjectMeta{Name: "shop", Namespace: "ns1"},
		Spec: wafv1beta1.WAFSpec{
			Engine:   wafv1beta1.EngineModSecurity,
			LogLevel: 3,
			Provider: &wafv1beta1.WAFProvider{Type: wafv1beta1.ProviderEnvoyGateway},
		},
	}
	opts := BuildOptions{
		DefaultECDSHost: "ecds.svc",
		DefaultECDSPort: 18001,
		DefaultModuleHTTP: map[engine.ModuleID]string{
			engine.ModuleModSecurity: "http://ecds.svc:18002/wasm/modsecurity-proxy-wasm.wasm",
		},
	}
	p, err := BuildFromWAF(waf, []string{`SecRule ARGS "@rx x" "id:100001,phase:2,pass"`}, opts)
	if err != nil {
		t.Fatal(err)
	}
	if p.Engine != wafv1beta1.EngineModSecurity {
		t.Fatalf("engine=%s", p.Engine)
	}
	if len(p.Filters) != 1 || p.Filters[0].ModuleID != engine.ModuleModSecurity {
		t.Fatalf("filters=%+v", p.Filters)
	}
	labels, _ := p.PluginJSON["metric_labels"].(map[string]string)
	if labels["owner"] != "modsecurity-proxy-wasm" {
		t.Fatalf("labels=%v", labels)
	}
}

func TestBuildFromWAF_ChallengeFilter(t *testing.T) {
	waf := &wafv1beta1.WAF{
		ObjectMeta: metav1.ObjectMeta{Name: "shop", Namespace: "ns1"},
		Spec: wafv1beta1.WAFSpec{
			Engine: wafv1beta1.EngineCoraza,
			Challenge: &wafv1beta1.ChallengeSpec{
				Enabled:        boolPtr(true),
				Secret:         "super-secret-hmac-key-for-tests",
				BaseDifficulty: intPtr(16),
			},
		},
	}
	opts := BuildOptions{
		DefaultECDSHost: "ecds.svc",
		DefaultECDSPort: 18001,
		DefaultModuleHTTP: map[engine.ModuleID]string{
			engine.ModuleCoraza:    "http://ecds.svc:18002/wasm/coraza-proxy-wasm.wasm",
			engine.ModuleChallenge: "http://ecds.svc:18002/wasm/challenge-proxy-wasm.wasm",
		},
	}
	p, err := BuildFromWAF(waf, nil, opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Filters) != 2 {
		t.Fatalf("want 2 filters, got %d", len(p.Filters))
	}
	if p.Filters[0].Role != FilterRoleChallenge {
		t.Fatalf("first filter should be challenge: %s", p.Filters[0].Role)
	}
	if p.Filters[1].Role != FilterRoleWAF {
		t.Fatalf("second filter should be waf: %s", p.Filters[1].Role)
	}
	if p.Filters[0].PluginJSON["secret"] != "super-secret-hmac-key-for-tests" {
		t.Fatalf("secret not set")
	}
	if p.Filters[0].ExtensionName != "kubewaf/ns1/shop/challenge" {
		t.Fatalf("challenge name=%s", p.Filters[0].ExtensionName)
	}
}

func TestBuildFromWAF_IstioProvider(t *testing.T) {
	waf := &wafv1beta1.WAF{
		ObjectMeta: metav1.ObjectMeta{Name: "shop", Namespace: "ns1"},
		Spec: wafv1beta1.WAFSpec{
			LogLevel: 3,
			Provider: &wafv1beta1.WAFProvider{
				Type:        wafv1beta1.ProviderIstio,
				ECDSCluster: "my_ecds",
				ECDSService: "ecds.ns.svc:18001",
				Istio: &wafv1beta1.IstioProvider{
					WorkloadSelector: map[string]string{"app": "istio-ingress"},
					Context:          "GATEWAY",
				},
			},
		},
	}
	p, err := BuildFromWAF(waf, []string{`SecRule ARGS "@rx x" "id:100001,phase:2,pass"`}, BuildOptions{
		DefaultECDSHost: "default-host",
		DefaultECDSPort: 18001,
		DefaultModuleHTTP: map[engine.ModuleID]string{
			engine.ModuleCoraza: "http://h/c.wasm",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if p.Provider != wafv1beta1.ProviderIstio {
		t.Fatalf("provider=%s", p.Provider)
	}
	if p.ExtensionName != "kubewaf/ns1/shop" {
		t.Fatalf("extension name=%s", p.ExtensionName)
	}
}

func TestExtensionNames(t *testing.T) {
	if got := ExtensionName("a", "b"); got != "kubewaf/a/b" {
		t.Fatalf("got %s", got)
	}
	if got := ChallengeExtensionName("a", "b"); got != "kubewaf/a/b/challenge" {
		t.Fatalf("got %s", got)
	}
}
