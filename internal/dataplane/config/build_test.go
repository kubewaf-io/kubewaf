package config

import (
	"strings"
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
			Metrics: &wafv1beta1.WAFMetrics{
				IncludeRuleID: boolPtr(false),
				EnableStats:   boolPtr(true),
				ExtraLabels:   map[string]string{"team": "payments"},
			},
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
	if labels["waf_namespace"] != "ns1" || labels["waf_name"] != "shop" {
		t.Fatalf("identity labels=%v", labels)
	}
	if labels["engine"] != "modsecurity" {
		t.Fatalf("engine label=%v", labels)
	}
	if labels["team"] != "payments" {
		t.Fatalf("extra labels=%v", labels)
	}
	if p.PluginJSON["mode"] != "kubewaf" {
		t.Fatalf("mode=%v", p.PluginJSON["mode"])
	}
	if p.PluginJSON["config_id"] != "kubewaf/ns1/shop" {
		t.Fatalf("config_id=%v", p.PluginJSON["config_id"])
	}
	if p.PluginJSON["allow_fallback"] != false {
		t.Fatalf("allow_fallback=%v", p.PluginJSON["allow_fallback"])
	}
	metrics, ok := p.PluginJSON["metrics"].(map[string]any)
	if !ok {
		t.Fatalf("metrics type %T", p.PluginJSON["metrics"])
	}
	if metrics["per_rule_id"] != false {
		t.Fatalf("per_rule_id=%v", metrics["per_rule_id"])
	}
	if metrics["enabled"] != true {
		t.Fatalf("enabled=%v", metrics["enabled"])
	}
	if p.PluginJSON["metrics_per_rule_id"] != false {
		t.Fatalf("flat metrics_per_rule_id=%v", p.PluginJSON["metrics_per_rule_id"])
	}
	block, ok := p.PluginJSON["block"].(map[string]any)
	if !ok {
		t.Fatalf("block type %T", p.PluginJSON["block"])
	}
	if block["message"] != "blocked by kubeWAF" {
		t.Fatalf("block.message=%v", block["message"])
	}
	// Directives must start with production baseline virtual include.
	if len(p.Directives) == 0 || p.Directives[0] != "Include @kubewaf-defaults" {
		t.Fatalf("directives[0]=%v full=%v", firstOrEmpty(p.Directives), p.Directives)
	}
}

func firstOrEmpty(ss []string) string {
	if len(ss) == 0 {
		return ""
	}
	return ss[0]
}

func TestBuildDirectives_Order(t *testing.T) {
	waf := &wafv1beta1.WAF{
		Spec: wafv1beta1.WAFSpec{
			Engine:    wafv1beta1.EngineModSecurity,
			LogLevel:  3,
			CRSEnable: true,
			CRS: &wafv1beta1.CRSTuning{
				ParanoiaLevel: intPtr(2),
			},
		},
	}
	dirs := BuildDirectives(waf, []string{`SecRule ARGS "@rx x" "id:100001,phase:2,pass"`})
	if dirs[0] != "Include @kubewaf-defaults" {
		t.Fatalf("want kubewaf-defaults first, got %v", dirs)
	}
	joined := strings.Join(dirs, "\n")
	for _, want := range []string{
		"SecRuleEngine On",
		"Include @crs-setup-conf",
		"Include @owasp_crs/*.conf",
		"id:100001",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("directives missing %q: %v", want, dirs)
		}
	}

	// Coraza must not receive @kubewaf-defaults (not in that binary).
	waf.Spec.Engine = wafv1beta1.EngineCoraza
	corazaDirs := BuildDirectives(waf, nil)
	for _, d := range corazaDirs {
		if d == "Include @kubewaf-defaults" {
			t.Fatalf("coraza should not include @kubewaf-defaults: %v", corazaDirs)
		}
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
