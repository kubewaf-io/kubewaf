package ecds

import (
	"strings"
	"testing"

	wasm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/wasm/v3"
	wafv1beta1 "github.com/kubewaf-io/kubewaf/api/waf/v1beta1"
	"github.com/kubewaf-io/kubewaf/internal/dataplane/config"
	"github.com/kubewaf-io/kubewaf/internal/dataplane/engine"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func TestBuildTypedExtensionConfigs_TwoFilters(t *testing.T) {
	p := &config.PortableConfig{
		ExtensionName: "kubewaf/ns/waf",
		Filters: []config.PortableFilter{
			{
				ExtensionName: "kubewaf/ns/waf/challenge",
				Role:          config.FilterRoleChallenge,
				ModuleID:      engine.ModuleChallenge,
				WasmName:      "kubewaf.challenge",
				HTTPURL:       "http://ecds:18002/wasm/challenge-proxy-wasm.wasm",
				SHA256:        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
				PluginJSON:    map[string]any{"secret": "x", "base_difficulty": 18},
			},
			{
				ExtensionName: "kubewaf/ns/waf",
				Role:          config.FilterRoleWAF,
				ModuleID:      engine.ModuleModSecurity,
				WasmName:      "kubewaf.modsecurity",
				HTTPURL:       "http://ecds:18002/wasm/modsecurity-proxy-wasm.wasm",
				SHA256:        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				PluginJSON: map[string]any{
					"default_directives": "default",
					"directives_map":     map[string]any{"default": []string{"SecRuleEngine On"}},
				},
			},
		},
	}
	tecs, err := BuildTypedExtensionConfigs(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(tecs) != 2 {
		t.Fatalf("len=%d", len(tecs))
	}
	if tecs[0].GetName() != "kubewaf/ns/waf/challenge" {
		t.Fatalf("name0=%s", tecs[0].GetName())
	}
	if tecs[1].GetName() != "kubewaf/ns/waf" {
		t.Fatalf("name1=%s", tecs[1].GetName())
	}
}

func TestBuildTypedExtensionConfig_RequiresHTTP(t *testing.T) {
	_, err := BuildTypedExtensionConfig(&config.PortableConfig{
		ExtensionName: "x",
		PluginJSON:    map[string]any{},
	})
	if err == nil {
		t.Fatal("expected error when HTTPURL empty")
	}
}

func TestBuildTypedExtensionConfig_RequiresSHA256(t *testing.T) {
	_, err := BuildTypedExtensionConfig(&config.PortableConfig{
		ExtensionName: "x",
		HTTPURL:       "http://ecds:18002/wasm/modsecurity-proxy-wasm.wasm",
		PluginJSON:    map[string]any{},
	})
	if err == nil {
		t.Fatal("expected error when SHA256 empty")
	}
}

func TestWasmFetchCluster(t *testing.T) {
	tests := []struct {
		name string
		p    *config.PortableConfig
		want string
	}{
		{
			name: "cilium",
			p:    &config.PortableConfig{Provider: wafv1beta1.ProviderCilium, Namespace: "demo", Name: "w"},
			want: CiliumPrefixedCluster("demo", "w", WasmCodeCluster),
		},
		{
			name: "envoy-gateway",
			p:    &config.PortableConfig{Provider: wafv1beta1.ProviderEnvoyGateway, Namespace: "demo", Name: "w"},
			want: WasmCodeCluster,
		},
		{
			name: "istio",
			p:    &config.PortableConfig{Provider: wafv1beta1.ProviderIstio, Namespace: "demo", Name: "w"},
			want: WasmCodeCluster,
		},
		{
			name: "cilium-missing-ns",
			p:    &config.PortableConfig{Provider: wafv1beta1.ProviderCilium, Name: "w"},
			want: WasmCodeCluster,
		},
		{
			name: "cilium-missing-name",
			p:    &config.PortableConfig{Provider: wafv1beta1.ProviderCilium, Namespace: "demo"},
			want: WasmCodeCluster,
		},
		{name: "nil", p: nil, want: WasmCodeCluster},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := wasmFetchCluster(tt.p); got != tt.want {
				t.Fatalf("got %q want %q", got, tt.want)
			}
		})
	}
}

func TestWasmFetchCluster_CiliumPrefixedTEC(t *testing.T) {
	sha := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	uri := "http://ecds:18002/wasm/modsecurity-proxy-wasm.wasm"
	p := &config.PortableConfig{
		Provider:      wafv1beta1.ProviderCilium,
		Namespace:     "demo",
		Name:          "demo-waf-cilium",
		ExtensionName: "kubewaf/demo/demo-waf-cilium",
		HTTPURL:       uri,
		SHA256:        sha,
		PluginJSON:    map[string]any{"mode": "kubewaf"},
	}
	tecs, err := BuildTypedExtensionConfigs(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(tecs) != 1 {
		t.Fatalf("len=%d", len(tecs))
	}
	var w wasm.Wasm
	if err := tecs[0].GetTypedConfig().UnmarshalTo(&w); err != nil {
		t.Fatal(err)
	}
	vm := w.GetConfig().GetVmConfig()
	remote := vm.GetCode().GetRemote()
	want := CiliumPrefixedCluster("demo", "demo-waf-cilium", WasmCodeCluster)
	if got := remote.GetHttpUri().GetCluster(); got != want {
		t.Fatalf("cluster=%q want %q", got, want)
	}
	if remote.GetSha256() != sha {
		t.Fatalf("sha=%q", remote.GetSha256())
	}
	if remote.GetHttpUri().GetUri() != uri {
		t.Fatalf("uri=%q", remote.GetHttpUri().GetUri())
	}
	if !vm.GetAllowPrecompiled() {
		t.Fatal("AllowPrecompiled")
	}
	var sv wrapperspb.StringValue
	if err := w.GetConfig().GetConfiguration().UnmarshalTo(&sv); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(sv.GetValue(), `"mode":"kubewaf"`) {
		t.Fatalf("plugin JSON %q", sv.GetValue())
	}
}

func TestWasmCodeClusterHostPort(t *testing.T) {
	h, p, err := WasmCodeClusterHostPort("https://cdn.example.com:8443/a.wasm")
	if err != nil {
		t.Fatal(err)
	}
	if h != "cdn.example.com" || p != 8443 {
		t.Fatalf("got %s:%d", h, p)
	}
}
