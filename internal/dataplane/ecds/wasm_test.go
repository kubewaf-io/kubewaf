package ecds

import (
	"testing"

	"github.com/kubewaf-io/kubewaf/internal/dataplane/config"
	"github.com/kubewaf-io/kubewaf/internal/dataplane/engine"
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

func TestWasmCodeClusterHostPort(t *testing.T) {
	h, p, err := WasmCodeClusterHostPort("https://cdn.example.com:8443/a.wasm")
	if err != nil {
		t.Fatal(err)
	}
	if h != "cdn.example.com" || p != 8443 {
		t.Fatalf("got %s:%d", h, p)
	}
}
