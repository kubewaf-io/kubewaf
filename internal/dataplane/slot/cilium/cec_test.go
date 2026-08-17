/*
Copyright 2025 Buzz-IT GmbH.
*/
package cilium

import (
	"strings"
	"testing"

	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"

	egv1a1 "github.com/envoyproxy/gateway/api/v1alpha1"
	"github.com/kubewaf-io/kubewaf/internal/dataplane/config"
	"github.com/kubewaf-io/kubewaf/internal/dataplane/ecds"
)

func TestResourceNameMatchesECDSPrefix(t *testing.T) {
	if ResourceName("demo-waf") != ecds.CECResourceName("demo-waf") {
		t.Fatalf("ResourceName=%q ecds.CECResourceName=%q", ResourceName("demo-waf"), ecds.CECResourceName("demo-waf"))
	}
}

func TestBuildResources_IncludesECDSFilter(t *testing.T) {
	p := gatewayPortable()
	svcs := buildServices(p)
	if len(svcs) < 2 {
		t.Fatalf("expected gateway + app services, got %#v", svcs)
	}
	if !serviceNamed(svcs, "cilium-gateway-demo-gateway") || !serviceNamed(svcs, "httpbin") {
		t.Fatalf("missing gateway or app service: %#v", svcs)
	}

	res := buildResources(p, wasmEndpoint{})
	assertNoClusterNamed(t, res, "kubewaf_ecds")
	assertNoClusterNamed(t, res, "kubewaf_otel")
	assertClusterNamed(t, res, ecds.WasmCodeCluster)
	stubs := collectECDSStubs(res)
	if len(stubs) != 1 {
		t.Fatalf("want 1 ECDS stub, got %d (%#v)", len(stubs), stubs)
	}
	assertECDSStub(t, stubs[0], "kubewaf/demo/demo-waf-cilium")
	assertRouterLast(t, res)
	if hasPluginJSON(res) {
		t.Fatal("CEC must not embed plugin JSON / remote Wasm typed_config")
	}

	staticRes := buildResources(p, wasmEndpoint{host: "10.96.1.2", port: 18002, static: true})
	c := clusterByName(staticRes, ecds.WasmCodeCluster)
	if c == nil {
		t.Fatal("missing wasm cluster")
	}
	if c["type"] != "STATIC" {
		t.Fatalf("wasm cluster type=%v", c["type"])
	}
	if addr := clusterSocketAddress(c); addr != "10.96.1.2" {
		t.Fatalf("wasm cluster address=%q", addr)
	}
}

func TestBuildResources_ServiceOnlyECDS(t *testing.T) {
	p := &config.PortableConfig{
		ExtensionName:          "kubewaf/ns/w",
		Namespace:              "ns",
		Name:                   "w",
		ECDSCluster:            "kubewaf_ecds",
		CiliumServiceName:      "app",
		CiliumServiceNamespace: "ns",
		HTTPURL:                "http://ecds:18002/wasm/modsecurity-proxy-wasm.wasm",
		SHA256:                 "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}
	res := buildResources(p, wasmEndpoint{})
	assertNoClusterNamed(t, res, "kubewaf_ecds")
	assertNoClusterNamed(t, res, "kubewaf_otel")
	stubs := collectECDSStubs(res)
	if len(stubs) != 1 {
		t.Fatalf("service-only stubs=%d", len(stubs))
	}
	assertECDSStub(t, stubs[0], "kubewaf/ns/w")
	if listenerByName(res, "listener") != nil {
		t.Fatal("service-only must not emit gateway listener")
	}
	if listenerByName(res, "kubewaf-w-listener") == nil {
		t.Fatal("missing service listener")
	}
	if got := routeClusterName(res); got != "kubewaf_original_dst" {
		t.Fatalf("service route cluster=%q", got)
	}
	if clusterByName(res, "kubewaf_original_dst") == nil {
		t.Fatal("missing ORIGINAL_DST cluster")
	}
}

func TestHTTPFilters_TwoFiltersAndDefaultCluster(t *testing.T) {
	p := &config.PortableConfig{
		Filters: []config.PortableFilter{
			{ExtensionName: "chal"},
			{ExtensionName: "waf"},
		},
	}
	fs := httpFilters(p)
	if len(fs) != 3 {
		t.Fatalf("want challenge+waf+router, got %d", len(fs))
	}
	assertECDSStub(t, fs[0].(map[string]any), "chal")
	assertECDSStub(t, fs[1].(map[string]any), "waf")
	router := fs[2].(map[string]any)
	if router["name"] != "envoy.filters.http.router" {
		t.Fatalf("router last: %#v", router)
	}
	if _, ok := router["typed_config"]; !ok {
		t.Fatal("router needs typed_config")
	}
}

func TestECDSClusterName_EmptyFallsBack(t *testing.T) {
	if got := ecdsClusterName(nil); got != config.DefaultECDSCluster {
		t.Fatalf("nil: %q", got)
	}
	if got := ecdsClusterName(&config.PortableConfig{}); got != config.DefaultECDSCluster {
		t.Fatalf("empty: %q", got)
	}
}

func TestResolveWasmEndpoint(t *testing.T) {
	tests := []struct {
		name       string
		url        string
		wantHost   string
		wantPort   uint32
		wantStatic bool
		wantHTTPS  bool
	}{
		{name: "empty"},
		{name: "invalid", url: "not-a-url"},
		{name: "no-host", url: "http:///wasm/x.wasm"},
		{name: "ip-http", url: "http://10.96.1.5:18002/wasm/x.wasm", wantHost: "10.96.1.5", wantPort: 18002, wantStatic: true},
		{name: "ip-https", url: "https://10.96.1.5:8443/wasm/x.wasm", wantHost: "10.96.1.5", wantPort: 8443, wantStatic: true, wantHTTPS: true},
		{name: "unresolvable-host", url: "http://no-such-host.invalid:18002/x.wasm", wantHost: "no-such-host.invalid", wantPort: 18002},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ep := resolveWasmEndpoint(t.Context(), nil, tt.url)
			if ep.host != tt.wantHost || ep.port != tt.wantPort || ep.static != tt.wantStatic || ep.https != tt.wantHTTPS {
				t.Fatalf("got %+v want host=%q port=%d static=%v https=%v", ep, tt.wantHost, tt.wantPort, tt.wantStatic, tt.wantHTTPS)
			}
		})
	}

	c := wasmCodeClusterResource(wasmEndpoint{host: "cdn.example.com", port: 18002})
	if c["type"] != "STRICT_DNS" {
		t.Fatalf("hostname fallback type=%v", c["type"])
	}
	httpsC := wasmCodeClusterResource(wasmEndpoint{host: "cdn.example.com", port: 443, https: true})
	if httpsC["type"] != "STRICT_DNS" {
		t.Fatalf("https hostname type=%v", httpsC["type"])
	}
}

func TestBuildResources_OTelAccessLogNoCluster(t *testing.T) {
	p := gatewayPortable()
	p.TelemetryManaged = true
	res := buildResources(p, wasmEndpoint{})
	assertNoClusterNamed(t, res, "kubewaf_otel")
	// Cilium 1.19 cannot parse OpenTelemetryAccessLogConfig; injecting it
	// drops the CEC listener. Do not emit access_log on Cilium.
	if hasOTelAccessLog(res) {
		t.Fatal("Cilium CEC must not embed OTel access log (Cilium protojson rejects it)")
	}
	if hasAccessLogKey(res) {
		t.Fatal("access_log key must be omitted on Cilium even when TelemetryManaged")
	}
}

func TestHCMAccessLogs_NoneWhenNotManaged(t *testing.T) {
	if logs := hcmAccessLogs(gatewayPortable()); logs != nil {
		t.Fatalf("unexpected access logs: %#v", logs)
	}
	res := buildResources(gatewayPortable(), wasmEndpoint{})
	if hasAccessLogKey(res) {
		t.Fatal("access_log key must be omitted when not Managed")
	}
}

func hasAccessLogKey(res []any) bool {
	for _, r := range res {
		m := asMap(r)
		if !listenerType(m) {
			continue
		}
		chains, _ := m["filter_chains"].([]any)
		for _, ch := range chains {
			filters, _ := asMap(ch)["filters"].([]any)
			for _, fl := range filters {
				tc := asMap(asMap(fl)["typed_config"])
				if _, ok := tc["access_log"]; ok {
					return true
				}
			}
		}
	}
	return false
}

func hasOTelAccessLog(res []any) bool {
	for _, r := range res {
		m := asMap(r)
		if !listenerType(m) {
			continue
		}
		chains, _ := m["filter_chains"].([]any)
		for _, ch := range chains {
			filters, _ := asMap(ch)["filters"].([]any)
			for _, fl := range filters {
				tc := asMap(asMap(fl)["typed_config"])
				logs, _ := tc["access_log"].([]any)
				for _, l := range logs {
					if asMap(l)["name"] == "envoy.access_loggers.open_telemetry" {
						return true
					}
				}
			}
		}
	}
	return false
}

func TestECDSHTTPFilter_Stub(t *testing.T) {
	f := ecdsHTTPFilter("ext", "kubewaf_ecds")
	assertECDSStub(t, f, "ext")
}

func TestGatewayServiceName(t *testing.T) {
	if got := GatewayServiceName("demo-gateway"); got != "cilium-gateway-demo-gateway" {
		t.Fatalf("got %q", got)
	}
}

func TestBuildServices_NoGateway(t *testing.T) {
	p := &config.PortableConfig{
		Name:                   "w",
		Namespace:              "ns",
		CiliumServiceName:      "app",
		CiliumServiceNamespace: "ns",
		PolicyTargets:          egv1a1.PolicyTargetReferences{},
	}
	svcs := buildServices(p)
	if len(svcs) != 1 {
		t.Fatalf("want 1 service, got %#v", svcs)
	}
	m := asMap(svcs[0])
	if m["name"] != "app" || m["namespace"] != "ns" {
		t.Fatalf("service name/namespace=%#v", m)
	}
}

func gatewayPortable() *config.PortableConfig {
	return &config.PortableConfig{
		ExtensionName: "kubewaf/demo/demo-waf-cilium",
		Namespace:     "demo",
		Name:          "demo-waf-cilium",
		ECDSCluster:   "kubewaf_ecds",
		WasmName:      "kubewaf.modsecurity",
		HTTPURL:       "http://kubewaf-ecds.kubewaf-system.svc.cluster.local:18002/wasm/modsecurity-proxy-wasm.wasm",
		SHA256:        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		PluginJSON: map[string]any{
			"mode": "kubewaf",
			"directives_map": map[string]any{
				"default": []any{"SecRuleEngine On"},
			},
		},
		CiliumServiceName:      "httpbin",
		CiliumServiceNamespace: "demo",
		PolicyTargets: egv1a1.PolicyTargetReferences{
			TargetRef: &gwapiv1.LocalPolicyTargetReferenceWithSectionName{
				LocalPolicyTargetReference: gwapiv1.LocalPolicyTargetReference{
					Group: "gateway.networking.k8s.io",
					Kind:  "Gateway",
					Name:  "demo-gateway",
				},
			},
		},
	}
}

func asMap(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

func serviceNamed(svcs []any, name string) bool {
	for _, s := range svcs {
		if asMap(s)["name"] == name {
			return true
		}
	}
	return false
}

func clusterType(m map[string]any) bool {
	t, _ := m["@type"].(string)
	return t == "type.googleapis.com/envoy.config.cluster.v3.Cluster"
}

func listenerType(m map[string]any) bool {
	t, _ := m["@type"].(string)
	return t == "type.googleapis.com/envoy.config.listener.v3.Listener"
}

func clusterByName(res []any, name string) map[string]any {
	for _, r := range res {
		m := asMap(r)
		if clusterType(m) && m["name"] == name {
			return m
		}
	}
	return nil
}

func listenerByName(res []any, name string) map[string]any {
	for _, r := range res {
		m := asMap(r)
		if listenerType(m) && m["name"] == name {
			return m
		}
	}
	return nil
}

func assertNoClusterNamed(t *testing.T, res []any, name string) {
	t.Helper()
	if c := clusterByName(res, name); c != nil {
		t.Fatalf("CEC must not define Cluster %q: %#v", name, c)
	}
}

func assertClusterNamed(t *testing.T, res []any, name string) {
	t.Helper()
	if clusterByName(res, name) == nil {
		t.Fatalf("missing Cluster %q", name)
	}
	for _, r := range res {
		m := asMap(r)
		if !clusterType(m) {
			continue
		}
		n, _ := m["name"].(string)
		if strings.HasSuffix(n, "/"+ecds.WasmCodeCluster) {
			t.Fatalf("CEC Cluster.name must be unprefixed %q, got %q", ecds.WasmCodeCluster, n)
		}
	}
}

func routeClusterName(res []any) string {
	for _, r := range res {
		m := asMap(r)
		t, _ := m["@type"].(string)
		if t != "type.googleapis.com/envoy.config.route.v3.RouteConfiguration" {
			continue
		}
		vhs, _ := m["virtual_hosts"].([]any)
		if len(vhs) == 0 {
			continue
		}
		routes, _ := asMap(vhs[0])["routes"].([]any)
		if len(routes) == 0 {
			continue
		}
		cl, _ := asMap(asMap(routes[0])["route"])["cluster"].(string)
		return cl
	}
	return ""
}

func clusterSocketAddress(c map[string]any) string {
	la := asMap(c["load_assignment"])
	eps, _ := la["endpoints"].([]any)
	if len(eps) == 0 {
		return ""
	}
	lbs, _ := asMap(eps[0])["lb_endpoints"].([]any)
	if len(lbs) == 0 {
		return ""
	}
	ep := asMap(asMap(lbs[0])["endpoint"])
	sock := asMap(asMap(ep["address"])["socket_address"])
	addr, _ := sock["address"].(string)
	return addr
}

func collectECDSStubs(res []any) []map[string]any {
	var out []map[string]any
	for _, f := range collectHTTPFilters(res) {
		if _, ok := f["config_discovery"]; ok {
			out = append(out, f)
		}
	}
	return out
}

func collectHTTPFilters(res []any) []map[string]any {
	var out []map[string]any
	for _, r := range res {
		m := asMap(r)
		if !listenerType(m) {
			continue
		}
		chains, _ := m["filter_chains"].([]any)
		for _, ch := range chains {
			filters, _ := asMap(ch)["filters"].([]any)
			for _, fl := range filters {
				tc := asMap(asMap(fl)["typed_config"])
				hfs, _ := tc["http_filters"].([]any)
				for _, hf := range hfs {
					if fm := asMap(hf); fm != nil {
						out = append(out, fm)
					}
				}
			}
		}
	}
	return out
}

func assertRouterLast(t *testing.T, res []any) {
	t.Helper()
	fs := collectHTTPFilters(res)
	if len(fs) == 0 {
		t.Fatal("no http_filters")
	}
	last := fs[len(fs)-1]
	if last["name"] != "envoy.filters.http.router" {
		t.Fatalf("router not last: %#v", last)
	}
}

func assertECDSStub(t *testing.T, f map[string]any, name string) {
	t.Helper()
	if f["name"] != name {
		t.Fatalf("filter name=%v want %q", f["name"], name)
	}
	if _, ok := f["typed_config"]; ok {
		t.Fatalf("ECDS stub must not have typed_config: %#v", f)
	}
	cd := asMap(f["config_discovery"])
	if cd == nil {
		t.Fatalf("missing config_discovery: %#v", f)
	}
	urls, _ := cd["type_urls"].([]any)
	if len(urls) != 1 || urls[0] != "type.googleapis.com/envoy.extensions.filters.http.wasm.v3.Wasm" {
		t.Fatalf("type_urls=%#v", urls)
	}
	src := asMap(cd["config_source"])
	if src["resource_api_version"] != "V3" {
		t.Fatalf("resource_api_version=%v", src["resource_api_version"])
	}
	api := asMap(src["api_config_source"])
	if api["api_type"] != "GRPC" {
		t.Fatalf("api_type=%v", api["api_type"])
	}
	if api["transport_api_version"] != "V3" {
		t.Fatalf("transport_api_version=%v", api["transport_api_version"])
	}
	if api["set_node_on_first_message_only"] != true {
		t.Fatalf("set_node_on_first_message_only=%v", api["set_node_on_first_message_only"])
	}
	svcs, _ := api["grpc_services"].([]any)
	if len(svcs) != 1 {
		t.Fatalf("grpc_services=%#v", svcs)
	}
	got, _ := asMap(asMap(svcs[0])["envoy_grpc"])["cluster_name"].(string)
	if got != config.DefaultECDSCluster {
		t.Fatalf("envoy_grpc.cluster_name=%q want %q", got, config.DefaultECDSCluster)
	}
}

func hasPluginJSON(res []any) bool {
	var walk func(any) bool
	walk = func(v any) bool {
		switch x := v.(type) {
		case map[string]any:
			if _, ok := x["directives_map"]; ok {
				return true
			}
			if _, ok := x["allow_precompiled"]; ok {
				return true
			}
			for _, e := range x {
				if walk(e) {
					return true
				}
			}
		case []any:
			for _, e := range x {
				if walk(e) {
					return true
				}
			}
		case string:
			if x == "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
				return true
			}
		}
		return false
	}
	return walk(res)
}
