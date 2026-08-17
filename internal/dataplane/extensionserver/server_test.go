package extensionserver

import (
	"testing"

	listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	"github.com/go-logr/logr"
	"google.golang.org/protobuf/types/known/anypb"

	wafv1beta1 "github.com/kubewaf-io/kubewaf/api/waf/v1beta1"
	"github.com/kubewaf-io/kubewaf/internal/dataplane/config"
	"github.com/kubewaf-io/kubewaf/internal/dataplane/xdsutil"
)

func TestUpsertDeleteIndex(t *testing.T) {
	s := New(logr.Discard(), nil, config.BuildOptions{})
	p := &config.PortableConfig{
		Namespace: "ns",
		Name:      "shop",
		Provider:  wafv1beta1.ProviderEnvoyGateway,
	}
	s.Upsert(p)
	s.mu.RLock()
	_, ok := s.configs["ns/shop"]
	s.mu.RUnlock()
	if !ok {
		t.Fatal("expected index entry")
	}

	// Non-EG providers are ignored.
	s.Upsert(&config.PortableConfig{
		Namespace: "ns",
		Name:      "istio",
		Provider:  wafv1beta1.ProviderIstio,
	})
	s.mu.RLock()
	_, ok = s.configs["ns/istio"]
	s.mu.RUnlock()
	if ok {
		t.Fatal("istio provider should not be indexed for EG extension")
	}

	s.Delete("ns", "shop")
	s.mu.RLock()
	_, ok = s.configs["ns/shop"]
	s.mu.RUnlock()
	if ok {
		t.Fatal("expected delete")
	}
}

func TestUpsertNilSafe(t *testing.T) {
	s := New(logr.Discard(), nil, config.BuildOptions{})
	s.Upsert(nil)
	s.Delete("a", "b")
}

func TestBuildOTelCluster(t *testing.T) {
	s := New(logr.Discard(), nil, config.BuildOptions{
		DefaultOTelHost: "otel.svc",
		DefaultOTelPort: 4317,
	})
	c, err := s.buildOTelCluster(nil)
	if err != nil || c == nil {
		t.Fatalf("defaults: c=%v err=%v", c, err)
	}
	if c.GetName() != config.DefaultOTelCluster {
		t.Fatalf("name=%s", c.GetName())
	}
	if c.GetTypedExtensionProtocolOptions()["envoy.extensions.upstreams.http.v3.HttpProtocolOptions"] == nil {
		t.Fatal("http2 required")
	}

	s2 := New(logr.Discard(), nil, config.BuildOptions{})
	c, err = s2.buildOTelCluster([]*config.PortableConfig{{OTelHost: "from-waf", OTelPort: 4317}})
	if err != nil || c == nil {
		t.Fatal(err)
	}
	s3 := New(logr.Discard(), nil, config.BuildOptions{})
	c, err = s3.buildOTelCluster(nil)
	if err != nil || c != nil {
		t.Fatalf("empty should skip: %v %v", c, err)
	}
}

func TestInjectIntoFilterChain_AccessLogWhenStubsExist(t *testing.T) {
	mgr := &hcm.HttpConnectionManager{
		HttpFilters: []*hcm.HttpFilter{
			{Name: "kubewaf/ns/shop"},
			{Name: "envoy.filters.http.router"},
		},
	}
	anyHCM, err := anypb.New(mgr)
	if err != nil {
		t.Fatal(err)
	}
	fc := &listener.FilterChain{
		Filters: []*listener.Filter{{
			Name:       "envoy.filters.network.http_connection_manager",
			ConfigType: &listener.Filter_TypedConfig{TypedConfig: anyHCM},
		}},
	}
	p := &config.PortableConfig{
		ExtensionName:    "kubewaf/ns/shop",
		ECDSCluster:      "kubewaf_ecds",
		TelemetryManaged: true,
	}
	if err := injectIntoFilterChain(fc, []*config.PortableConfig{p}); err != nil {
		t.Fatal(err)
	}
	var out hcm.HttpConnectionManager
	if err := fc.Filters[0].GetTypedConfig().UnmarshalTo(&out); err != nil {
		t.Fatal(err)
	}
	if !xdsutil.HasOTelAccessLog(&out) {
		t.Fatal("expected WAF OTel access log when stubs already present")
	}
	if err := injectIntoFilterChain(fc, []*config.PortableConfig{p}); err != nil {
		t.Fatal(err)
	}
	if err := fc.Filters[0].GetTypedConfig().UnmarshalTo(&out); err != nil {
		t.Fatal(err)
	}
	if n := len(out.AccessLog); n != 1 {
		t.Fatalf("second inject not idempotent: %d", n)
	}
}
