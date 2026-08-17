package xdsutil

import (
	"testing"

	accesslog "github.com/envoyproxy/go-control-plane/envoy/config/accesslog/v3"
	otelaccesslog "github.com/envoyproxy/go-control-plane/envoy/extensions/access_loggers/open_telemetry/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/kubewaf-io/kubewaf/internal/dataplane/config"
)

func TestMakeOTelCluster_HTTP2(t *testing.T) {
	c, err := MakeOTelCluster("otel.svc", 4317)
	if err != nil {
		t.Fatal(err)
	}
	if c.GetName() != config.DefaultOTelCluster {
		t.Fatalf("name=%s", c.GetName())
	}
	if c.GetTypedExtensionProtocolOptions()["envoy.extensions.upstreams.http.v3.HttpProtocolOptions"] == nil {
		t.Fatal("expected http2 protocol options")
	}
	nilC, err := MakeOTelCluster("", 4317)
	if err != nil || nilC != nil {
		t.Fatalf("empty host: c=%v err=%v", nilC, err)
	}
}

func TestAppendOTelAccessLog_Idempotent(t *testing.T) {
	mgr := &hcm.HttpConnectionManager{}
	if err := AppendOTelAccessLog(mgr, config.DefaultOTelCluster); err != nil {
		t.Fatal(err)
	}
	if !HasOTelAccessLog(mgr) || len(mgr.AccessLog) != 1 {
		t.Fatalf("logs=%d", len(mgr.AccessLog))
	}
	if err := AppendOTelAccessLog(mgr, config.DefaultOTelCluster); err != nil {
		t.Fatal(err)
	}
	if len(mgr.AccessLog) != 1 {
		t.Fatalf("second append clobbered: %d", len(mgr.AccessLog))
	}
	al := mgr.AccessLog[0]
	if al.GetName() != OTelAccessLogName {
		t.Fatalf("name=%s", al.GetName())
	}
	if al.GetFilter() != nil {
		t.Fatal("HCM filter must be omitted; Collector drops non-event bodies")
	}
}

func TestHasOTelAccessLog_IgnoresPlatformAPM(t *testing.T) {
	cfg, err := anypb.New(&otelaccesslog.OpenTelemetryAccessLogConfig{StatPrefix: "gateway"})
	if err != nil {
		t.Fatal(err)
	}
	mgr := &hcm.HttpConnectionManager{
		AccessLog: []*accesslog.AccessLog{{
			Name:       OTelAccessLogName,
			ConfigType: &accesslog.AccessLog_TypedConfig{TypedConfig: cfg},
		}},
	}
	if HasOTelAccessLog(mgr) {
		t.Fatal("platform APM logger must not count as kubeWAF")
	}
}

func TestAppendOTelAccessLog_PreservesFileLogger(t *testing.T) {
	mgr := &hcm.HttpConnectionManager{
		AccessLog: []*accesslog.AccessLog{{Name: "envoy.access_loggers.file"}},
	}
	if err := AppendOTelAccessLog(mgr, config.DefaultOTelCluster); err != nil {
		t.Fatal(err)
	}
	if len(mgr.AccessLog) != 2 {
		t.Fatalf("len=%d", len(mgr.AccessLog))
	}
	if mgr.AccessLog[0].GetName() != "envoy.access_loggers.file" {
		t.Fatal("must not replace existing file logger")
	}
	if err := AppendOTelAccessLog(mgr, config.DefaultOTelCluster); err != nil {
		t.Fatal(err)
	}
	if len(mgr.AccessLog) != 2 {
		t.Fatalf("second inject not idempotent: %d", len(mgr.AccessLog))
	}
}

func TestOTelAccessLogMap_OmitsHCMFilter(t *testing.T) {
	m := OTelAccessLogMap("")
	if _, ok := m["filter"]; ok {
		t.Fatalf("HCM filter must be omitted, got %v", m["filter"])
	}
	tc := m["typed_config"].(map[string]any)
	body := tc["body"].(map[string]any)["string_value"].(string)
	if body != "%FILTER_STATE("+FilterStateEventKey+":PLAIN)%" {
		t.Fatalf("body=%s", body)
	}
}

func TestOTelAccessLogMap_NoOTelClientFields(t *testing.T) {
	m := OTelAccessLogMap("")
	if m["name"] != OTelAccessLogName {
		t.Fatalf("%v", m["name"])
	}
	tc := m["typed_config"].(map[string]any)
	gs := tc["grpc_service"].(map[string]any)
	if gs["envoy_grpc"].(map[string]any)["cluster_name"] != config.DefaultOTelCluster {
		t.Fatalf("%v", gs)
	}
	if _, ok := m["httpCall"]; ok {
		t.Fatal("must not mention httpCall")
	}
}

func TestEnsureCluster(t *testing.T) {
	c, err := MakeOTelCluster("h", 4317)
	if err != nil {
		t.Fatal(err)
	}
	out := EnsureCluster(nil, c)
	out = EnsureCluster(out, c)
	if len(out) != 1 {
		t.Fatalf("len=%d", len(out))
	}
}
