package observability

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func chartDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs(filepath.Join("..", "..", "..", "charts", "kubewaf"))
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

func helmBin(t *testing.T) string {
	t.Helper()
	if p := os.Getenv("HELM"); p != "" {
		return p
	}
	if p, err := exec.LookPath("helm"); err == nil {
		return p
	}
	if _, err := os.Stat("/data/bin/helm"); err == nil {
		return "/data/bin/helm"
	}
	t.Skip("helm not found")
	return ""
}

func TestHelmManagedFailWithoutBackend(t *testing.T) {
	out, err := exec.Command(helmBin(t), "template", "t", chartDir(t),
		"--set", "observability.managed.enabled=true",
		"--set", "observability.managed.victoriaMetrics.enabled=false",
		"--set", "observability.managed.prometheusRemoteWrite.enabled=false",
	).CombinedOutput()
	if err == nil || !strings.Contains(string(out), "requires victoriaMetrics") {
		t.Fatalf("want fail: %s err=%v", out, err)
	}
}

func TestHelmManagedRendersCMAndNoCiliumBit(t *testing.T) {
	out, err := exec.Command(helmBin(t), "template", "t", chartDir(t),
		"--set", "observability.managed.enabled=true",
		"--set", "observability.managed.victoriaMetrics.enabled=true",
	).CombinedOutput()
	if err != nil {
		t.Fatal(string(out), err)
	}
	s := string(out)
	if !strings.Contains(s, "name: kubewaf-managed-observability") {
		t.Fatal("missing well-known CM")
	}
	if !strings.Contains(s, "injectConfigured:") {
		t.Fatal("missing injectConfigured")
	}
	if strings.Contains(s, "ciliumOtelMerged") {
		t.Fatal("Helm must not write ciliumOtelMerged")
	}
	if !strings.Contains(s, "prometheusremotewrite") {
		t.Fatal("in-cluster VM must use prometheusremotewrite to /api/v1/write")
	}
	if !strings.Contains(s, "/api/v1/write") {
		t.Fatal("in-cluster VM remote_write URL missing")
	}
	if !strings.Contains(s, `^kubewaf_waf[._].*`) {
		t.Fatal("collector filter must accept tag-extracted kubewaf_waf.* names")
	}
	if !strings.Contains(s, "storageDataPath=/victoria-metrics-data") {
		t.Fatal("VM must mount writable storage")
	}
	if strings.Contains(s, "transform/waf_spans") {
		t.Fatal("lite must not enable the span transform")
	}
}

func TestHelmManagedRemoteWriteExporter(t *testing.T) {
	out, err := exec.Command(helmBin(t), "template", "t", chartDir(t),
		"--set", "observability.managed.enabled=true",
		"--set", "observability.managed.victoriaMetrics.enabled=false",
		"--set", "observability.managed.prometheusRemoteWrite.enabled=true",
		"--set", "observability.managed.prometheusRemoteWrite.endpoint=http://prom:9090/api/v1/write",
	).CombinedOutput()
	if err != nil {
		t.Fatal(string(out), err)
	}
	if !strings.Contains(string(out), "prometheusremotewrite") {
		t.Fatal("expected prometheusremotewrite exporter")
	}
	if strings.Contains(string(out), "metrics_endpoint: \"http://prom:9090/api/v1/write\"") {
		t.Fatal("must not send remote_write URL to otlphttp")
	}
}

func TestHelmManagedFullRendersVictoriaTraces(t *testing.T) {
	out, err := exec.Command(helmBin(t), "template", "t", chartDir(t),
		"--set", "observability.managed.enabled=true",
		"--set", "observability.managed.profile=full",
		"--set", "observability.managed.victoriaMetrics.enabled=true",
		"--set", "observability.managed.victoriaTraces.enabled=true",
	).CombinedOutput()
	if err != nil {
		t.Fatal(string(out), err)
	}
	s := string(out)
	if !strings.Contains(s, "victoria-traces") {
		t.Fatal("full profile must render VictoriaTraces")
	}
	if !strings.Contains(s, "tracesBackend: \"victoriaTraces\"") {
		t.Fatal("managed CM must record tracesBackend")
	}
	if !strings.Contains(s, "profile: \"full\"") {
		t.Fatal("managed CM must record profile=full")
	}
	if !strings.Contains(s, "transform/waf_spans") || !strings.Contains(s, "otlpjson") {
		t.Fatal("full profile must convert access-log records to waf.eval traces")
	}
	if !strings.Contains(s, "filter/span_json") {
		t.Fatal("full profile must drop non-span log bodies before otlpjson")
	}
	if !strings.Contains(s, "storageDataPath=/victoria-metrics-data") {
		t.Fatal("VM needs a writable storage path under readOnlyRootFilesystem")
	}
	if strings.Contains(s, "kind: PrometheusRule") {
		t.Fatal("helm template without Prometheus CRD must not emit PrometheusRule")
	}
	if strings.Contains(s, "00000000000000000000000000000001") || strings.Contains(s, "a1b2c3d4e5f60708") {
		t.Fatal("collector must not emit hard-coded eval IDs")
	}
	if !strings.Contains(s, `"events"`) {
		t.Fatal("collector transform must emit span events")
	}
	if strings.Contains(s, "replace_all_patterns(") {
		t.Fatal("cache fields are strings; collector 0.128 replace_all_patterns needs a map + mode")
	}
	if !strings.Contains(s, `ParseJSON(cache["raw"])`) {
		t.Fatal("collector must ParseJSON(String(body)); Envoy may deliver bytes")
	}
	if strings.Contains(s, `Len(cache["evt"]["matches"])`) {
		t.Fatal("unguarded Len(matches) fails when matches is missing and drops the log")
	}
	if !strings.Contains(s, `"0000000000000000"`) {
		t.Fatal("empty parentSpanId is invalid OTLP hex; default to 16 zeros")
	}
	if !strings.Contains(s, `replace_pattern(cache["e0_msg"]`) ||
		!strings.Contains(s, `replace_pattern(cache["path"]`) ||
		!strings.Contains(s, `replace_pattern(cache["action"]`) ||
		!strings.Contains(s, `replace_pattern(cache["e0_data"]`) {
		t.Fatal("collector must JSON-escape msg/data/path/action")
	}
	if !strings.Contains(s, "metricsQueryService:") || !strings.Contains(s, "evalIds: \"v1\"") {
		t.Fatal("managed CM must record query service keys and evalIds")
	}
	if !strings.Contains(s, "deleteAuthKey") || !strings.Contains(s, "--deleteAuthKey") {
		t.Fatal("VM must set deleteAuthKey")
	}
	if !strings.Contains(s, "app.kubernetes.io/component: subresource-api") {
		t.Fatal("query NP must allow subresource-api")
	}
	if strings.Contains(s, "fromEntities:\n        - cluster") && strings.Contains(s, "port: \"8428\"") {
		t.Fatal("Cilium query ports must not default to fromEntities [cluster]")
	}
}

func TestHelmSubresourceAPIWithoutProbeTestServer(t *testing.T) {
	out, err := exec.Command(helmBin(t), "template", "t", chartDir(t),
		"--set", "subresourceApi.enabled=true",
		"--set", "subresourceApi.probes.enabled=false",
		"--set", "subresourceApi.directives.enabled=true",
		"--set", "probeTestServer.enabled=false",
		"--set", "observability.managed.enabled=true",
		"--set", "observability.managed.victoriaMetrics.enabled=true",
	).CombinedOutput()
	if err != nil {
		t.Fatal(string(out), err)
	}
	s := string(out)
	if !strings.Contains(s, "kind: APIService") {
		t.Fatal("APIService must render without probe test server")
	}
	if strings.Contains(s, "--enable-probes=true") {
		t.Fatal("probes must be off")
	}
	if !strings.Contains(s, "--enable-directives=true") || !strings.Contains(s, "--enable-query=true") {
		t.Fatal("directives/query must stay on")
	}
	if !strings.Contains(s, "--metrics-backend-url=") {
		t.Fatal("query backend URL missing")
	}
	if strings.Contains(s, "--test-server-token-file") {
		t.Fatal("eval token must not be required when probes are off")
	}
	if strings.Contains(s, "app.kubernetes.io/component: probe-test-server") {
		t.Fatal("query/directives-only install must not deploy probe-test-server")
	}
}

func TestHelmSubresourceAPIProbesStillRequireTestServer(t *testing.T) {
	out, err := exec.Command(helmBin(t), "template", "t", chartDir(t),
		"--set", "subresourceApi.enabled=true",
		"--set", "subresourceApi.probes.enabled=true",
		"--set", "probeTestServer.enabled=false",
	).CombinedOutput()
	if err == nil || !strings.Contains(string(out), "probeTestServer.enabled must be true") {
		t.Fatalf("want fail when probes on without test server: %s err=%v", out, err)
	}
}

func TestHelmManagedOffNoCM(t *testing.T) {
	out, err := exec.Command(helmBin(t), "template", "t", chartDir(t)).CombinedOutput()
	if err != nil {
		t.Fatal(string(out), err)
	}
	if strings.Contains(string(out), "kubewaf-managed-observability") {
		t.Fatal("managed off must not render CM")
	}
}
