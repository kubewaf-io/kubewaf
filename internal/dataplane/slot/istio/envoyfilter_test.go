package istio

import (
	"context"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	wafv1beta1 "github.com/kubewaf-io/kubewaf/api/waf/v1beta1"
	"github.com/kubewaf-io/kubewaf/internal/dataplane/config"
)

func istioScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := wafv1beta1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	return s
}

func istioManagedWAF(name, ns string) *wafv1beta1.WAF {
	return &wafv1beta1.WAF{
		TypeMeta:   metav1.TypeMeta{APIVersion: "waf.kubewaf.io/v1beta1", Kind: "WAF"},
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: wafv1beta1.WAFSpec{
			Provider:  &wafv1beta1.WAFProvider{Type: wafv1beta1.ProviderIstio},
			Telemetry: &wafv1beta1.WAFTelemetry{Mode: wafv1beta1.TelemetryModeManaged},
		},
	}
}

func accessLogEF(ns string, selector map[string]any) *unstructured.Unstructured {
	ef := &unstructured.Unstructured{}
	ef.SetGroupVersionKind(envoyFilterGVK)
	ef.SetNamespace(ns)
	ef.SetName(AccessLogResourceName())
	spec := map[string]any{"priority": int64(10)}
	if selector != nil {
		spec["workloadSelector"] = map[string]any{"labels": selector}
	}
	_ = unstructured.SetNestedMap(ef.Object, spec, "spec")
	return ef
}

func portable(name string, managed bool) *config.PortableConfig {
	const ns = "ns"
	return &config.PortableConfig{
		Name:                  name,
		Namespace:             ns,
		ExtensionName:         "kubewaf/" + ns + "/" + name,
		ECDSCluster:           "kubewaf_ecds",
		ECDSHost:              "ecds.svc",
		ECDSPort:              18001,
		TelemetryManaged:      managed,
		IstioWorkloadSelector: map[string]string{"app": name},
	}
}

func TestResourceName(t *testing.T) {
	if got := ResourceName("shop"); got != "kubewaf-shop" {
		t.Fatalf("got %q", got)
	}
}

func TestBuildSpec_OTelClusterNoPerWAFAccessLog(t *testing.T) {
	p := &config.PortableConfig{
		Name:             "shop",
		Namespace:        "ns",
		ExtensionName:    "kubewaf/ns/shop",
		ECDSCluster:      "kubewaf_ecds",
		ECDSHost:         "ecds.svc",
		ECDSPort:         18001,
		OTelHost:         "otel.svc",
		OTelPort:         4317,
		TelemetryManaged: true,
	}
	spec := buildSpec(p)
	patches, _ := spec["configPatches"].([]any)
	var hasOTel, hasECDS, hasAccessLog bool
	for _, raw := range patches {
		m := raw.(map[string]any)
		if m["applyTo"] == "CLUSTER" {
			val := m["patch"].(map[string]any)["value"].(map[string]any)
			switch val["name"] {
			case "kubewaf_otel":
				hasOTel = true
				opts := val["typed_extension_protocol_options"].(map[string]any)
				http := opts["envoy.extensions.upstreams.http.v3.HttpProtocolOptions"].(map[string]any)
				if _, ok := http["explicit_http_config"].(map[string]any)["http2_protocol_options"]; !ok {
					t.Fatal("otel cluster missing http2")
				}
			case "kubewaf_ecds":
				hasECDS = true
			}
		}
		if m["applyTo"] == "NETWORK_FILTER" && m["patch"].(map[string]any)["operation"] == "MERGE" {
			hasAccessLog = true
		}
	}
	if !hasOTel || !hasECDS {
		t.Fatalf("otel=%v ecds=%v", hasOTel, hasECDS)
	}
	if hasAccessLog {
		t.Fatal("per-WAF EnvoyFilter must not MERGE access_log (singleton owns it)")
	}

	alog := buildAccessLogSpec()
	if _, ok := alog["workloadSelector"]; ok {
		t.Fatal("singleton must omit workloadSelector")
	}
	if AccessLogResourceName() != "kubewaf-otel-access-log" {
		t.Fatal(AccessLogResourceName())
	}
	if len(alog["configPatches"].([]any)) != 1 {
		t.Fatal("singleton must have one MERGE")
	}
	match := alog["configPatches"].([]any)[0].(map[string]any)["match"].(map[string]any)
	if _, ok := match["context"]; ok {
		t.Fatal("singleton must omit match.context")
	}
	patch := alog["configPatches"].([]any)[0].(map[string]any)
	logs := patch["patch"].(map[string]any)["value"].(map[string]any)["typed_config"].(map[string]any)["access_log"].([]any)
	if len(logs) != 1 {
		t.Fatalf("access_log=%v", logs)
	}
	if _, ok := logs[0].(map[string]any)["filter"]; ok {
		t.Fatalf("HCM filter must be omitted: %v", logs[0])
	}
}

func TestBuildSpec_NoOTelWhenHostEmpty(t *testing.T) {
	p := &config.PortableConfig{
		Name:          "shop",
		Namespace:     "ns",
		ExtensionName: "kubewaf/ns/shop",
		ECDSCluster:   "kubewaf_ecds",
		ECDSHost:      "ecds.svc",
		ECDSPort:      18001,
	}
	spec := buildSpec(p)
	for _, raw := range spec["configPatches"].([]any) {
		m := raw.(map[string]any)
		if m["applyTo"] != "CLUSTER" {
			continue
		}
		val := m["patch"].(map[string]any)["value"].(map[string]any)
		if val["name"] == "kubewaf_otel" {
			t.Fatal("otel cluster must not be added without host")
		}
	}
}

func TestEnsureOTelAccessLogStripsWorkloadSelector(t *testing.T) {
	ctx := context.Background()
	existing := accessLogEF("ns", map[string]any{"app": "wrong"})
	c := fake.NewClientBuilder().WithScheme(istioScheme(t)).WithRuntimeObjects(existing).Build()
	if err := EnsureOTelAccessLogEnvoyFilter(ctx, c, portable("shop", true)); err != nil {
		t.Fatal(err)
	}
	got := &unstructured.Unstructured{}
	got.SetGroupVersionKind(envoyFilterGVK)
	if err := c.Get(ctx, client.ObjectKey{Name: AccessLogResourceName(), Namespace: "ns"}, got); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := unstructured.NestedMap(got.Object, "spec", "workloadSelector"); ok {
		t.Fatal("CreateOrUpdate must strip workloadSelector")
	}
}

func TestEnsureOTelAccessLogEnvoyFilterSingleton(t *testing.T) {
	ctx := context.Background()
	c := fake.NewClientBuilder().WithScheme(istioScheme(t)).Build()
	p := portable("shop", true)
	if err := EnsureOTelAccessLogEnvoyFilter(ctx, c, p); err != nil {
		t.Fatal(err)
	}
	got := &unstructured.Unstructured{}
	got.SetGroupVersionKind(envoyFilterGVK)
	if err := c.Get(ctx, client.ObjectKey{Name: AccessLogResourceName(), Namespace: "ns"}, got); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := unstructured.NestedMap(got.Object, "spec", "workloadSelector"); ok {
		t.Fatal("singleton must omit workloadSelector")
	}
	if got.GetLabels()["kubewaf.io/component"] != "otel-access-log" {
		t.Fatalf("labels=%v", got.GetLabels())
	}
	if err := EnsureOTelAccessLogEnvoyFilter(ctx, c, portable("other", true)); err != nil {
		t.Fatal(err)
	}
	list := &unstructured.UnstructuredList{}
	list.SetGroupVersionKind(envoyFilterGVK)
	if err := c.List(ctx, list, client.InNamespace("ns")); err != nil {
		t.Fatal(err)
	}
	if len(list.Items) != 1 {
		t.Fatalf("want one singleton, got %d", len(list.Items))
	}
}

func TestEnsureOTelAccessLogEnvoyFilterSkipsUnmanaged(t *testing.T) {
	ctx := context.Background()
	c := fake.NewClientBuilder().WithScheme(istioScheme(t)).Build()
	if err := EnsureOTelAccessLogEnvoyFilter(ctx, c, portable("shop", false)); err != nil {
		t.Fatal(err)
	}
	got := &unstructured.Unstructured{}
	got.SetGroupVersionKind(envoyFilterGVK)
	err := c.Get(ctx, client.ObjectKey{Name: AccessLogResourceName(), Namespace: "ns"}, got)
	if !apierrors.IsNotFound(err) {
		t.Fatalf("unmanaged must not create singleton: %v", err)
	}
}

func TestMaybeDeleteOTelAccessLogKeepsOtherManaged(t *testing.T) {
	ctx := context.Background()
	other := istioManagedWAF("other", "ns")
	c := fake.NewClientBuilder().WithScheme(istioScheme(t)).WithObjects(other).Build()
	if err := EnsureOTelAccessLogEnvoyFilter(ctx, c, portable("shop", true)); err != nil {
		t.Fatal(err)
	}
	if err := MaybeDeleteOTelAccessLogEnvoyFilter(ctx, c, "ns", "shop"); err != nil {
		t.Fatal(err)
	}
	got := &unstructured.Unstructured{}
	got.SetGroupVersionKind(envoyFilterGVK)
	if err := c.Get(ctx, client.ObjectKey{Name: AccessLogResourceName(), Namespace: "ns"}, got); err != nil {
		t.Fatal(err)
	}
}

func TestMaybeDeleteOTelAccessLogRemovesLast(t *testing.T) {
	ctx := context.Background()
	c := fake.NewClientBuilder().WithScheme(istioScheme(t)).Build()
	if err := EnsureOTelAccessLogEnvoyFilter(ctx, c, portable("shop", true)); err != nil {
		t.Fatal(err)
	}
	if err := MaybeDeleteOTelAccessLogEnvoyFilter(ctx, c, "ns", "shop"); err != nil {
		t.Fatal(err)
	}
	got := &unstructured.Unstructured{}
	got.SetGroupVersionKind(envoyFilterGVK)
	err := c.Get(ctx, client.ObjectKey{Name: AccessLogResourceName(), Namespace: "ns"}, got)
	if !apierrors.IsNotFound(err) {
		t.Fatalf("last Managed WAF must delete singleton: %v", err)
	}
}
