package waf

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	wafv1beta1 "github.com/kubewaf-io/kubewaf/api/waf/v1beta1"
)

func TestIsObservabilityConfigMap(t *testing.T) {
	if !isObservabilityConfigMap("kubewaf-managed-observability") || !isObservabilityConfigMap("kubewaf-cilium-otel") {
		t.Fatal("expected well-known names")
	}
	if isObservabilityConfigMap("other") {
		t.Fatal("must ignore unrelated ConfigMaps")
	}
}

func TestApplyTelemetrySinkOmitsWhenNone(t *testing.T) {
	w := &wafv1beta1.WAF{
		ObjectMeta: metav1.ObjectMeta{Name: "w", Generation: 1},
		Spec:       wafv1beta1.WAFSpec{},
	}
	r := &WAFReconciler{}
	r.applyTelemetrySink(t.Context(), w)
	if c := findCond(w, ConditionTypeTelemetrySink); c != nil {
		t.Fatalf("expected omitted condition, got %+v", c)
	}

	w.Spec.Telemetry = &wafv1beta1.WAFTelemetry{Mode: wafv1beta1.TelemetryModeNone}
	r.applyTelemetrySink(t.Context(), w)
	if c := findCond(w, ConditionTypeTelemetrySink); c != nil {
		t.Fatalf("None must omit TelemetrySink, got %+v", c)
	}
}

func TestEvaluateTelemetrySinkRules(t *testing.T) {
	t.Setenv("NAMESPACE", "kubewaf-system")
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	helm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: managedObservabilityCM, Namespace: "kubewaf-system"},
		Data:       map[string]string{"enabled": "true", "injectConfigured": "true"},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(helm).Build()
	st, reason, _ := evaluateTelemetrySink(t.Context(), c, wafv1beta1.ProviderEnvoyGateway)
	if st != metav1.ConditionTrue || reason != "Ready" {
		t.Fatalf("EG: status=%s reason=%s", st, reason)
	}

	st, reason, _ = evaluateTelemetrySink(t.Context(), c, wafv1beta1.ProviderCilium)
	if st != metav1.ConditionFalse || reason != "OTelClusterMissing" {
		t.Fatalf("Cilium without remesh: status=%s reason=%s", st, reason)
	}

	otel := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: ciliumOTelCM, Namespace: "kubewaf-system"},
		Data:       map[string]string{"ciliumOtelMerged": "true"},
	}
	c = fake.NewClientBuilder().WithScheme(scheme).WithObjects(helm, otel).Build()
	st, reason, _ = evaluateTelemetrySink(t.Context(), c, wafv1beta1.ProviderCilium)
	if st != metav1.ConditionTrue || reason != "Ready" {
		t.Fatalf("Cilium remeshed: status=%s reason=%s", st, reason)
	}

	empty := fake.NewClientBuilder().WithScheme(scheme).Build()
	st, reason, _ = evaluateTelemetrySink(t.Context(), empty, wafv1beta1.ProviderIstio)
	if st != metav1.ConditionFalse || reason != "Absent" {
		t.Fatalf("missing CM: status=%s reason=%s", st, reason)
	}

	degraded := helm.DeepCopy()
	degraded.Data["injectConfigured"] = "false"
	c = fake.NewClientBuilder().WithScheme(scheme).WithObjects(degraded).Build()
	st, reason, _ = evaluateTelemetrySink(t.Context(), c, wafv1beta1.ProviderIstio)
	if st != metav1.ConditionFalse || reason != "Degraded" {
		t.Fatalf("degraded: status=%s reason=%s", st, reason)
	}

	disabled := helm.DeepCopy()
	disabled.Data["enabled"] = "false"
	c = fake.NewClientBuilder().WithScheme(scheme).WithObjects(disabled).Build()
	for _, p := range []wafv1beta1.ProviderType{wafv1beta1.ProviderEnvoyGateway, wafv1beta1.ProviderCilium} {
		st, reason, _ = evaluateTelemetrySink(t.Context(), c, p)
		if st != metav1.ConditionFalse || reason != "Absent" {
			t.Fatalf("enabled=false %s: %s %s", p, st, reason)
		}
	}

	falseRemesh := otel.DeepCopy()
	falseRemesh.Data["ciliumOtelMerged"] = "false"
	c = fake.NewClientBuilder().WithScheme(scheme).WithObjects(helm, falseRemesh).Build()
	st, reason, _ = evaluateTelemetrySink(t.Context(), c, wafv1beta1.ProviderCilium)
	if st != metav1.ConditionFalse || reason != "OTelClusterMissing" {
		t.Fatalf("remesh false: %s %s", st, reason)
	}

	// Cilium remeshed is Ready even if injectConfigured is false (bootstrap is the remesh).
	helmNoInject := helm.DeepCopy()
	helmNoInject.Data["injectConfigured"] = "false"
	c = fake.NewClientBuilder().WithScheme(scheme).WithObjects(helmNoInject, otel).Build()
	st, reason, _ = evaluateTelemetrySink(t.Context(), c, wafv1beta1.ProviderCilium)
	if st != metav1.ConditionTrue || reason != "Ready" {
		t.Fatalf("Cilium remesh ignores injectConfigured: %s %s", st, reason)
	}
}

func TestApplyTelemetrySinkManagedWritesAndRemoves(t *testing.T) {
	t.Setenv("NAMESPACE", "kubewaf-system")
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	helm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: managedObservabilityCM, Namespace: "kubewaf-system"},
		Data:       map[string]string{"enabled": "true", "injectConfigured": "true"},
	}
	r := &WAFReconciler{Client: fake.NewClientBuilder().WithScheme(scheme).WithObjects(helm).Build()}
	w := &wafv1beta1.WAF{
		ObjectMeta: metav1.ObjectMeta{Name: "w", Generation: 2},
		Spec:       wafv1beta1.WAFSpec{Telemetry: &wafv1beta1.WAFTelemetry{Mode: wafv1beta1.TelemetryModeManaged}},
		Status:     wafv1beta1.WAFStatus{Provider: wafv1beta1.ProviderEnvoyGateway},
	}
	meta.SetStatusCondition(&w.Status.Conditions, metav1.Condition{Type: "Ready", Status: metav1.ConditionTrue, Reason: "Ready"})
	r.applyTelemetrySink(t.Context(), w)
	c := findCond(w, ConditionTypeTelemetrySink)
	if c == nil || c.Status != metav1.ConditionTrue {
		t.Fatalf("expected TelemetrySink True, got %+v", c)
	}
	if findCond(w, "Ready").Status != metav1.ConditionTrue {
		t.Fatal("Ready must be unchanged")
	}
	w.Spec.Telemetry.Mode = wafv1beta1.TelemetryModeNone
	r.applyTelemetrySink(t.Context(), w)
	if findCond(w, ConditionTypeTelemetrySink) != nil {
		t.Fatal("Managed→None must remove TelemetrySink")
	}
}

func TestRequestsForManagedWAFs(t *testing.T) {
	list := &wafv1beta1.WAFList{Items: []wafv1beta1.WAF{
		{ObjectMeta: metav1.ObjectMeta{Name: "m", Namespace: "ns"}, Spec: wafv1beta1.WAFSpec{Telemetry: &wafv1beta1.WAFTelemetry{Mode: wafv1beta1.TelemetryModeManaged}}},
		{ObjectMeta: metav1.ObjectMeta{Name: "n", Namespace: "ns"}, Spec: wafv1beta1.WAFSpec{Telemetry: &wafv1beta1.WAFTelemetry{Mode: wafv1beta1.TelemetryModeNone}}},
	}}
	keys := requestsForManagedWAFs(list)
	if len(keys) != 1 || keys[0].Name != "m" {
		t.Fatalf("keys=%v", keys)
	}
}

func findCond(w *wafv1beta1.WAF, typ string) *metav1.Condition {
	for i := range w.Status.Conditions {
		if w.Status.Conditions[i].Type == typ {
			return &w.Status.Conditions[i]
		}
	}
	return nil
}
