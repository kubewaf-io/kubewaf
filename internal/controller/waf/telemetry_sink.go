/*
Copyright 2025 Buzz-IT GmbH.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package waf

import (
	"context"
	"os"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	wafv1beta1 "github.com/kubewaf-io/kubewaf/api/waf/v1beta1"
)

const (
	// ConditionTypeTelemetrySink is True/False Ready|Degraded|Absent. Does not gate Ready.
	ConditionTypeTelemetrySink = "TelemetrySink"

	managedObservabilityCM = "kubewaf-managed-observability"
	ciliumOTelCM           = "kubewaf-cilium-otel"
)

// applyTelemetrySink sets or omits TelemetrySink. Missing sink ≠ Ready false.
func (r *WAFReconciler) applyTelemetrySink(ctx context.Context, waf *wafv1beta1.WAF) {
	if waf.Spec.Telemetry == nil || waf.Spec.Telemetry.Mode != wafv1beta1.TelemetryModeManaged {
		meta.RemoveStatusCondition(&waf.Status.Conditions, ConditionTypeTelemetrySink)
		return
	}
	st, reason, msg := evaluateTelemetrySink(ctx, r.Client, waf.Status.Provider)
	meta.SetStatusCondition(&waf.Status.Conditions, metav1.Condition{
		Type:               ConditionTypeTelemetrySink,
		Status:             st,
		Reason:             reason,
		Message:            msg,
		ObservedGeneration: waf.Generation,
	})
}

func evaluateTelemetrySink(ctx context.Context, c client.Client, provider wafv1beta1.ProviderType) (metav1.ConditionStatus, string, string) {
	ns := operatorNamespace()
	var helm corev1.ConfigMap
	err := c.Get(ctx, types.NamespacedName{Name: managedObservabilityCM, Namespace: ns}, &helm)
	if err != nil {
		return metav1.ConditionFalse, "Absent", "managed observability ConfigMap missing or disabled"
	}
	if helm.Data["enabled"] != "true" {
		return metav1.ConditionFalse, "Absent", "managed observability is disabled"
	}
	if provider == wafv1beta1.ProviderCilium {
		var otel corev1.ConfigMap
		if err := c.Get(ctx, types.NamespacedName{Name: ciliumOTelCM, Namespace: ns}, &otel); err != nil ||
			otel.Data["ciliumOtelMerged"] != "true" {
			return metav1.ConditionFalse, "OTelClusterMissing", "Cilium remesh missing (ciliumOtelMerged!=true)"
		}
		return metav1.ConditionTrue, "Ready", "Cilium bootstrap includes kubewaf_otel"
	}
	if helm.Data["injectConfigured"] == "true" {
		return metav1.ConditionTrue, "Ready", "Envoy OTel inject is configured"
	}
	return metav1.ConditionFalse, "Degraded", "managed observability enabled but inject is not configured"
}

func operatorNamespace() string {
	if ns := os.Getenv("NAMESPACE"); ns != "" {
		return ns
	}
	if ns := os.Getenv("POD_NAMESPACE"); ns != "" {
		return ns
	}
	return "kubewaf-system"
}

func isObservabilityConfigMap(name string) bool {
	return name == managedObservabilityCM || name == ciliumOTelCM
}

func requestsForManagedWAFs(list *wafv1beta1.WAFList) []client.ObjectKey {
	if list == nil {
		return nil
	}
	var keys []client.ObjectKey
	for i := range list.Items {
		w := &list.Items[i]
		if w.Spec.Telemetry != nil && w.Spec.Telemetry.Mode == wafv1beta1.TelemetryModeManaged {
			keys = append(keys, client.ObjectKey{Name: w.Name, Namespace: w.Namespace})
		}
	}
	return keys
}
