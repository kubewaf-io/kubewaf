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

package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

const (
	// MetricsNamespace is the Prometheus namespace for all kubeWAF metrics.
	MetricsNamespace = "kubewaf"
)

// WAF metrics
var (
	// WAFTotal reports the total number of WAF resources.
	WAFTotal = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: MetricsNamespace,
			Name:      "waf_total",
			Help:      "Total number of WAF resources in the cluster",
		},
		[]string{"namespace"},
	)

	// WAFReady reports whether a WAF is Ready (1) or not (0).
	WAFReady = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: MetricsNamespace,
			Name:      "waf_ready",
			Help:      "Readiness status of WAF resources (1 = Ready, 0 = not Ready)",
		},
		[]string{"namespace", "name"},
	)

	// WAFCRSEnabled reports whether CRS is enabled on a WAF policy.
	WAFCRSEnabled = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: MetricsNamespace,
			Name:      "waf_crs_enabled",
			Help:      "Whether OWASP CRS is enabled on a WAF (1 = enabled)",
		},
		[]string{"namespace", "name"},
	)

	// RulesLoaded reports how many SecRules were successfully resolved and loaded for a policy.
	RulesLoaded = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: MetricsNamespace,
			Name:      "rules_loaded",
			Help:      "Number of SecRules loaded after reference resolution for a WAF policy",
		},
		[]string{"namespace", "name", "policy_type"},
	)

	// RuleSetTotal reports the total number of RuleSet resources.
	RuleSetTotal = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: MetricsNamespace,
			Name:      "ruleset_total",
			Help:      "Total number of RuleSet resources",
		},
		[]string{"namespace"},
	)

	// SecRuleTotal reports the total number of SecRule resources.
	SecRuleTotal = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: MetricsNamespace,
			Name:      "secrule_total",
			Help:      "Total number of SecRule resources",
		},
		[]string{"namespace"},
	)
)

// Controller reconciliation metrics
var (
	// ReconcileTotal counts reconciliations per controller.
	ReconcileTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: MetricsNamespace,
			Name:      "reconcile_total",
			Help:      "Total number of reconciliations per controller",
		},
		[]string{"controller", "result"},
	)

	// ReconcileDuration tracks how long reconciliations take.
	ReconcileDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: MetricsNamespace,
			Name:      "reconcile_duration_seconds",
			Help:      "Duration of reconcile loops in seconds",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"controller"},
	)

	// ReferenceResolveErrors counts reference resolution failures.
	ReferenceResolveErrors = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: MetricsNamespace,
			Name:      "reference_resolve_errors_total",
			Help:      "Total number of reference resolution errors during reconciliation",
		},
		[]string{"controller", "namespace", "name"},
	)
)

// RegisterMetrics registers all custom metrics with the controller-runtime registry.
func RegisterMetrics() {
	metrics.Registry.MustRegister(
		WAFTotal,
		WAFReady,
		WAFCRSEnabled,
		RulesLoaded,
		RuleSetTotal,
		SecRuleTotal,
		ReconcileTotal,
		ReconcileDuration,
		ReferenceResolveErrors,
	)
}

func init() {
	RegisterMetrics()
}
