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

package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/metrics/filters"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	envoygatewayv1alpha1 "github.com/envoyproxy/gateway/api/v1alpha1"
	seclangv1beta1 "github.com/kubewaf-io/kubewaf/api/seclang/v1beta1"
	wafv1beta1 "github.com/kubewaf-io/kubewaf/api/waf/v1beta1"
	seclangcontroller "github.com/kubewaf-io/kubewaf/internal/controller/seclang"
	wafcontroller "github.com/kubewaf-io/kubewaf/internal/controller/waf"
	"github.com/kubewaf-io/kubewaf/internal/dataplane/config"
	"github.com/kubewaf-io/kubewaf/internal/dataplane/ecds"
	"github.com/kubewaf-io/kubewaf/internal/dataplane/engine"
	"github.com/kubewaf-io/kubewaf/internal/dataplane/extensionserver"
	"github.com/kubewaf-io/kubewaf/internal/dataplane/sync"
	"github.com/kubewaf-io/kubewaf/internal/dataplane/wasmserve"
	"github.com/kubewaf-io/kubewaf/internal/metrics"
	kubewafwebhook "github.com/kubewaf-io/kubewaf/internal/webhook"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"
	// +kubebuilder:scaffold:imports
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))

	utilruntime.Must(seclangv1beta1.AddToScheme(scheme))
	utilruntime.Must(wafv1beta1.AddToScheme(scheme))
	utilruntime.Must(envoygatewayv1alpha1.AddToScheme(scheme))
	// Gateway API types for provider auto-discovery (Gateway / GatewayClass / HTTPRoute).
	utilruntime.Must(gwapiv1.Install(scheme))
	// +kubebuilder:scaffold:scheme
}

// nolint:gocyclo
func main() {
	var metricsAddr string
	var metricsCertPath, metricsCertName, metricsCertKey string
	var webhookCertPath, webhookCertName, webhookCertKey string
	var enableLeaderElection bool
	var probeAddr string
	var secureMetrics, enablePprof bool
	var enableHTTP2 bool
	var ecdsBindAddr string
	var extensionServerBindAddr string
	var ecdsServiceHost string
	var ecdsServicePort uint
	var wasmServeBindAddr string
	var wasmServePort uint
	var enableWebhooks bool
	var otelServiceHost string
	var otelServicePort uint
	var telemetryProfile string
	var telemetrySampleNonDisruptive string
	var telemetrySampleDisruptive string
	var telemetryRedact bool
	var telemetryIncludeMatchData bool
	var tlsOpts []func(*tls.Config)
	flag.StringVar(&metricsAddr, "metrics-bind-address", "0", "The address the metrics endpoint binds to. "+
		"Use :8443 for HTTPS or :8080 for HTTP, or leave as 0 to disable the metrics service.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":10080", "The address the probe endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", true,
		"Enable leader election for controller manager. "+
			"Required for multi-replica Deployments: only the leader writes status/EnvoyFilters; "+
			"every replica still serves ECDS, wasm HTTP, and EG extension hooks.")
	flag.BoolVar(&secureMetrics, "metrics-secure", true,
		"If set, the metrics endpoint is served securely via HTTPS. Use --metrics-secure=false to use HTTP instead.")
	flag.StringVar(&webhookCertPath, "webhook-cert-path", "", "The directory that contains the webhook certificate.")
	flag.StringVar(&webhookCertName, "webhook-cert-name", "tls.crt", "The name of the webhook certificate file.")
	flag.StringVar(&webhookCertKey, "webhook-cert-key", "tls.key", "The name of the webhook key file.")
	flag.StringVar(&metricsCertPath, "metrics-cert-path", "",
		"The directory that contains the metrics server certificate.")
	flag.StringVar(&metricsCertName, "metrics-cert-name", "tls.crt", "The name of the metrics server certificate file.")
	flag.StringVar(&metricsCertKey, "metrics-cert-key", "tls.key", "The name of the metrics server key file.")
	flag.BoolVar(&enableHTTP2, "enable-http2", false,
		"If set, HTTP/2 will be enabled for the metrics and webhook servers")
	flag.BoolVar(
		&enablePprof,
		"enable-pprof",
		false,
		"Enables Pprof endpoint for profiling (not recommend in production)",
	)
	flag.StringVar(&ecdsBindAddr, "ecds-bind-address", ":18001",
		"gRPC bind address for the Extension Config Discovery Service (ECDS) that serves Coraza Wasm configs")
	flag.StringVar(&extensionServerBindAddr, "extension-server-bind-address", ":5005",
		"gRPC bind address for the Envoy Gateway Extension Server (injects ECDS filter slots)")
	flag.StringVar(&ecdsServiceHost, "ecds-service-host", "kubewaf-ecds.kubewaf-system.svc.cluster.local",
		"DNS name Envoy uses to reach the ECDS gRPC service (cluster endpoint address)")
	flag.UintVar(&ecdsServicePort, "ecds-service-port", 18001,
		"Port Envoy uses to reach the ECDS gRPC service")
	flag.StringVar(&wasmServeBindAddr, "wasm-serve-bind-address", ":18002",
		"HTTP bind address for wasm serve (ModSecurity + Challenge)")
	flag.UintVar(&wasmServePort, "wasm-serve-port", 18002,
		"Port advertised in operator-hosted wasm URLs")
	flag.BoolVar(&enableWebhooks, "enable-webhooks", true,
		"Register validating admission webhooks (requires TLS certs via "+
			"--webhook-cert-path and a ValidatingWebhookConfiguration)")
	flag.StringVar(&otelServiceHost, "otel-service-host", "",
		"DNS name Envoy uses for cluster kubewaf_otel (empty = do not CDS-inject)")
	flag.UintVar(&otelServicePort, "otel-service-port", 4317,
		"Port for cluster kubewaf_otel (OTLP/gRPC)")
	flag.StringVar(&telemetryProfile, "telemetry-profile", "lite",
		"Managed telemetry profile (lite|full) used when WAF traces.enabled is unset")
	flag.StringVar(&telemetrySampleNonDisruptive, "telemetry-sample-non-disruptive", "0.25",
		"Default sample rate for non-disruptive WAF matches")
	flag.StringVar(&telemetrySampleDisruptive, "telemetry-sample-disruptive", "1.0",
		"Default sample rate for disruptive WAF interrupts")
	flag.BoolVar(&telemetryRedact, "telemetry-redact", true,
		"Default redact (omit client.address) for managed traces")
	flag.BoolVar(&telemetryIncludeMatchData, "telemetry-include-match-data", false,
		"Default includeMatchData for managed traces")
	// Production logger by default. Pass --zap-devel for development-style logs.
	opts := zap.Options{
		Development: false,
	}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	// if the enable-http2 flag is false (the default), http/2 should be disabled
	// due to its vulnerabilities. More specifically, disabling http/2 will
	// prevent from being vulnerable to the HTTP/2 Stream Cancellation and
	// Rapid Reset CVEs. For more information see:
	// - https://github.com/advisories/GHSA-qppj-fm5r-hxr3
	// - https://github.com/advisories/GHSA-4374-p667-p6c8
	disableHTTP2 := func(c *tls.Config) {
		setupLog.Info("disabling http/2")
		c.NextProtos = []string{"http/1.1"}
	}

	if !enableHTTP2 {
		tlsOpts = append(tlsOpts, disableHTTP2)
	}

	// Initial webhook TLS options
	webhookTLSOpts := tlsOpts
	webhookServerOptions := webhook.Options{
		TLSOpts: webhookTLSOpts,
	}

	if len(webhookCertPath) > 0 {
		setupLog.Info("Initializing webhook certificate watcher using provided certificates",
			"webhook-cert-path", webhookCertPath, "webhook-cert-name", webhookCertName, "webhook-cert-key", webhookCertKey)

		webhookServerOptions.CertDir = webhookCertPath
		webhookServerOptions.CertName = webhookCertName
		webhookServerOptions.KeyName = webhookCertKey
	}

	webhookServer := webhook.NewServer(webhookServerOptions)

	// Metrics endpoint is enabled in 'config/default/kustomization.yaml'. The Metrics options configure the server.
	// More info:
	// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.22.4/pkg/metrics/server
	// - https://book.kubebuilder.io/reference/metrics.html
	metricsServerOptions := metricsserver.Options{
		BindAddress:   metricsAddr,
		SecureServing: secureMetrics,
		TLSOpts:       tlsOpts,
	}

	if secureMetrics {
		// FilterProvider is used to protect the metrics endpoint with authn/authz.
		// These configurations ensure that only authorized users and service accounts
		// can access the metrics endpoint. The RBAC are configured in 'config/rbac/kustomization.yaml'. More info:
		// https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.22.4/pkg/metrics/filters#WithAuthenticationAndAuthorization
		metricsServerOptions.FilterProvider = filters.WithAuthenticationAndAuthorization
	}

	// If metricsCertPath is empty, controller-runtime may use self-signed certs (dev only).
	// For production, mount cert-manager (or other) TLS material and set --metrics-cert-path.
	if len(metricsCertPath) > 0 {
		setupLog.Info("Initializing metrics certificate watcher using provided certificates",
			"metrics-cert-path", metricsCertPath, "metrics-cert-name", metricsCertName, "metrics-cert-key", metricsCertKey)

		metricsServerOptions.CertDir = metricsCertPath
		metricsServerOptions.CertName = metricsCertName
		metricsServerOptions.KeyName = metricsCertKey
	}

	ctrlOpts := ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsServerOptions,
		WebhookServer:          webhookServer,
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "fb102d45.kubewaf.io",
	}

	// Only bind pprof when explicitly requested (never start a side listener by default).
	if enablePprof {
		ctrlOpts.PprofBindAddress = ":8082"
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrlOpts)
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	if err := (&seclangcontroller.SecRuleReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "SecRule")
		os.Exit(1)
	}
	if err := (&seclangcontroller.SecActionReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "SecAction")
		os.Exit(1)
	}
	if err := (&seclangcontroller.PhraseListReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "PhraseList")
		os.Exit(1)
	}
	if err := (&seclangcontroller.IPListReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "IPList")
		os.Exit(1)
	}
	if err := (&wafcontroller.RuleSetReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "RuleSet")
		os.Exit(1)
	}

	if enableWebhooks {
		if err := kubewafwebhook.SetupWithManager(mgr); err != nil {
			setupLog.Error(err, "unable to create webhooks")
			os.Exit(1)
		}
		setupLog.Info("validating admission webhooks registered",
			"webhook-cert-path", webhookCertPath)
	} else {
		setupLog.Info("validating admission webhooks disabled (--enable-webhooks=false)")
	}

	// Shared dataplane services: ECDS (config push) + wasm HTTP + EG Extension Server.
	// These run on every replica; SnapshotCache is local, so leader election should
	// still be enabled for the reconciler. Envoy will reconnect if a pod restarts.
	runCtx := ctrl.SetupSignalHandler()

	// Wasm HTTP server (ModSecurity + optional Challenge/PoW).
	// Binaries load from the operator image / mount paths under /wasm.
	var wasmServer *wasmserve.Server
	wasmPort := uint32(wasmServePort)
	if wasmPort == 0 {
		wasmPort = 18002
	}
	moduleHTTP := map[engine.ModuleID]string{}
	moduleSHA := map[engine.ModuleID]string{}

	if wasmServeBindAddr != "" {
		wasmServer = wasmserve.New(setupLog)
		modsecPath := resolveWasmFile(engine.DefaultModSecurityFile)
		challengePath := resolveWasmFile(engine.DefaultChallengeFile)
		setupLog.Info("wasm local paths",
			"modsecurity", modsecPath,
			"challenge", challengePath,
			"ko_data_path", os.Getenv("KO_DATA_PATH"),
		)
		loadOpts := wasmserve.Options{
			Modules: []wasmserve.ModuleSource{
				{ID: engine.ModuleModSecurity, File: modsecPath},
				{ID: engine.ModuleChallenge, File: challengePath},
			},
		}
		if err := wasmServer.Load(runCtx, loadOpts); err != nil {
			setupLog.Error(err, "wasm module load (continuing; missing engines return 503)")
		}
		if err := mgr.Add(wasmserve.Runnable{Server: wasmServer, BindAddr: wasmServeBindAddr}); err != nil {
			setupLog.Error(err, "unable to add wasm HTTP server")
			os.Exit(1)
		}
		// Only advertise HTTP URL + SHA for modules that actually loaded.
		// Envoy rejects remote Wasm code with empty sha256; advertising a URL
		// for a missing module produces 503 fetches and invalid ECDS configs.
		for _, m := range engine.AllModules() {
			if !wasmServer.Has(m.ID) {
				setupLog.Info("wasm module not loaded (skipping ECDS defaults)", "id", m.ID)
				continue
			}
			moduleHTTP[m.ID] = wasmserve.PublicURLFor(ecdsServiceHost, wasmPort, m.ID)
			moduleSHA[m.ID] = wasmServer.SHA256(m.ID)
		}
		setupLog.Info("operator-hosted wasm modules",
			"modsecurity", moduleHTTP[engine.ModuleModSecurity],
			"challenge", moduleHTTP[engine.ModuleChallenge],
			"modsecurity_sha", moduleSHA[engine.ModuleModSecurity],
			"challenge_sha", moduleSHA[engine.ModuleChallenge],
		)
	}

	ecdsServer := ecds.New(runCtx, setupLog)
	if err := mgr.Add(ecds.Runnable{Server: ecdsServer, BindAddr: ecdsBindAddr}); err != nil {
		setupLog.Error(err, "unable to add ECDS server")
		os.Exit(1)
	}

	buildOpts := config.BuildOptions{
		DefaultECDSHost:     ecdsServiceHost,
		DefaultECDSPort:     uint32(ecdsServicePort),
		DefaultModuleHTTP:   moduleHTTP,
		DefaultModuleSHA256: moduleSHA,
		DefaultWasmHTTPURL:  moduleHTTP[engine.ModuleModSecurity],
		DefaultWasmSHA256:   moduleSHA[engine.ModuleModSecurity],
		DefaultOTelHost:     otelServiceHost,
		DefaultOTelPort:     uint32(otelServicePort),
		TelemetryDefaults: config.TelemetryDefaults{
			Profile:             telemetryProfile,
			SampleNonDisruptive: telemetrySampleNonDisruptive,
			SampleDisruptive:    telemetrySampleDisruptive,
			Redact:              telemetryRedact,
			IncludeMatchData:    telemetryIncludeMatchData,
		},
	}

	egExtServer := extensionserver.New(setupLog, mgr.GetClient(), buildOpts)
	if err := mgr.Add(extensionserver.Runnable{Server: egExtServer, BindAddr: extensionServerBindAddr}); err != nil {
		setupLog.Error(err, "unable to add Envoy Gateway extension server")
		os.Exit(1)
	}

	if err := (&wafcontroller.WAFReconciler{
		Client:      mgr.GetClient(),
		Scheme:      mgr.GetScheme(),
		ECDS:        ecdsServer,
		EGExtension: egExtServer,
		BuildOpts:   buildOpts,
		//nolint:staticcheck // SA1019: controller still uses record.EventRecorder
		Recorder: mgr.GetEventRecorderFor("waf-controller"),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "Failed to create controller", "controller", "WAF")
		os.Exit(1)
	}

	// Non-leader-elected: keep ECDS + EG extension indexes warm on every replica
	// so Service load-balancing to any pod returns current config.
	if err := (&sync.Reconciler{
		Client:      mgr.GetClient(),
		Scheme:      mgr.GetScheme(),
		ECDS:        ecdsServer,
		EGExtension: egExtServer,
		BuildOpts:   buildOpts,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "Failed to create controller", "controller", "WAFDataplaneSync")
		os.Exit(1)
	}
	// +kubebuilder:scaffold:builder

	// Start the inventory metrics updater (leader-elected background task)
	inventoryUpdater := metrics.NewInventoryUpdater(mgr.GetClient(), 60*time.Second)
	if err := mgr.Add(inventoryUpdater); err != nil {
		setupLog.Error(err, "unable to add inventory updater")
		os.Exit(1)
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	setupLog.Info("starting manager",
		"ecds", ecdsBindAddr,
		"extensionServer", extensionServerBindAddr,
		"wasmServe", wasmServeBindAddr,
		"ecdsService", fmt.Sprintf("%s:%d", ecdsServiceHost, ecdsServicePort),
	)
	if err := mgr.Start(runCtx); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}

// resolveWasmFile picks the on-disk wasm path for a module default path.
//
// Order:
//  1. path if it exists (absolute or relative)
//  2. $KO_DATA_PATH/wasm/<basename> (ko embeds cmd/kodata into the image)
//  3. $KO_DATA_PATH/<basename>
//  4. original path unchanged (Load reports missing modules)
func resolveWasmFile(configured string) string {
	if configured == "" {
		return ""
	}
	if _, err := os.Stat(configured); err == nil {
		return configured
	}
	base := filepath.Base(configured)
	if kodata := os.Getenv("KO_DATA_PATH"); kodata != "" {
		for _, cand := range []string{
			filepath.Join(kodata, "wasm", base),
			filepath.Join(kodata, base),
		} {
			if _, err := os.Stat(cand); err == nil {
				return cand
			}
		}
	}
	return configured
}
