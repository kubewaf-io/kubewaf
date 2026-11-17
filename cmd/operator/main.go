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

// Command operator runs the v1alpha1 SecLang controllers.
// charts/kubewaf-v1alpha1 starts this binary. charts/kubewaf still starts cmd/main.
// This binary does not serve ECDS or Wasm.
package main

import (
	"crypto/tls"
	"flag"
	"os"

	egv1a1 "github.com/envoyproxy/gateway/api/v1alpha1"
	seclangv1alpha1 "github.com/kubewaf-io/kubewaf/api/seclang/v1alpha1"
	v1alpha1 "github.com/kubewaf-io/kubewaf/internal/controller/v1alpha1"
	"github.com/kubewaf-io/kubewaf/internal/provider/registry"
	kubewafwebhook "github.com/kubewaf-io/kubewaf/internal/webhook"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(seclangv1alpha1.AddToScheme(scheme))
	utilruntime.Must(egv1a1.AddToScheme(scheme))
	utilruntime.Must(gatewayv1.Install(scheme))
	utilruntime.Must(v1alpha1.AddProtectionScheme(scheme))
}

func main() {
	var metricsAddr, probeAddr, webhookCertPath, proxyNamespace string
	var enableLeaderElection, enableWebhooks bool
	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080", "metrics bind address")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "health probe bind address")
	flag.BoolVar(&enableLeaderElection, "leader-elect", true, "run reconcilers only on the leader")
	flag.BoolVar(&enableWebhooks, "enable-webhooks", false, "register validating webhooks")
	flag.StringVar(&webhookCertPath, "webhook-cert-path", "", "directory with tls.crt and tls.key")
	flag.StringVar(&proxyNamespace, "proxy-namespace", "envoy-gateway-system", "namespace of the platform Envoy pods and the kubewaf-seclang ConfigMap")
	opts := zap.Options{Development: true}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()
	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	hook := webhook.NewServer(webhook.Options{TLSOpts: []func(*tls.Config){}})
	if webhookCertPath != "" {
		hook = webhook.NewServer(webhook.Options{CertDir: webhookCertPath})
	}
	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsserver.Options{BindAddress: metricsAddr},
		HealthProbeBindAddress: probeAddr,
		WebhookServer:          hook,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "seclang.kubewaf.io",
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}
	reg := registry.New(proxyNamespace)
	if err := (&v1alpha1.SecRuleReconciler{Client: mgr.GetClient(), Scheme: mgr.GetScheme()}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "SecRule")
		os.Exit(1)
	}
	if err := (&v1alpha1.SecActionReconciler{Client: mgr.GetClient(), Scheme: mgr.GetScheme()}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "SecAction")
		os.Exit(1)
	}
	if err := (&v1alpha1.IncludeReconciler{Client: mgr.GetClient(), Scheme: mgr.GetScheme()}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "Include")
		os.Exit(1)
	}
	if err := (&v1alpha1.SecPolicyReconciler{
		Client: mgr.GetClient(), Scheme: mgr.GetScheme(), Registry: reg, ProxyNamespace: proxyNamespace,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "SecPolicy")
		os.Exit(1)
	}
	if enableWebhooks {
		if err := kubewafwebhook.SetupV1Alpha1(mgr); err != nil {
			setupLog.Error(err, "webhooks")
			os.Exit(1)
		}
	}
	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "healthz")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "readyz")
		os.Exit(1)
	}
	setupLog.Info("starting v1alpha1 operator", "proxy-namespace", proxyNamespace)
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}
