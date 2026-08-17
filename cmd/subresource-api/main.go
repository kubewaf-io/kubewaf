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

// Command subresource-api is the kubeWAF Subresource API Server
// (aggregated extension for subresources.kubewaf.io). Capability-agnostic shell;
// v1 capability is probes. Not named probe-api (K1b).
package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/kubernetes"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"

	seclangv1beta1 "github.com/kubewaf-io/kubewaf/api/seclang/v1beta1"
	wafv1beta1 "github.com/kubewaf-io/kubewaf/api/waf/v1beta1"
	"github.com/kubewaf-io/kubewaf/internal/probeassemble"
	"github.com/kubewaf-io/kubewaf/internal/subresourceapi"
)

type cliFlags struct {
	bindAddr, authMode, devUser  string
	testServerURL, testTokenFile string
	testToken                    string
	skipKube                     bool
	perNS, globalMax             int
	queryPerNS, queryGlobal      int
	tlsCert, tlsKey              string
	requestHeaderClientCA        string
	requestHeaderAllowedNames    string
	enableProbes                 bool
	enableDirectives             bool
	enableQuery                  bool
	metricsBackendURL            string
	tracesBackendURL             string
}

func parseFlags() cliFlags {
	var f cliFlags
	flag.StringVar(&f.bindAddr, "bind-address", ":8444", "HTTP(S) listen address")
	flag.StringVar(&f.authMode, "authentication", "requestheader", "Auth mode: requestheader | insecure-dev")
	flag.StringVar(&f.devUser, "dev-user", "system:anonymous", "Identity in insecure-dev mode")
	flag.StringVar(&f.testServerURL, "test-server-url", "http://127.0.0.1:8080", "Test HTTP Server base URL")
	flag.StringVar(&f.testTokenFile, "test-server-token-file", "", "Path to shared bearer token file")
	flag.StringVar(&f.testToken, "test-server-token", "", "Shared bearer token (dev)")
	flag.BoolVar(&f.skipKube, "skip-kube", false, "Dev-only: skip kube client")
	flag.IntVar(&f.perNS, "per-namespace-concurrency", 4, "Max in-flight probes per namespace")
	flag.IntVar(&f.globalMax, "global-max-in-flight", subresourceapi.DefaultGlobalMaxInFlight, "Max concurrent probes process-wide")
	flag.IntVar(&f.queryPerNS, "query-per-namespace-concurrency", subresourceapi.DefaultQueryPerNamespace, "Max in-flight metrics/traces queries per namespace")
	flag.IntVar(&f.queryGlobal, "query-global-max-in-flight", subresourceapi.DefaultQueryGlobalMax, "Max concurrent metrics/traces queries process-wide")
	flag.StringVar(&f.tlsCert, "tls-cert-file", "", "TLS certificate file (required for requestheader)")
	flag.StringVar(&f.tlsKey, "tls-private-key-file", "", "TLS private key file (required for requestheader)")
	flag.StringVar(&f.requestHeaderClientCA, "requestheader-client-ca-file", "", "CA bundle to verify aggregator client certs")
	flag.StringVar(&f.requestHeaderAllowedNames, "requestheader-allowed-names", "", "Comma-separated allowed client cert CN/DNS SANs")
	flag.BoolVar(&f.enableProbes, "enable-probes", true, "Register /probes (requires test server)")
	flag.BoolVar(&f.enableDirectives, "enable-directives", true, "Register GET …/wafs/{name}/directives")
	flag.BoolVar(&f.enableQuery, "enable-query", true, "Register GET …/metrics, /traces, /clustermetrics")
	flag.StringVar(&f.metricsBackendURL, "metrics-backend-url", "", "VictoriaMetrics base URL (http://svc:8428)")
	flag.StringVar(&f.tracesBackendURL, "traces-backend-url", "", "VictoriaTraces base URL (http://svc:10428)")
	flag.Parse()
	return f
}

func loadEvalToken(log *slog.Logger, token, tokenFile, authMode string, probes bool) string {
	if !probes {
		if subresourceapi.AuthMode(authMode) == subresourceapi.AuthInsecureDev {
			log.Warn("INSECURE: authentication=insecure-dev — do not use in production")
		}
		return ""
	}
	if token == "" && tokenFile != "" {
		b, err := os.ReadFile(tokenFile)
		if err != nil {
			log.Error("read test server token", "err", err)
			os.Exit(1)
		}
		token = strings.TrimSpace(string(b))
	}
	if subresourceapi.AuthMode(authMode) != subresourceapi.AuthInsecureDev && token == "" {
		log.Error("test server token required when probes are enabled")
		os.Exit(1)
	}
	if subresourceapi.AuthMode(authMode) == subresourceapi.AuthInsecureDev {
		log.Warn("INSECURE: authentication=insecure-dev — do not use in production")
	}
	return token
}

func setupKube(log *slog.Logger, skipKube bool) (client.Client, kubernetes.Interface, error) {
	if skipKube {
		return nil, nil, nil
	}
	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(seclangv1beta1.AddToScheme(scheme))
	utilruntime.Must(wafv1beta1.AddToScheme(scheme))
	restCfg, err := config.GetConfig()
	if err != nil {
		log.Warn("kube config unavailable; continuing with stub assembly", "err", err)
		return nil, nil, err
	}
	kclient, err := client.New(restCfg, client.Options{Scheme: scheme})
	if err != nil {
		log.Warn("kube client failed; continuing with stub assembly", "err", err)
		kclient = nil
	}
	kubeClientset, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		log.Warn("kubernetes clientset failed", "err", err)
		kubeClientset = nil
	}
	return kclient, kubeClientset, nil
}

func chooseSAR(log *slog.Logger, auth subresourceapi.AuthMode, kubeClientset kubernetes.Interface, skipKube bool, restCfgErr error) subresourceapi.SARAuthorizer {
	switch {
	case auth == subresourceapi.AuthInsecureDev:
		return subresourceapi.AllowAllSAR{}
	case kubeClientset != nil:
		return &subresourceapi.SubjectAccessReviewSAR{Client: kubeClientset}
	case skipKube:
		log.Warn("skip-kube is dev-only; requestheader uses DenyAllSAR")
		return subresourceapi.DenyAllSAR{}
	default:
		log.Error("requestheader mode requires kube client for SubjectAccessReview", "kubeConfigErr", restCfgErr)
		os.Exit(1)
		return nil
	}
}

func parseAllowedNames(csv string) []string {
	if csv == "" {
		return nil
	}
	var names []string
	for _, n := range strings.Split(csv, ",") {
		n = strings.TrimSpace(n)
		if n != "" {
			names = append(names, n)
		}
	}
	return names
}

func requestHeaderTLS(log *slog.Logger, tlsCert, tlsKey, caFile string) *tls.Config {
	if tlsCert == "" || tlsKey == "" {
		log.Error("requestheader mode requires -tls-cert-file and -tls-private-key-file")
		os.Exit(1)
	}
	if caFile == "" {
		log.Error("requestheader mode requires -requestheader-client-ca-file")
		os.Exit(1)
	}
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		log.Error("read requestheader client CA", "err", err)
		os.Exit(1)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		log.Error("no certificates found in requestheader-client-ca-file")
		os.Exit(1)
	}
	// VerifyClientCertIfGiven so kubelet HTTPS probes work; API still requires peer cert.
	return &tls.Config{
		ClientCAs:  pool,
		ClientAuth: tls.VerifyClientCertIfGiven,
		MinVersion: tls.VersionTLS12,
	}
}

func main() {
	f := parseFlags()
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	f.authMode = strings.TrimSpace(strings.ToLower(f.authMode))
	if subresourceapi.AuthMode(f.authMode) != subresourceapi.AuthRequestHeader &&
		subresourceapi.AuthMode(f.authMode) != subresourceapi.AuthInsecureDev {
		log.Error("invalid -authentication; use requestheader or insecure-dev", "got", f.authMode)
		os.Exit(1)
	}
	f.testToken = loadEvalToken(log, f.testToken, f.testTokenFile, f.authMode, f.enableProbes)
	if f.enableProbes {
		if u, err := url.Parse(f.testServerURL); err == nil {
			host := u.Hostname()
			if u.Scheme == "http" && host != "127.0.0.1" && host != "localhost" && host != "::1" {
				log.Warn("test-server-url is cleartext HTTP to a non-loopback host", "url", f.testServerURL)
			}
		}
	}

	kclient, kubeClientset, restCfgErr := setupKube(log, f.skipKube)
	var dataProvider probeassemble.ListBodyProvider
	if kclient != nil {
		dataProvider = &probeassemble.ClientListProvider{Client: kclient}
	}
	auth := subresourceapi.AuthRequestHeader
	if subresourceapi.AuthMode(f.authMode) == subresourceapi.AuthInsecureDev {
		auth = subresourceapi.AuthInsecureDev
	}
	sar := chooseSAR(log, auth, kubeClientset, f.skipKube, restCfgErr)
	var tlsConfig *tls.Config
	if auth == subresourceapi.AuthRequestHeader {
		tlsConfig = requestHeaderTLS(log, f.tlsCert, f.tlsKey, f.requestHeaderClientCA)
	}

	var evalClient subresourceapi.EvalClient
	if f.enableProbes {
		evalClient = subresourceapi.NewHTTPEvalClient(f.testServerURL, f.testToken)
	}
	var query *subresourceapi.QueryBackend
	if f.enableQuery && (f.metricsBackendURL != "" || f.tracesBackendURL != "") {
		query = subresourceapi.NewQueryBackend(f.metricsBackendURL, f.tracesBackendURL)
	}
	srv := subresourceapi.NewServer(subresourceapi.Config{
		Auth:                         auth,
		DevUser:                      f.devUser,
		EvalClient:                   evalClient,
		Client:                       kclient,
		SAR:                          sar,
		PerNamespaceConcurrency:      f.perNS,
		GlobalMaxInFlight:            f.globalMax,
		PerNamespaceQueryConcurrency: f.queryPerNS,
		GlobalQueryMaxInFlight:       f.queryGlobal,
		Logger:                       log,
		DataFiles:                    dataProvider,
		SkipAssembly:                 kclient == nil,
		RequestHeaderAllowedNames:    parseAllowedNames(f.requestHeaderAllowedNames),
		DisableProbes:                !f.enableProbes,
		DisableDirectives:            !f.enableDirectives,
		DisableQuery:                 !f.enableQuery,
		Query:                        query,
	})

	httpSrv := &http.Server{
		Addr:              f.bindAddr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       35 * time.Second,
		WriteTimeout:      40 * time.Second,
		IdleTimeout:       90 * time.Second,
		TLSConfig:         tlsConfig,
	}

	go func() {
		log.Info("subresource-api listening",
			"addr", f.bindAddr,
			"auth", f.authMode,
			"testServer", f.testServerURL,
			"tls", tlsConfig != nil,
		)
		var err error
		if f.tlsCert != "" && f.tlsKey != "" {
			err = httpSrv.ListenAndServeTLS(f.tlsCert, f.tlsKey)
		} else {
			err = httpSrv.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			log.Error("listen failed", "err", err)
			os.Exit(1)
		}
	}()

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	sig := <-ch
	log.Info("shutting down", "signal", fmt.Sprintf("%v", sig))
	_ = httpSrv.Close()
}
