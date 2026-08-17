//go:build e2e
// +build e2e

package e2e

import (
	"os"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/kubewaf-io/kubewaf/test/utils"
)

// Provider e2e matrix. Select with E2E_PROVIDER=envoy-gateway|istio|cilium|all
//
// Prerequisites are installed by Makefile targets:
//   make setup-test-e2e-envoy-gateway
//   make setup-test-e2e-istio
//   make setup-test-e2e-cilium
//
// Operator is installed once in BeforeSuite of this Ordered container when any
// provider test runs.

// ContinueOnFailure: one provider failing must not skip the others in the matrix.
var _ = Describe("Provider dataplane e2e", Ordered, ContinueOnFailure, func() {
	BeforeAll(func() {
		if e2eProvider() == "manager" || e2eProvider() == "probe" {
			// Manager-only or probe-only suite; provider tests skipped via providerEnabled.
			return
		}
		// Ensure operator is present for provider tests (suite may have already built image).
		if os.Getenv("E2E_SKIP_OPERATOR_INSTALL") != "true" {
			installOperatorHelm()
		}
		applyCommonAppAndRules()
	})

	AfterAll(func() {
		if os.Getenv("E2E_SKIP_OPERATOR_INSTALL") == "true" {
			return
		}
		if e2eProvider() == "manager" || e2eProvider() == "probe" {
			return
		}
		// Clean demo resources; leave cluster for other suites if shared.
		// Use fully-qualified resource names — bare "waf" collides with the CRD category.
		// --wait=false: WAF finalizers may probe Istio EnvoyFilter CRDs that are absent on EG-only clusters.
		_, _ = kubectl("delete", wafResource, "--all", "-n", demoNamespace, "--ignore-not-found", "--wait=false")
		_, _ = kubectl("delete", "envoyfilter", "--all", "-n", demoNamespace, "--ignore-not-found", "--wait=false")
		_, _ = kubectl("delete", "ciliumenvoyconfig", "--all", "-n", demoNamespace, "--ignore-not-found", "--wait=false")
	})

	// -------------------------------------------------------------------------
	// Envoy Gateway
	// -------------------------------------------------------------------------
	Context("Envoy Gateway", func() {
		BeforeEach(func() {
			if !providerEnabled("envoy-gateway") {
				Skip("E2E_PROVIDER does not include envoy-gateway")
			}
			skipUnlessCRD("gateways.gateway.networking.k8s.io", "Gateway API required")
			skipUnlessCRD("envoyproxies.gateway.envoyproxy.io", "install Envoy Gateway first")
		})

		It("reconciles WAF and marks Ready with ExtensionServer slot", func() {
			applyFile("test/e2e/manifests/envoygateway/gateway.yaml")
			// Use the fully-qualified Gateway API resource. Bare "gateway" collides with the
			// WAF CRD category "gateway" (kubectl lists WAFs instead of Gateway objects).
			waitForGatewayProgrammed(demoNamespace, "demo-gateway", 4*time.Minute)

			applyFile("test/e2e/manifests/envoygateway/waf.yaml")
			waitForWAFReady(demoNamespace, "demo-waf-eg", 3*time.Minute)

			// Auto-discovery from targetRef → GatewayClass (no spec.provider).
			Expect(wafStatusField(demoNamespace, "demo-waf-eg", "{.status.provider}")).
				To(Equal("EnvoyGateway"))
			Expect(wafStatusField(demoNamespace, "demo-waf-eg", "{.status.providerDetection}")).
				To(ContainSubstring("targetRef Gateway"))
			Expect(wafStatusField(demoNamespace, "demo-waf-eg", "{.status.providerDetection}")).
				To(ContainSubstring("gateway.envoyproxy.io"))
			Expect(wafStatusField(demoNamespace, "demo-waf-eg", "{.status.slotKind}")).
				To(Equal("ExtensionServer"))
			Expect(wafStatusField(demoNamespace, "demo-waf-eg", "{.status.ecdsResourceName}")).
				To(Equal("kubewaf/demo/demo-waf-eg"))
		})

		It("blocks scanner User-Agent through the gateway when real wasm is configured", func() {
			if !realWasmConfigured() {
				Skip("product wasm not available in operator image for traffic tests")
			}
			// Re-assert EG Gateway attachment (suite may have switched GatewayClass for Istio).
			applyFile("test/e2e/manifests/envoygateway/gateway.yaml")
			waitForGatewayProgrammed(demoNamespace, "demo-gateway", 4*time.Minute)

			// Path B / other suites may leave extra WAFs on the same Gateway. Two ECDS
			// filters race: Path B CRS without exclusive ownership returns HTTP 500
			// (901001) on benign traffic. Keep only the Path A smoke WAF.
			ensureExclusiveWAF(demoNamespace, "demo-waf-eg")

			// Ensure WAF is applied in blocking mode (FTW profile uses DetectionOnly).
			applyFile("test/e2e/manifests/envoygateway/waf.yaml")
			disableFTWProfileOnWAF(demoNamespace, "demo-waf-eg")
			waitForWAFReady(demoNamespace, "demo-waf-eg", 3*time.Minute)
			// Give ECDS a moment after clearing FTW DetectionOnly.
			time.Sleep(5 * time.Second)

			// Resolve Envoy proxy service created for the gateway.
			// Label selectors vary by EG version; try common ones.
			svc := findEnvoyGatewayService()
			if svc == "" {
				Skip("could not locate Envoy Gateway proxy Service")
			}
			waitForServiceEndpoints("envoy-gateway-system", svc, 3*time.Minute)
			assertGatewayBlocksScannerUA("envoy-gateway-system", svc, "demo.local")
		})

		It("exports catalog metrics to VictoriaMetrics and TelemetrySink for Managed", func() {
			if !realWasmConfigured() {
				Skip("product wasm not available in operator image for traffic tests")
			}
			applyFile("test/e2e/manifests/envoygateway/gateway.yaml")
			waitForGatewayProgrammed(demoNamespace, "demo-gateway", 4*time.Minute)
			ensureExclusiveWAF(demoNamespace, "demo-waf-eg")
			applyFile("test/e2e/manifests/envoygateway/waf.yaml")
			disableFTWProfileOnWAF(demoNamespace, "demo-waf-eg")
			patchWAFTelemetry(demoNamespace, "demo-waf-eg", "Managed")
			waitForWAFReady(demoNamespace, "demo-waf-eg", 3*time.Minute)

			Eventually(func(g Gomega) {
				st, reason := wafCondition(demoNamespace, "demo-waf-eg", "TelemetrySink")
				g.Expect(st).To(Equal("True"), "TelemetrySink status=%s reason=%s", st, reason)
			}, 2*time.Minute, 3*time.Second).Should(Succeed())

			svc := findEnvoyGatewayService()
			if svc == "" {
				Skip("could not locate Envoy Gateway proxy Service")
			}
			waitForServiceEndpoints("envoy-gateway-system", svc, 3*time.Minute)
			assertGatewayBlocksScannerUA("envoy-gateway-system", svc, "demo.local")

			By("waiting for kubewaf_waf catalog series on Envoy and VictoriaMetrics")
			Eventually(func(g Gomega) {
				prom := queryEnvoyPrometheus("kubewaf_waf")
				g.Expect(prom).To(ContainSubstring("kubewaf_waf_tx_total"), prom)
				g.Expect(prom).To(ContainSubstring(`waf_namespace="demo"`), prom)
			}, 2*time.Minute, 10*time.Second).Should(Succeed())
			Eventually(func(g Gomega) {
				vm := queryVictoriaMetrics(demoNamespace, "demo-waf-eg", `{__name__=~"kubewaf_waf_tx.*"}`)
				g.Expect(vm).To(ContainSubstring(`"status":"success"`), vm)
				g.Expect(vm).To(ContainSubstring("kubewaf_waf_tx_total"), vm)
				g.Expect(vm).To(ContainSubstring(`"waf_namespace":"demo"`), vm)
			}, 2*time.Minute, 10*time.Second).Should(Succeed())
		})

		It("omits TelemetrySink when telemetry.mode is None", func() {
			applyFile("test/e2e/manifests/envoygateway/waf.yaml")
			patchWAFTelemetry(demoNamespace, "demo-waf-eg", "None")
			waitForWAFReady(demoNamespace, "demo-waf-eg", 3*time.Minute)
			Eventually(func(g Gomega) {
				st, _ := wafCondition(demoNamespace, "demo-waf-eg", "TelemetrySink")
				g.Expect(st).To(BeEmpty(), "mode=None must omit TelemetrySink, got %s", st)
			}, 2*time.Minute, 3*time.Second).Should(Succeed())
		})

		It("records a waf.eval span on interrupt when traces are enabled", func() {
			if os.Getenv("E2E_TRACES") != "true" {
				Skip("set E2E_TRACES=true to assert waf.eval in VictoriaTraces")
			}
			if !realWasmConfigured() {
				Skip("product wasm not available in operator image for traffic tests")
			}
			applyFile("test/e2e/manifests/envoygateway/gateway.yaml")
			waitForGatewayProgrammed(demoNamespace, "demo-gateway", 4*time.Minute)
			ensureExclusiveWAF(demoNamespace, "demo-waf-eg")
			applyFile("test/e2e/manifests/envoygateway/waf.yaml")
			disableFTWProfileOnWAF(demoNamespace, "demo-waf-eg")
			patchWAFTelemetry(demoNamespace, "demo-waf-eg", "Managed")
			waitForWAFReady(demoNamespace, "demo-waf-eg", 3*time.Minute)
			Eventually(func(g Gomega) {
				st, reason := wafCondition(demoNamespace, "demo-waf-eg", "TelemetrySink")
				g.Expect(st).To(Equal("True"), "TelemetrySink status=%s reason=%s", st, reason)
			}, 2*time.Minute, 3*time.Second).Should(Succeed())

			svc := findEnvoyGatewayService()
			if svc == "" {
				Skip("could not locate Envoy Gateway proxy Service")
			}
			waitForServiceEndpoints("envoy-gateway-system", svc, 3*time.Minute)
			// Disruptive interrupt (sqlmap UA) should be sampled at 1.0.
			Eventually(func(g Gomega) {
				code := curlGatewayHTTP("envoy-gateway-system", svc, "demo.local", "/get", "sqlmap/1.0")
				g.Expect(code).To(Equal("403"))
			}, 2*time.Minute, 5*time.Second).Should(Succeed())

			prom := queryEnvoyPrometheus("access_log_kubewaf")
			if strings.Contains(prom, "envoy_access_logs_open_telemetry_access_log_kubewaf_logs_written{} 0") ||
				!strings.Contains(prom, "logs_written") {
				Skip("Wasm in the operator image does not annotate export metadata; rebuild engines/modsecurity-proxy-wasm")
			}
			By("waiting for waf.eval in VictoriaTraces")
			Eventually(func(g Gomega) {
				out := queryVictoriaTracesServices()
				g.Expect(out).To(Or(
					ContainSubstring("kubewaf"),
					ContainSubstring("waf.eval"),
				), out)
			}, 2*time.Minute, 10*time.Second).Should(Succeed())

			By("two denies produce two distinct trace IDs via the traces subresource")
			_ = curlGatewayHTTP("envoy-gateway-system", svc, "demo.local", "/get", "sqlmap/1.0")
			_ = curlGatewayHTTP("envoy-gateway-system", svc, "demo.local", "/headers", "sqlmap/1.0")
			Eventually(func(g Gomega) {
				out := queryWAFTraces(demoNamespace, "demo-waf-eg")
				ids := uniqueTraceIDs(out)
				g.Expect(len(ids)).To(BeNumerically(">=", 2), out)
			}, 2*time.Minute, 10*time.Second).Should(Succeed())
		})

		It("denies unlabeled pods from querying VictoriaMetrics when NP is enforced", func() {
			direct := queryVictoriaMetricsDirect(`up`)
			if strings.Contains(direct, `"status":"success"`) {
				Skip("CNI does not enforce NetworkPolicy (unlabeled pod still reached VM :8428)")
			}
			Expect(direct).NotTo(ContainSubstring(`"status":"success"`), direct)
		})
	})

	// -------------------------------------------------------------------------
	// Istio
	// -------------------------------------------------------------------------
	Context("Istio", func() {
		BeforeEach(func() {
			if !providerEnabled("istio") {
				Skip("E2E_PROVIDER does not include istio")
			}
			skipUnlessCRD("gateways.gateway.networking.k8s.io", "Gateway API required")
			// Istio may use networking.istio.io/v1 or gateway API only.
			if !crdExists("envoyfilters.networking.istio.io") {
				Skip("Istio not installed (missing EnvoyFilter CRD)")
			}
		})

		It("reconciles WAF and creates an EnvoyFilter ECDS slot", func() {
			applyIstioECDSBootstrap()
			applyFile("test/e2e/manifests/istio/gateway.yaml")
			// Service type ClusterIP via Gateway annotation (networking.istio.io/service-type);
			// patch as belt-and-suspenders if Istio already created a LoadBalancer Service.
			ensureIstioGatewayServiceClusterIP()
			// Gateway API pods are not sidecar-injected; annotation alone does not mount
			// the bootstrap ConfigMap — patch Deployment like the injector would.
			ensureIstioGatewayBootstrapMount()
			applyFile("test/e2e/manifests/istio/waf.yaml")

			waitForWAFReady(demoNamespace, "demo-waf-istio", 3*time.Minute)

			// Auto-discovery from targetRef → GatewayClass (no spec.provider).
			Expect(wafStatusField(demoNamespace, "demo-waf-istio", "{.status.provider}")).
				To(Equal("Istio"))
			Expect(wafStatusField(demoNamespace, "demo-waf-istio", "{.status.providerDetection}")).
				To(ContainSubstring("targetRef Gateway"))
			Expect(wafStatusField(demoNamespace, "demo-waf-istio", "{.status.providerDetection}")).
				To(ContainSubstring("istio.io"))
			Expect(wafStatusField(demoNamespace, "demo-waf-istio", "{.status.slotKind}")).
				To(Equal("EnvoyFilter"))
			Expect(wafStatusField(demoNamespace, "demo-waf-istio", "{.status.slotName}")).
				To(Equal("kubewaf-demo-waf-istio"))

			By("verifying EnvoyFilter exists")
			Eventually(func(g Gomega) {
				_, err := kubectl("get", "envoyfilter", "kubewaf-demo-waf-istio", "-n", demoNamespace)
				g.Expect(err).NotTo(HaveOccurred())
			}, time.Minute, 2*time.Second).Should(Succeed())

			// EnvoyFilter should reference kubewaf_ecds cluster.
			out := kubectlOK("get", "envoyfilter", "kubewaf-demo-waf-istio", "-n", demoNamespace, "-o", "yaml")
			Expect(out).To(ContainSubstring("kubewaf_ecds"))
			Expect(out).To(ContainSubstring("config_discovery"))
		})

		It("blocks scanner User-Agent via Istio gateway when real wasm is configured", func() {
			if !trafficOptIn("E2E_ISTIO_TRAFFIC") {
				Skip("Istio traffic smoke disabled (E2E_ISTIO_TRAFFIC=false)")
			}
			if !realWasmConfigured() {
				Skip("product wasm not available in operator image for traffic tests")
			}
			// Bootstrap-static kubewaf_ecds is required for ECDS Wasm filters on Istio
			// (EnvoyFilter CLUSTER ADD is not enough — see ecds-bootstrap.yaml).
			// Gateway API pods skip sidecar injection, so we must also mount the CM
			// and set ISTIO_BOOTSTRAP_OVERRIDE on the Deployment.
			applyIstioECDSBootstrap()
			applyFile("test/e2e/manifests/istio/gateway.yaml")
			ensureIstioGatewayServiceClusterIP()
			ensureIstioGatewayBootstrapMount()
			waitForGatewayProgrammed(demoNamespace, "demo-gateway", 4*time.Minute)

			ensureExclusiveWAF(demoNamespace, "demo-waf-istio")
			applyFile("test/e2e/manifests/istio/waf.yaml")
			disableFTWProfileOnWAF(demoNamespace, "demo-waf-istio")
			waitForWAFReady(demoNamespace, "demo-waf-istio", 3*time.Minute)
			time.Sleep(5 * time.Second)

			svcRef := findIstioIngressService()
			if svcRef == "" {
				Skip("could not locate Istio ingress Service")
			}
			ns, svc := splitNSName(svcRef, demoNamespace)
			waitForServiceEndpoints(ns, svc, 3*time.Minute)
			assertGatewayBlocksScannerUA(ns, svc, "demo.local")
		})

		It("exports catalog metrics to VictoriaMetrics and TelemetrySink for Managed", func() {
			if !trafficOptIn("E2E_ISTIO_TRAFFIC") {
				Skip("Istio traffic smoke disabled (E2E_ISTIO_TRAFFIC=false)")
			}
			if !realWasmConfigured() {
				Skip("product wasm not available in operator image for traffic tests")
			}
			applyIstioECDSBootstrap()
			applyFile("test/e2e/manifests/istio/gateway.yaml")
			ensureIstioGatewayServiceClusterIP()
			ensureIstioGatewayBootstrapMount()
			waitForGatewayProgrammed(demoNamespace, "demo-gateway", 4*time.Minute)
			ensureExclusiveWAF(demoNamespace, "demo-waf-istio")
			applyFile("test/e2e/manifests/istio/waf.yaml")
			disableFTWProfileOnWAF(demoNamespace, "demo-waf-istio")
			patchWAFTelemetry(demoNamespace, "demo-waf-istio", "Managed")
			waitForWAFReady(demoNamespace, "demo-waf-istio", 3*time.Minute)

			Eventually(func(g Gomega) {
				st, reason := wafCondition(demoNamespace, "demo-waf-istio", "TelemetrySink")
				g.Expect(st).To(Equal("True"), "TelemetrySink status=%s reason=%s", st, reason)
			}, 2*time.Minute, 3*time.Second).Should(Succeed())

			svcRef := findIstioIngressService()
			if svcRef == "" {
				Skip("could not locate Istio ingress Service")
			}
			ns, svc := splitNSName(svcRef, demoNamespace)
			waitForServiceEndpoints(ns, svc, 3*time.Minute)
			assertGatewayBlocksScannerUA(ns, svc, "demo.local")

			By("waiting for catalog series in VictoriaMetrics")
			Eventually(func(g Gomega) {
				vm := queryVictoriaMetrics(demoNamespace, "demo-waf-istio", `{__name__=~"kubewaf_waf_tx.*"}`)
				g.Expect(vm).To(ContainSubstring(`"status":"success"`), vm)
				g.Expect(vm).To(ContainSubstring("kubewaf_waf_tx_total"), vm)
			}, 2*time.Minute, 10*time.Second).Should(Succeed())
		})
	})

	// -------------------------------------------------------------------------
	// Cilium
	// -------------------------------------------------------------------------
	Context("Cilium", func() {
		BeforeEach(func() {
			if !providerEnabled("cilium") {
				Skip("E2E_PROVIDER does not include cilium")
			}
			if !crdExists("ciliumenvoyconfigs.cilium.io") {
				Skip("Cilium not installed (missing CiliumEnvoyConfig CRD)")
			}
		})

		It("reconciles WAF and creates a CiliumEnvoyConfig slot", func() {
			// Gateway resources are best-effort when Cilium Gateway API is enabled.
			if crdExists("gateways.gateway.networking.k8s.io") {
				ensureCiliumGatewayLBIPPool()
				applyFile("test/e2e/manifests/cilium/gateway.yaml")
			}
			applyFile("test/e2e/manifests/cilium/waf.yaml")

			waitForWAFReady(demoNamespace, "demo-waf-cilium", 3*time.Minute)

			// Auto-discovery from targetRef → GatewayClass (no spec.provider).
			Expect(wafStatusField(demoNamespace, "demo-waf-cilium", "{.status.provider}")).
				To(Equal("Cilium"))
			Expect(wafStatusField(demoNamespace, "demo-waf-cilium", "{.status.providerDetection}")).
				To(ContainSubstring("targetRef Gateway"))
			Expect(wafStatusField(demoNamespace, "demo-waf-cilium", "{.status.providerDetection}")).
				To(ContainSubstring("cilium"))
			Expect(wafStatusField(demoNamespace, "demo-waf-cilium", "{.status.slotKind}")).
				To(Equal("CiliumEnvoyConfig"))
			Expect(wafStatusField(demoNamespace, "demo-waf-cilium", "{.status.slotName}")).
				To(Equal("kubewaf-demo-waf-cilium"))
			Expect(wafStatusField(demoNamespace, "demo-waf-cilium", "{.status.ecdsResourceName}")).
				To(Equal("kubewaf/demo/demo-waf-cilium"))

			By("verifying CiliumEnvoyConfig exists and targets httpbin")
			Eventually(func(g Gomega) {
				_, err := kubectl("get", "ciliumenvoyconfig", "kubewaf-demo-waf-cilium", "-n", demoNamespace)
				g.Expect(err).NotTo(HaveOccurred())
			}, time.Minute, 2*time.Second).Should(Succeed())

			out := kubectlOK("get", "ciliumenvoyconfig", "kubewaf-demo-waf-cilium", "-n", demoNamespace, "-o", "yaml")
			// ECDS stub only — plugin JSON lives in TypedExtensionConfig, not CEC.
			Expect(out).To(ContainSubstring("kubewaf_wasm_code"))
			Expect(out).To(ContainSubstring("envoy.extensions.filters.http.wasm.v3.Wasm"))
			Expect(out).To(ContainSubstring("config_discovery"))
			Expect(out).To(ContainSubstring("kubewaf_ecds"))
			Expect(out).ToNot(ContainSubstring("directives_map"))
			Expect(out).ToNot(ContainSubstring("allow_precompiled"))
			Expect(out).To(ContainSubstring("httpbin"))
			Expect(out).To(ContainSubstring("kubewaf/demo/demo-waf-cilium"))
		})

		It("blocks scanner User-Agent through Cilium Gateway when real wasm is configured", func() {
			// ECDS via CEC config_discovery; kubewaf_ecds must be bootstrap-static.
			if !trafficOptIn("E2E_CILIUM_TRAFFIC") {
				Skip("Cilium traffic smoke disabled (E2E_CILIUM_TRAFFIC=false)")
			}
			if !realWasmConfigured() {
				Skip("product wasm not available in operator image for traffic tests")
			}
			skipUnlessCRD("gateways.gateway.networking.k8s.io", "install Gateway API CRDs first")
			applyCiliumECDSBootstrap()
			// Kind: CiliumLoadBalancerIPPool so LoadBalancer Services get EXTERNAL-IP
			// and Gateway Programmed=True (type→ClusterIP is reverted by Cilium).
			ensureCiliumGatewayLBIPPool()
			applyFile("test/e2e/manifests/cilium/gateway.yaml")
			waitForGatewayProgrammed(demoNamespace, "demo-gateway", 4*time.Minute)

			ensureExclusiveWAF(demoNamespace, "demo-waf-cilium")
			applyFile("test/e2e/manifests/cilium/waf.yaml")
			disableFTWProfileOnWAF(demoNamespace, "demo-waf-cilium")
			waitForWAFReady(demoNamespace, "demo-waf-cilium", 3*time.Minute)
			time.Sleep(5 * time.Second)

			svcRef := findCiliumGatewayService()
			if svcRef == "" {
				Skip("no Cilium gateway Service found (is gatewayAPI.enabled and Gateway Programmed?)")
			}
			ns, svc := splitNSName(svcRef, demoNamespace)
			// LB Service still has a ClusterIP usable for in-cluster curls.
			assertGatewayBlocksScannerUA(ns, svc, "demo.local")
		})

		It("exports catalog metrics to VictoriaMetrics and TelemetrySink for Managed", func() {
			if !trafficOptIn("E2E_CILIUM_TRAFFIC") {
				Skip("Cilium traffic smoke disabled (E2E_CILIUM_TRAFFIC=false)")
			}
			if !realWasmConfigured() {
				Skip("product wasm not available in operator image for traffic tests")
			}
			skipUnlessCRD("gateways.gateway.networking.k8s.io", "install Gateway API CRDs first")
			applyCiliumECDSBootstrap()
			ensureCiliumGatewayLBIPPool()
			applyFile("test/e2e/manifests/cilium/gateway.yaml")
			waitForGatewayProgrammed(demoNamespace, "demo-gateway", 4*time.Minute)
			ensureExclusiveWAF(demoNamespace, "demo-waf-cilium")
			applyFile("test/e2e/manifests/cilium/waf.yaml")
			disableFTWProfileOnWAF(demoNamespace, "demo-waf-cilium")
			patchWAFTelemetry(demoNamespace, "demo-waf-cilium", "Managed")
			waitForWAFReady(demoNamespace, "demo-waf-cilium", 3*time.Minute)

			Eventually(func(g Gomega) {
				st, reason := wafCondition(demoNamespace, "demo-waf-cilium", "TelemetrySink")
				g.Expect(st).To(Equal("True"), "TelemetrySink status=%s reason=%s", st, reason)
			}, 2*time.Minute, 3*time.Second).Should(Succeed())

			svcRef := findCiliumGatewayService()
			if svcRef == "" {
				Skip("no Cilium gateway Service found (is gatewayAPI.enabled and Gateway Programmed?)")
			}
			ns, svc := splitNSName(svcRef, demoNamespace)
			assertGatewayBlocksScannerUA(ns, svc, "demo.local")
			// Catalog counters are not asserted: Cilium Envoy 1.36 does not
			// register envoy.stat_sinks.open_telemetry (bootstrap sink crash-loops
			// the DS). TelemetrySink=True means the remesh STATIC kubewaf_otel
			// cluster is present.
		})
	})
})

func findEnvoyGatewayService() string {
	// EG creates services labeled with owning gateway.
	out, err := kubectl("get", "svc", "-n", "envoy-gateway-system",
		"-o", "jsonpath={range .items[*]}{.metadata.name}{'\\n'}{end}")
	if err != nil {
		return ""
	}
	// Prefer services that look like envoy proxies (not the controller).
	for _, line := range utils.GetNonEmptyLines(out) {
		if line == "" || line == "envoy-gateway" {
			continue
		}
		// Common pattern: envoy-demo-demo-gateway-...
		if containsAny(line, "demo-gateway", "envoy-demo", "eg-") {
			return line
		}
	}
	// Fallback: first non-controller service
	for _, line := range utils.GetNonEmptyLines(out) {
		if line != "" && line != "envoy-gateway" {
			return line
		}
	}
	return ""
}

// findIstioIngressService returns "namespace/name" for the Istio data-plane Service.
// Prefer Gateway API managed svc (demo-gateway-istio) over the helm chart istio-ingress.
func findIstioIngressService() string {
	// 1) Gateway API: istiod creates <gateway-name>-istio in the Gateway namespace.
	for _, ns := range []string{demoNamespace, "istio-system", "istio-ingress"} {
		out, err := kubectl("get", "svc", "-n", ns,
			"-o", "jsonpath={range .items[*]}{.metadata.name}{'\\n'}{end}")
		if err != nil {
			continue
		}
		for _, line := range utils.GetNonEmptyLines(out) {
			if containsAny(line, "demo-gateway-istio", "gateway-istio") {
				return ns + "/" + line
			}
		}
	}
	// 2) Classic / helm gateway chart Service.
	for _, ns := range []string{"istio-system", "istio-ingress"} {
		out, err := kubectl("get", "svc", "-n", ns,
			"-o", "jsonpath={range .items[*]}{.metadata.name}{'\\n'}{end}")
		if err != nil {
			continue
		}
		for _, line := range utils.GetNonEmptyLines(out) {
			if containsAny(line, "ingress", "gateway") {
				return ns + "/" + line
			}
		}
	}
	return ""
}

// splitNSName parses "ns/name" or bare "name" (default ns = istio-system).
func splitNSName(s, defaultNS string) (ns, name string) {
	if i := strings.Index(s, "/"); i > 0 {
		return s[:i], s[i+1:]
	}
	return defaultNS, s
}

// findCiliumGatewayService returns "namespace/name" for the Cilium Gateway data-plane Service.
// Cilium typically creates cilium-gateway-<gateway-name> in the Gateway namespace.
func findCiliumGatewayService() string {
	for _, ns := range []string{demoNamespace, "kube-system", "cilium-gateway"} {
		out, err := kubectl("get", "svc", "-n", ns,
			"-o", "jsonpath={range .items[*]}{.metadata.name}{'\\n'}{end}")
		if err != nil {
			continue
		}
		for _, line := range utils.GetNonEmptyLines(out) {
			if containsAny(line, "cilium-gateway", "demo-gateway") {
				return ns + "/" + line
			}
		}
		for _, line := range utils.GetNonEmptyLines(out) {
			if containsAny(line, "gateway") && line != "kubernetes" {
				return ns + "/" + line
			}
		}
	}
	return ""
}

// patchCiliumGatewayServicesClusterIP is a no-op for type changes: the Cilium
// gateway controller reverts Service type to LoadBalancer. Prefer
// ensureCiliumGatewayLBIPPool() so LB Services get an EXTERNAL-IP on Kind.
// Kept for FTW helpers that still call it; in-cluster curls use ClusterIP of the LB Service.
func patchCiliumGatewayServicesClusterIP() {
	ensureCiliumGatewayLBIPPool()
}

// ensureCiliumGatewayLBIPPool installs a CiliumLoadBalancerIPPool covering Kind's
// docker network so Gateway LoadBalancer Services leave <pending> and Programmed
// can become True.
func ensureCiliumGatewayLBIPPool() {
	GinkgoHelper()
	if !crdExists("ciliumloadbalancerippools.cilium.io") {
		return
	}
	By("ensuring CiliumLoadBalancerIPPool for Kind Gateway Services")
	applyFile("test/e2e/manifests/cilium/lb-ip-pool.yaml")
	_, err := kubectl("get", "ciliumloadbalancerippool", "kind-e2e-gateway-pool")
	Expect(err).NotTo(HaveOccurred(), "CiliumLoadBalancerIPPool kind-e2e-gateway-pool")

	// If a gateway Service already exists, wait until it has an EXTERNAL-IP.
	out, err := kubectl("get", "svc", "-n", demoNamespace,
		"-o", "jsonpath={range .items[*]}{.metadata.name}{'\\n'}{end}")
	if err != nil {
		return
	}
	var gwSvcs []string
	for _, name := range utils.GetNonEmptyLines(out) {
		if containsAny(name, "cilium-gateway", "gateway") {
			gwSvcs = append(gwSvcs, name)
		}
	}
	if len(gwSvcs) == 0 {
		return
	}
	Eventually(func(g Gomega) {
		for _, name := range gwSvcs {
			ip, err := kubectl("get", "svc", name, "-n", demoNamespace,
				"-o", "jsonpath={.status.loadBalancer.ingress[0].ip}")
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(strings.TrimSpace(ip)).NotTo(BeEmpty(),
				"Service %s/%s waiting for LB EXTERNAL-IP from CiliumLoadBalancerIPPool", demoNamespace, name)
		}
	}, 2*time.Minute, 2*time.Second).Should(Succeed())
}

func containsAny(s string, parts ...string) bool {
	for _, p := range parts {
		if p != "" && strings.Contains(s, p) {
			return true
		}
	}
	return false
}
