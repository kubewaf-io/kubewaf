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

var _ = Describe("Provider dataplane e2e", Ordered, func() {
	BeforeAll(func() {
		if e2eProvider() == "manager" {
			// Manager-only suite; provider tests skipped via providerEnabled.
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
		if e2eProvider() == "manager" {
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
			Eventually(func(g Gomega) {
				_, err := kubectl("get", "gateways.gateway.networking.k8s.io", "demo-gateway", "-n", demoNamespace)
				g.Expect(err).NotTo(HaveOccurred())
			}, 2*time.Minute, time.Second).Should(Succeed())

			// Gateway may take time to Programmed
			Eventually(func(g Gomega) {
				out, err := kubectl("get", "gateways.gateway.networking.k8s.io", "demo-gateway", "-n", demoNamespace,
					"-o", "jsonpath={.status.conditions[?(@.type=='Programmed')].status}")
				g.Expect(err).NotTo(HaveOccurred())
				// Accept Programmed=True when available; some EG versions use different conditions.
				if out != "" {
					g.Expect(out).To(Equal("True"))
				}
			}, 3*time.Minute, 3*time.Second).Should(Succeed())

			applyFile("test/e2e/manifests/envoygateway/waf.yaml")
			waitForWAFReady(demoNamespace, "demo-waf-eg", 3*time.Minute)

			Expect(wafStatusField(demoNamespace, "demo-waf-eg", "{.status.provider}")).
				To(Equal("EnvoyGateway"))
			Expect(wafStatusField(demoNamespace, "demo-waf-eg", "{.status.slotKind}")).
				To(Equal("ExtensionServer"))
			Expect(wafStatusField(demoNamespace, "demo-waf-eg", "{.status.ecdsResourceName}")).
				To(Equal("kubewaf/demo/demo-waf-eg"))
		})

		It("blocks scanner User-Agent through the gateway when real wasm is configured", func() {
			if !realWasmConfigured() {
				Skip("set E2E_WASM_SOURCE_URL to a real modsecurity-proxy-wasm binary for traffic tests")
			}
			// Ensure WAF is applied
			applyFile("test/e2e/manifests/envoygateway/waf.yaml")
			waitForWAFReady(demoNamespace, "demo-waf-eg", 3*time.Minute)

			// Resolve Envoy proxy service created for the gateway.
			// Label selectors vary by EG version; try common ones.
			svc := findEnvoyGatewayService()
			if svc == "" {
				Skip("could not locate Envoy Gateway proxy Service")
			}

			By("sending benign request")
			Eventually(func(g Gomega) {
				code := curlGatewayHTTP("envoy-gateway-system", svc, "demo.local", "/get", "Mozilla/5.0")
				g.Expect(code).To(Equal("200"), "benign request should pass")
			}, 2*time.Minute, 5*time.Second).Should(Succeed())

			By("sending sqlmap User-Agent (should be blocked)")
			Eventually(func(g Gomega) {
				code := curlGatewayHTTP("envoy-gateway-system", svc, "demo.local", "/get", "sqlmap/1.0")
				g.Expect(code).To(Equal("403"), "scanner UA should be denied")
			}, 2*time.Minute, 5*time.Second).Should(Succeed())
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
			applyFile("test/e2e/manifests/istio/gateway.yaml")
			applyFile("test/e2e/manifests/istio/waf.yaml")

			waitForWAFReady(demoNamespace, "demo-waf-istio", 3*time.Minute)

			Expect(wafStatusField(demoNamespace, "demo-waf-istio", "{.status.provider}")).
				To(Equal("Istio"))
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
			if !realWasmConfigured() {
				Skip("set E2E_WASM_SOURCE_URL to a real modsecurity-proxy-wasm binary for traffic tests")
			}
			applyFile("test/e2e/manifests/istio/waf.yaml")
			waitForWAFReady(demoNamespace, "demo-waf-istio", 3*time.Minute)

			svc := findIstioIngressService()
			if svc == "" {
				Skip("could not locate Istio ingress Service")
			}
			ns := "istio-system"

			Eventually(func(g Gomega) {
				code := curlGatewayHTTP(ns, svc, "demo.local", "/get", "Mozilla/5.0")
				g.Expect(code).To(Equal("200"))
			}, 3*time.Minute, 5*time.Second).Should(Succeed())

			Eventually(func(g Gomega) {
				code := curlGatewayHTTP(ns, svc, "demo.local", "/get", "sqlmap/1.0")
				g.Expect(code).To(Equal("403"))
			}, 3*time.Minute, 5*time.Second).Should(Succeed())
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
				applyFile("test/e2e/manifests/cilium/gateway.yaml")
			}
			applyFile("test/e2e/manifests/cilium/waf.yaml")

			waitForWAFReady(demoNamespace, "demo-waf-cilium", 3*time.Minute)

			Expect(wafStatusField(demoNamespace, "demo-waf-cilium", "{.status.provider}")).
				To(Equal("Cilium"))
			Expect(wafStatusField(demoNamespace, "demo-waf-cilium", "{.status.slotKind}")).
				To(Equal("CiliumEnvoyConfig"))
			Expect(wafStatusField(demoNamespace, "demo-waf-cilium", "{.status.slotName}")).
				To(Equal("kubewaf-demo-waf-cilium"))

			By("verifying CiliumEnvoyConfig exists and targets httpbin")
			Eventually(func(g Gomega) {
				_, err := kubectl("get", "ciliumenvoyconfig", "kubewaf-demo-waf-cilium", "-n", demoNamespace)
				g.Expect(err).NotTo(HaveOccurred())
			}, time.Minute, 2*time.Second).Should(Succeed())

			out := kubectlOK("get", "ciliumenvoyconfig", "kubewaf-demo-waf-cilium", "-n", demoNamespace, "-o", "yaml")
			Expect(out).To(ContainSubstring("kubewaf_ecds"))
			Expect(out).To(ContainSubstring("httpbin"))
			Expect(out).To(ContainSubstring("kubewaf/demo/demo-waf-cilium"))
		})

		It("documents traffic test limitation without Wasm-capable Cilium Envoy", func() {
			// Full L7 WAF enforcement on Cilium depends on the Envoy build and CEC
			// filter-chain merge. Resource slot is asserted above; traffic is optional.
			if os.Getenv("E2E_CILIUM_TRAFFIC") != "true" {
				Skip("set E2E_CILIUM_TRAFFIC=true to run experimental Cilium traffic checks")
			}
			if !realWasmConfigured() {
				Skip("set E2E_WASM_SOURCE_URL for traffic tests")
			}
			// Best-effort: curl via Cilium Gateway service if present.
			svc := findCiliumGatewayService()
			if svc == "" {
				Skip("no Cilium gateway Service found")
			}
			Eventually(func(g Gomega) {
				code := curlGatewayHTTP(demoNamespace, svc, "demo.local", "/get", "sqlmap/1.0")
				g.Expect(code).To(Equal("403"))
			}, 3*time.Minute, 5*time.Second).Should(Succeed())
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

func findIstioIngressService() string {
	for _, ns := range []string{"istio-system", "istio-ingress"} {
		out, err := kubectl("get", "svc", "-n", ns,
			"-o", "jsonpath={range .items[*]}{.metadata.name}{'\\n'}{end}")
		if err != nil {
			continue
		}
		for _, line := range utils.GetNonEmptyLines(out) {
			if containsAny(line, "ingress", "gateway") {
				return line
			}
		}
	}
	return ""
}

func findCiliumGatewayService() string {
	out, err := kubectl("get", "svc", "-n", demoNamespace,
		"-o", "jsonpath={range .items[*]}{.metadata.name}{'\\n'}{end}")
	if err != nil {
		return ""
	}
	for _, line := range utils.GetNonEmptyLines(out) {
		if containsAny(line, "gateway", "cilium") {
			return line
		}
	}
	return ""
}

func containsAny(s string, parts ...string) bool {
	for _, p := range parts {
		if p != "" && strings.Contains(s, p) {
			return true
		}
	}
	return false
}

