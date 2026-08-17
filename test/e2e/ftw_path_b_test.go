//go:build e2e
// +build e2e

package e2e

import (
	"os"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// Path B CRS go-ftw: crsEnable=false + structured SecRules from config/samples/crs.
//
// Requires:
//   - Operator with modsecurity-proxy-wasm that supports gzip+base64 directives
//     (and full CRS catalog for @pmFromFile / @ftw-conf)
//   - E2E_FTW_PATH_B=true (make test-e2e-ftw-path-b)
//   - Same provider env as Path A FTW
//
// Env (in addition to Path A FTW):
//   E2E_FTW_PATH_B=true
//   E2E_FTW_INCLUDE=^913|all  (default ^913)

var _ = Describe("CRS go-ftw Path B (structured CRS)", Ordered, ContinueOnFailure, func() {
	BeforeAll(func() {
		if e2eProvider() == "manager" {
			return
		}
		if !ftwPathBEnabled() {
			return
		}
		if os.Getenv("E2E_SKIP_OPERATOR_INSTALL") != "true" {
			installOperatorHelm()
		}
		applyCommonAppAndRules()
		applyStructuredCRSSamples()
		applyPathBRuleset()
	})

	AfterAll(func() {
		if !ftwPathBEnabled() {
			return
		}
		// Path B wasm/ECDS reloads have left Envoy returning HTTP 000; tear the
		// Path B WAF down and recover the proxy before provider traffic specs.
		ensureExclusiveWAF(demoNamespace, "")
		if providerEnabled("envoy-gateway") {
			recoverEnvoyGatewayAfterPathB()
		}
	})

	Context("Envoy Gateway", func() {
		BeforeEach(func() {
			if !providerEnabled("envoy-gateway") {
				Skip("E2E_PROVIDER does not include envoy-gateway")
			}
			if !ftwPathBEnabled() {
				Skip("Path B go-ftw disabled (set E2E_FTW_PATH_B=true)")
			}
			skipUnlessCRD("gateways.gateway.networking.k8s.io", "Gateway API required")
			skipUnlessCRD("envoyproxies.gateway.envoyproxy.io", "install Envoy Gateway first")
		})

		It("passes go-ftw with crsEnable=false + structured CRS RuleSet", func() {
			applyFile("test/e2e/manifests/envoygateway/gateway.yaml")
			waitForGatewayProgrammed(demoNamespace, "demo-gateway", 4*time.Minute)

			// Ensure Path A (or any other) WAF is not competing for the same Gateway.
			ensureExclusiveWAF(demoNamespace, "")

			applyFile("test/e2e/manifests/envoygateway/waf-path-b.yaml")
			waitForWAFPathBReady(demoNamespace, "demo-waf-eg-path-b", 5*time.Minute)

			// Path B must not rely on crsEnable.
			Expect(wafStatusField(demoNamespace, "demo-waf-eg-path-b", "{.spec.crsEnable}")).
				NotTo(Equal("true"), "Path B WAF must have crsEnable=false")

			runProviderFTW("envoy-gateway", "demo-waf-eg-path-b", ftwTargetEnvoyGateway)

			// Leave a clean Gateway for later Path A / traffic specs in the same suite.
			ensureExclusiveWAF(demoNamespace, "")
		})
	})

	Context("Istio", func() {
		BeforeEach(func() {
			if !providerEnabled("istio") {
				Skip("E2E_PROVIDER does not include istio")
			}
			if !ftwPathBEnabled() {
				Skip("Path B go-ftw disabled (set E2E_FTW_PATH_B=true)")
			}
			if !crdExists("envoyfilters.networking.istio.io") {
				Skip("Istio not installed (missing EnvoyFilter CRD)")
			}
		})

		It("passes go-ftw Path B against Istio ingress", func() {
			if os.Getenv("E2E_ISTIO_TRAFFIC") != "true" {
				Skip("set E2E_ISTIO_TRAFFIC=true after bootstrap-static kubewaf_ecds is available")
			}
			applyFile("test/e2e/manifests/istio/gateway.yaml")
			_, _ = kubectl("patch", "svc", "demo-gateway-istio", "-n", demoNamespace,
				"-p", `{"spec":{"type":"ClusterIP"}}`)
			_, _ = kubectl("delete", wafResource, "demo-waf-istio", "-n", demoNamespace, "--ignore-not-found", "--wait=false")
			applyFile("test/e2e/manifests/istio/waf-path-b.yaml")
			waitForWAFPathBReady(demoNamespace, "demo-waf-istio-path-b", 5*time.Minute)

			runProviderFTW("istio", "demo-waf-istio-path-b", ftwTargetIstio)
		})
	})

	Context("Cilium", func() {
		BeforeEach(func() {
			if !providerEnabled("cilium") {
				Skip("E2E_PROVIDER does not include cilium")
			}
			if !ftwPathBEnabled() {
				Skip("Path B go-ftw disabled (set E2E_FTW_PATH_B=true)")
			}
			if os.Getenv("E2E_CILIUM_TRAFFIC") != "true" {
				Skip("set E2E_CILIUM_TRAFFIC=true to run Cilium go-ftw (experimental)")
			}
			if !crdExists("ciliumenvoyconfigs.cilium.io") {
				Skip("Cilium not installed")
			}
		})

		It("passes go-ftw Path B against Cilium Gateway", func() {
			skipUnlessCRD("gateways.gateway.networking.k8s.io", "install Gateway API CRDs (make setup-test-e2e-cilium)")
			applyCiliumECDSBootstrap()
			applyFile("test/e2e/manifests/cilium/gateway.yaml")
			_, _ = kubectl("delete", wafResource, "demo-waf-cilium", "-n", demoNamespace, "--ignore-not-found", "--wait=false")
			applyFile("test/e2e/manifests/cilium/waf-path-b.yaml")
			waitForWAFPathBReady(demoNamespace, "demo-waf-cilium-path-b", 5*time.Minute)

			runProviderFTW("cilium", "demo-waf-cilium-path-b", ftwTargetCilium)
		})
	})
})
