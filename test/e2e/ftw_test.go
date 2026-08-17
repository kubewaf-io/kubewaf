//go:build e2e
// +build e2e

package e2e

import (
	"os"
	"time"

	. "github.com/onsi/ginkgo/v2"
)

// CRS go-ftw Path A (second-class): crsEnable + engine-embedded CRS (CATALOG_MODE=full).
//
// Default CI/operator embed is path-b wasm (no CRS rule confs). Path A requires the
// *-full wasm image and is opt-in only — use Path B (ftw_path_b_test.go) for first-class
// CRS regression against the tested default engine.
//
// Prerequisites:
//   - Operator image with full-catalog modsecurity-proxy-wasm (CATALOG_MODE=full)
//   - Provider installed (make setup-test-e2e-*)
//   - Docker available to run ghcr.io/coreruleset/go-ftw
//
// Env:
//
//	E2E_FTW_PATH_A=true     enable this suite (required; second-class)
//	E2E_SKIP_FTW=true       skip go-ftw
//	E2E_FTW_INCLUDE=regex   go-ftw -i filter (default ^913 scanner-detection smoke)
//	E2E_FTW_INCLUDE=all     full CRS regression suite
//	E2E_CILIUM_TRAFFIC=true required for Cilium FTW (experimental)
//	CRS_VERSION / GO_FTW_VERSION optional pins
//
// Each test enables annotation kubewaf.io/ftw-profile=true (Include @ftw-conf),
// routes demo.local to albedo, then runs go-ftw via test/e2e/ftw/run-ftw.sh.
//
// ContinueOnFailure: EG/Istio/Cilium FTW runs are independent.
var _ = Describe("CRS go-ftw Path A (full catalog, second-class)", Ordered, ContinueOnFailure, func() {
	BeforeAll(func() {
		if e2eProvider() == "manager" {
			return
		}
		if !ftwPathAEnabled() {
			return
		}
		// Operator + demo app are installed by the Provider dataplane suite when
		// both run; if only FTW-focused runs happen, ensure basics exist.
		if os.Getenv("E2E_SKIP_OPERATOR_INSTALL") != "true" {
			// Provider Ordered suite may already have installed; upgrade is fine.
			installOperatorHelm()
		}
		applyCommonAppAndRules()
	})

	Context("Envoy Gateway", func() {
		BeforeEach(func() {
			if !providerEnabled("envoy-gateway") {
				Skip("E2E_PROVIDER does not include envoy-gateway")
			}
			if !ftwPathAEnabled() {
				Skip("Path A go-ftw disabled (set E2E_FTW_PATH_A=true with full-catalog wasm)")
			}
			skipUnlessCRD("gateways.gateway.networking.k8s.io", "Gateway API required")
			skipUnlessCRD("envoyproxies.gateway.envoyproxy.io", "install Envoy Gateway first")
		})

		It("passes go-ftw against Envoy Gateway + kubeWAF ModSecurity (Path A)", func() {
			applyFile("test/e2e/manifests/envoygateway/gateway.yaml")
			waitForGatewayProgrammed(demoNamespace, "demo-gateway", 4*time.Minute)

			// Path A: force crsEnable (default e2e WAF is path-b / crsEnable:false).
			applyFile("test/e2e/manifests/envoygateway/waf.yaml")
			_, _ = kubectl("patch", "wafs.waf.kubewaf.io", "demo-waf-eg", "-n", demoNamespace,
				"--type=merge", "-p", `{"spec":{"crsEnable":true}}`)
			waitForWAFReady(demoNamespace, "demo-waf-eg", 3*time.Minute)

			runProviderFTW("envoy-gateway", "demo-waf-eg", ftwTargetEnvoyGateway)
		})
	})

	Context("Istio", func() {
		BeforeEach(func() {
			if !providerEnabled("istio") {
				Skip("E2E_PROVIDER does not include istio")
			}
			if !ftwPathAEnabled() {
				Skip("Path A go-ftw disabled (set E2E_FTW_PATH_A=true with full-catalog wasm)")
			}
			if !crdExists("envoyfilters.networking.istio.io") {
				Skip("Istio not installed (missing EnvoyFilter CRD)")
			}
		})

		It("passes go-ftw against Istio ingress + kubeWAF ModSecurity (Path A)", func() {
			if os.Getenv("E2E_ISTIO_TRAFFIC") != "true" {
				Skip("set E2E_ISTIO_TRAFFIC=true after bootstrap-static kubewaf_ecds is available (ECDS constraint)")
			}
			applyFile("test/e2e/manifests/istio/gateway.yaml")
			_, _ = kubectl("patch", "svc", "demo-gateway-istio", "-n", demoNamespace,
				"-p", `{"spec":{"type":"ClusterIP"}}`)
			applyFile("test/e2e/manifests/istio/waf.yaml")
			_, _ = kubectl("patch", "wafs.waf.kubewaf.io", "demo-waf-istio", "-n", demoNamespace,
				"--type=merge", "-p", `{"spec":{"crsEnable":true}}`)
			waitForWAFReady(demoNamespace, "demo-waf-istio", 3*time.Minute)

			runProviderFTW("istio", "demo-waf-istio", ftwTargetIstio)
		})
	})

	Context("Cilium", func() {
		BeforeEach(func() {
			if !providerEnabled("cilium") {
				Skip("E2E_PROVIDER does not include cilium")
			}
			if !ftwPathAEnabled() {
				Skip("Path A go-ftw disabled (set E2E_FTW_PATH_A=true with full-catalog wasm)")
			}
			if os.Getenv("E2E_CILIUM_TRAFFIC") != "true" {
				Skip("set E2E_CILIUM_TRAFFIC=true to run Cilium go-ftw (experimental)")
			}
			if !crdExists("ciliumenvoyconfigs.cilium.io") {
				Skip("Cilium not installed")
			}
		})

		It("passes go-ftw against Cilium Gateway + kubeWAF ModSecurity (Path A)", func() {
			skipUnlessCRD("gateways.gateway.networking.k8s.io", "install Gateway API CRDs (make setup-test-e2e-cilium)")
			applyCiliumECDSBootstrap()
			applyFile("test/e2e/manifests/cilium/gateway.yaml")
			applyFile("test/e2e/manifests/cilium/waf.yaml")
			_, _ = kubectl("patch", "wafs.waf.kubewaf.io", "demo-waf-cilium", "-n", demoNamespace,
				"--type=merge", "-p", `{"spec":{"crsEnable":true}}`)
			patchCiliumGatewayServicesClusterIP()
			waitForWAFReady(demoNamespace, "demo-waf-cilium", 3*time.Minute)

			runProviderFTW("cilium", "demo-waf-cilium", ftwTargetCilium)
		})
	})
})
