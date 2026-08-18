//go:build e2e
// +build e2e

package e2e

import (
	"os"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// PhraseList Path B e2e: inject custom @pmFromFile list via data_files and block UA.
// Also covers IPList + @ipMatchFromFile on the same inject path.
// PhraseList/IPList data_files injection is always enabled on the operator.
var _ = Describe("PhraseList pmFromFile e2e", Ordered, func() {
	BeforeAll(func() {
		if e2eProvider() == "manager" {
			Skip("manager-only suite")
		}
		if !providerEnabled("envoy-gateway") && e2eProvider() != "all" {
			Skip("E2E_PROVIDER does not include envoy-gateway")
		}
		if os.Getenv("E2E_SKIP_OPERATOR_INSTALL") != "true" {
			installOperatorHelm()
		}
		applyCommonAppAndRules()
		applyFile("test/e2e/manifests/envoygateway/gateway.yaml")
		waitForGatewayProgrammed(demoNamespace, "demo-gateway", 4*time.Minute)
	})

	AfterAll(func() {
		_, _ = kubectl("delete", "-f", "test/e2e/manifests/phraselist/rules.yaml", "--ignore-not-found", "--wait=false")
		_, _ = kubectl("delete", "-f", "test/e2e/manifests/phraselist/ip-blocklist.yaml", "--ignore-not-found", "--wait=false")
		_, _ = kubectl("delete", "-f", "test/e2e/manifests/phraselist/commented-pmfromfile.yaml", "--ignore-not-found", "--wait=false")
		_, _ = kubectl("delete", wafResource, "demo-waf-phraselist", "-n", demoNamespace, "--ignore-not-found", "--wait=false")
		_, _ = kubectl("delete", wafResource, "demo-waf-iplist", "-n", demoNamespace, "--ignore-not-found", "--wait=false")
		_, _ = kubectl("delete", wafResource, "demo-waf-commented-pmfromfile", "-n", demoNamespace, "--ignore-not-found", "--wait=false")
	})

	It("marks PhraseList Ready and SecRule Ready for custom pmFromFile", func() {
		applyFile("test/e2e/manifests/phraselist/rules.yaml")

		Eventually(func(g Gomega) {
			out, err := kubectl("get", "phraselists.seclang.kubewaf.io", "e2e-scanners", "-n", demoNamespace,
				"-o", "jsonpath={.status.conditions[?(@.type==\"Ready\")].status}")
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(strings.TrimSpace(out)).To(Equal("True"), "PhraseList Ready")
		}, 2*time.Minute, 2*time.Second).Should(Succeed())

		Eventually(func(g Gomega) {
			out, err := kubectl("get", "secrules.seclang.kubewaf.io", "block-e2e-phrase-scanners", "-n", demoNamespace,
				"-o", "jsonpath={.status.conditions[?(@.type==\"Ready\")].status}")
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(strings.TrimSpace(out)).To(Equal("True"), "SecRule Ready with custom pmFromFile")
		}, 2*time.Minute, 2*time.Second).Should(Succeed())
	})

	It("publishes WAF with data_files inject and blocks custom scanner UA", func() {
		applyFile("test/e2e/manifests/phraselist/rules.yaml")
		ensureExclusiveWAF(demoNamespace, "demo-waf-phraselist")
		waitForWAFReady(demoNamespace, "demo-waf-phraselist", 3*time.Minute)

		Eventually(func(g Gomega) {
			out, err := kubectl("get", wafResource, "demo-waf-phraselist", "-n", demoNamespace,
				"-o", "jsonpath={.status.dataFilesCount}")
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(strings.TrimSpace(out)).To(Equal("1"),
				"expected one injected data file; got %q", out)
		}, 2*time.Minute, 2*time.Second).Should(Succeed())

		Eventually(func(g Gomega) {
			out, err := kubectl("get", wafResource, "demo-waf-phraselist", "-n", demoNamespace,
				"-o", "jsonpath={.status.conditions[?(@.type==\"PhraseListsResolved\")].status}")
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(strings.TrimSpace(out)).To(Equal("True"), "PhraseListsResolved")
		}, 2*time.Minute, 2*time.Second).Should(Succeed())

		svc := findEnvoyGatewayService()
		if svc == "" {
			Skip("could not locate Envoy Gateway proxy Service")
		}
		waitForServiceEndpoints("envoy-gateway-system", svc, 3*time.Minute)
		// Allow ECDS push to settle on Envoy (exclusive WAF swap can lag Ready).
		time.Sleep(8 * time.Second)

		// waitForGatewayHTTPCode bounces a wedged EG proxy on persistent HTTP 000
		// (exclusive WAF swap / data_files inject has left Envoy unresponsive on Kind).
		By("sending benign User-Agent (should pass)")
		waitForGatewayHTTPCode("envoy-gateway-system", svc, "demo.local", "/get",
			"Mozilla/5.0 e2e-benign", []string{"200"}, 3*time.Minute, "benign UA should pass")

		By("sending custom PhraseList User-Agent token (should be blocked)")
		waitForGatewayHTTPCode("envoy-gateway-system", svc, "demo.local", "/get",
			"kubewaf-e2e-phrase-scanner", []string{"403"}, 2*time.Minute, "custom PhraseList token must be blocked")
	})

	It("injects IPList for @ipMatchFromFile and blocks listed client IP header", func() {
		// Apply first so the keeper exists, then drop other WAFs on the Gateway.
		applyFile("test/e2e/manifests/phraselist/ip-blocklist.yaml")
		ensureExclusiveWAF(demoNamespace, "demo-waf-iplist")

		Eventually(func(g Gomega) {
			out, err := kubectl("get", "iplists.seclang.kubewaf.io", "e2e-ip-blocklist", "-n", demoNamespace,
				"-o", "jsonpath={.status.conditions[?(@.type==\"Ready\")].status}")
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(strings.TrimSpace(out)).To(Equal("True"), "IPList Ready")
		}, 2*time.Minute, 2*time.Second).Should(Succeed())

		Eventually(func(g Gomega) {
			out, err := kubectl("get", "secrules.seclang.kubewaf.io", "block-e2e-ip-list", "-n", demoNamespace,
				"-o", "jsonpath={.status.conditions[?(@.type==\"Ready\")].status}")
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(strings.TrimSpace(out)).To(Equal("True"), "SecRule Ready with ipMatchFromFile")
		}, 2*time.Minute, 2*time.Second).Should(Succeed())

		waitForWAFReady(demoNamespace, "demo-waf-iplist", 3*time.Minute)
		Eventually(func(g Gomega) {
			out, err := kubectl("get", wafResource, "demo-waf-iplist", "-n", demoNamespace,
				"-o", "jsonpath={.status.dataFilesCount}")
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(strings.TrimSpace(out)).To(Equal("1"), "expected one injected IP list")
		}, 2*time.Minute, 2*time.Second).Should(Succeed())

		svc := findEnvoyGatewayService()
		if svc == "" {
			Skip("could not locate Envoy Gateway proxy Service")
		}
		waitForServiceEndpoints("envoy-gateway-system", svc, 3*time.Minute)
		time.Sleep(8 * time.Second)

		// Header-based match (manifest uses X-E2E-Client-IP) so the test is
		// independent of Envoy REMOTE_ADDR / Kind pod CIDR.
		By("sending benign X-E2E-Client-IP (should pass)")
		waitForGatewayHTTPCodeWithHeaders("envoy-gateway-system", svc, "demo.local", "/get",
			"Mozilla/5.0", map[string]string{"X-E2E-Client-IP": "8.8.8.8"},
			[]string{"200"}, 3*time.Minute, "unlisted IP header should pass")

		By("sending blocked X-E2E-Client-IP from IPList (should be denied)")
		waitForGatewayHTTPCodeWithHeaders("envoy-gateway-system", svc, "demo.local", "/get",
			"Mozilla/5.0", map[string]string{"X-E2E-Client-IP": "203.0.113.10"},
			[]string{"403"}, 2*time.Minute, "listed IP header should hit ipMatchFromFile")
	})

	// Juice-shop Path B: CRS rules render as a comment-prefixed SecLang blob
	// (metadata.comment + SecRule). ScanPmFromFileBasenames used to skip the
	// whole blob, so data_files omitted restricted-files.data and Envoy
	// fail-closed the plugin. This WAF pairs a comment-less @pmFromFile with a
	// 930130-shaped commented @pmFromFile so the miss is visible as
	// dataFilesCount=1 and a dead dataplane instead of count=2 + 403s.
	It("injects data_files for CRS-style comment-prefixed @pmFromFile SecLang", func() {
		applyFile("test/e2e/manifests/phraselist/commented-pmfromfile.yaml")
		ensureExclusiveWAF(demoNamespace, "demo-waf-commented-pmfromfile")

		Eventually(func(g Gomega) {
			out, err := kubectl("get", "secrules.seclang.kubewaf.io", "block-e2e-commented-pmfromfile", "-n", demoNamespace,
				"-o", "jsonpath={.status.secRuleString}")
			g.Expect(err).NotTo(HaveOccurred())
			trim := strings.TrimSpace(out)
			g.Expect(trim).To(HavePrefix("#"),
				"commented SecRule must render with a leading # (CRS-style); got %q", truncateForLog(trim, 160))
			g.Expect(trim).To(ContainSubstring("@pmFromFile e2e-restricted-commented.data"))
		}, 2*time.Minute, 2*time.Second).Should(Succeed())

		waitForWAFReady(demoNamespace, "demo-waf-commented-pmfromfile", 3*time.Minute)

		Eventually(func(g Gomega) {
			out, err := kubectl("get", wafResource, "demo-waf-commented-pmfromfile", "-n", demoNamespace,
				"-o", "jsonpath={.status.dataFilesCount}")
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(strings.TrimSpace(out)).To(Equal("2"),
				"expected both comment-less and comment-prefixed @pmFromFile lists; got dataFilesCount=%q", out)
		}, 2*time.Minute, 2*time.Second).Should(Succeed())

		Eventually(func(g Gomega) {
			out, err := kubectl("get", wafResource, "demo-waf-commented-pmfromfile", "-n", demoNamespace,
				"-o", "jsonpath={.status.conditions[?(@.type==\"PhraseListsResolved\")].message}")
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(out).To(ContainSubstring("injected 2 data files"),
				"PhraseListsResolved should inject both lists; got %q", out)
		}, 2*time.Minute, 2*time.Second).Should(Succeed())

		svc := findEnvoyGatewayService()
		if svc == "" {
			Skip("could not locate Envoy Gateway proxy Service")
		}
		waitForServiceEndpoints("envoy-gateway-system", svc, 3*time.Minute)
		time.Sleep(8 * time.Second)

		By("sending benign request (plugin must load; fail-closed is a miss)")
		waitForGatewayHTTPCode("envoy-gateway-system", svc, "demo.local", "/get",
			"Mozilla/5.0 e2e-benign", []string{"200"}, 3*time.Minute,
			"benign GET must pass; 403/503 means wasm fail-closed on missing .data")

		By("sending comment-less PhraseList User-Agent (should be blocked)")
		waitForGatewayHTTPCode("envoy-gateway-system", svc, "demo.local", "/get",
			"kubewaf-e2e-commented-scanner", []string{"403"}, 2*time.Minute,
			"comment-less @pmFromFile UA must be blocked")

		By("sending path token from comment-prefixed @pmFromFile list (should be blocked)")
		waitForGatewayHTTPCode("envoy-gateway-system", svc, "demo.local", "/e2e-commented-restricted-token",
			"Mozilla/5.0 e2e-benign", []string{"403"}, 2*time.Minute,
			"comment-prefixed @pmFromFile path must be blocked")
	})
})
