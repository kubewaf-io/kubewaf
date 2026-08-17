//go:build e2e
// +build e2e

package e2e

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/kubewaf-io/kubewaf/internal/dataplane/config"
	"github.com/kubewaf-io/kubewaf/test/utils"
)

// ftwEnabled is true when CRS go-ftw should run for providers.
// Opt-in: set E2E_FTW=true (make test-e2e-ftw). E2E_SKIP_FTW=true always skips.
//
// Note: historical "Path A" go-ftw (crsEnable + Include @owasp_crs) is second-class
// and requires full-catalog wasm. Use ftwPathAEnabled() / E2E_FTW_PATH_A=true.
// Default CI CRS coverage is Path B (ftwPathBEnabled).
func ftwEnabled() bool {
	if v := strings.ToLower(strings.TrimSpace(os.Getenv("E2E_SKIP_FTW"))); v == "true" || v == "1" {
		return false
	}
	v := strings.ToLower(strings.TrimSpace(os.Getenv("E2E_FTW")))
	return v == "true" || v == "1" || v == "yes"
}

// ftwPathAEnabled runs Path A go-ftw (crsEnable:true + engine-embedded CRS).
// Second-class: needs CATALOG_MODE=full wasm (*-full image). Default CI is path-b only.
// Opt-in: E2E_FTW_PATH_A=true (and E2E_FTW=true or this alone).
func ftwPathAEnabled() bool {
	if v := strings.ToLower(strings.TrimSpace(os.Getenv("E2E_SKIP_FTW"))); v == "true" || v == "1" {
		return false
	}
	v := strings.ToLower(strings.TrimSpace(os.Getenv("E2E_FTW_PATH_A")))
	return v == "true" || v == "1" || v == "yes"
}

// ftwPathBEnabled runs Path B (crsEnable=false + structured CRS SecRules) go-ftw.
// First-class CI path. Opt-in: E2E_FTW_PATH_B=true (make test-e2e-ftw-path-b).
func ftwPathBEnabled() bool {
	if v := strings.ToLower(strings.TrimSpace(os.Getenv("E2E_SKIP_FTW"))); v == "true" || v == "1" {
		return false
	}
	v := strings.ToLower(strings.TrimSpace(os.Getenv("E2E_FTW_PATH_B")))
	return v == "true" || v == "1" || v == "yes"
}

// ftwInclude is the go-ftw -i regex. Default is scanner-detection rules (fast smoke).
// Empty string / E2E_FTW_INCLUDE=all runs the full CRS suite.
func ftwInclude() string {
	v := os.Getenv("E2E_FTW_INCLUDE")
	if v == "" {
		return "^913"
	}
	if strings.EqualFold(v, "all") || v == "*" {
		return ""
	}
	return v
}

func ensureAlbedoBackend() {
	GinkgoHelper()
	By("deploying albedo backend for go-ftw")
	applyFile("test/e2e/manifests/ftw/albedo.yaml")
	Eventually(func(g Gomega) {
		out, err := kubectl("get", "deploy", "albedo", "-n", demoNamespace,
			"-o", "jsonpath={.status.availableReplicas}")
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(out).NotTo(Equal(""), "albedo not available")
		g.Expect(out).NotTo(Equal("0"))
	}, 2*time.Minute, 2*time.Second).Should(Succeed())
	applyFile("test/e2e/manifests/ftw/httproute-albedo.yaml")
}

func restoreHTTPBinRoute(provider string) {
	GinkgoHelper()
	By("restoring httpbin HTTPRoute after go-ftw")
	switch provider {
	case "envoy-gateway":
		applyFile("test/e2e/manifests/envoygateway/gateway.yaml")
	case "istio":
		applyFile("test/e2e/manifests/istio/gateway.yaml")
	case "cilium":
		if crdExists("gateways.gateway.networking.k8s.io") {
			applyFile("test/e2e/manifests/cilium/gateway.yaml")
		}
	}
}

func enableFTWProfileOnWAF(ns, name string) {
	GinkgoHelper()
	By(fmt.Sprintf("enabling FTW profile on WAF %s/%s", ns, name))
	// kubewaf.io/ftw-profile=true → Include @ftw-conf (DetectionOnly + X-CRS-Test markers).
	_, err := kubectl("annotate", wafResource, name, "-n", ns,
		config.AnnotationFTWProfile+"=true", "--overwrite")
	Expect(err).NotTo(HaveOccurred())
	waitForWAFReady(ns, name, 3*time.Minute)
	// Give ECDS + Envoy a moment to pick up the new directives_map.
	time.Sleep(5 * time.Second)
}

func disableFTWProfileOnWAF(ns, name string) {
	GinkgoHelper()
	// Best-effort: annotation may already be absent.
	_, _ = kubectl("annotate", wafResource, name, "-n", ns,
		config.AnnotationFTWProfile+"-", "--overwrite")
}

// ftwTarget describes how to reach the provider data plane for go-ftw.
type ftwTarget struct {
	Provider    string
	LogNS       string
	LogSel      string
	ForwardNS   string
	ForwardSvc  string
	ForwardPort string
}

func ftwTargetEnvoyGateway() (ftwTarget, bool) {
	svc := findEnvoyGatewayService()
	if svc == "" {
		return ftwTarget{}, false
	}
	return ftwTarget{
		Provider:    "envoy-gateway",
		LogNS:       "envoy-gateway-system",
		LogSel:      "app.kubernetes.io/component=proxy",
		ForwardNS:   "envoy-gateway-system",
		ForwardSvc:  svc,
		ForwardPort: "80",
	}, true
}

func ftwTargetIstio() (ftwTarget, bool) {
	svcRef := findIstioIngressService()
	if svcRef == "" {
		return ftwTarget{}, false
	}
	ns, svc := splitNSName(svcRef, "istio-system")
	// Gateway API managed pods: istio=ingressgateway in the Gateway namespace.
	// Helm gateway chart: app=istio-ingress in istio-system.
	logSel := "istio=ingressgateway"
	if out, err := kubectl("get", "pods", "-n", ns, "-l", logSel, "-o", "name"); err != nil || strings.TrimSpace(out) == "" {
		logSel = "app=istio-ingress"
		if out2, err2 := kubectl("get", "pods", "-n", ns, "-l", logSel, "-o", "name"); err2 != nil || strings.TrimSpace(out2) == "" {
			logSel = "app=istio-ingressgateway"
		}
	}
	// Istio proxy container name is istio-proxy (not envoy).
	return ftwTarget{
		Provider:    "istio",
		LogNS:       ns,
		LogSel:      logSel,
		ForwardNS:   ns,
		ForwardSvc:  svc,
		ForwardPort: "80",
	}, true
}

func ftwTargetCilium() (ftwTarget, bool) {
	svcRef := findCiliumGatewayService()
	if svcRef == "" {
		return ftwTarget{}, false
	}
	ns, svc := splitNSName(svcRef, demoNamespace)
	// Prefer gateway-owned pods; fall back to cilium-envoy in kube-system.
	logNS, logSel := ns, "io.cilium.gateway/owning-gateway=demo-gateway"
	if out, err := kubectl("get", "pods", "-n", logNS, "-l", logSel, "-o", "name"); err != nil || strings.TrimSpace(out) == "" {
		// Cilium 1.16+ often runs Envoy as a DaemonSet in kube-system.
		logNS, logSel = "kube-system", "k8s-app=cilium-envoy"
		if out2, err2 := kubectl("get", "pods", "-n", logNS, "-l", logSel, "-o", "name"); err2 != nil || strings.TrimSpace(out2) == "" {
			logNS, logSel = "kube-system", "app.kubernetes.io/name=cilium-envoy"
		}
	}
	return ftwTarget{
		Provider:    "cilium",
		LogNS:       logNS,
		LogSel:      logSel,
		ForwardNS:   ns,
		ForwardSvc:  svc,
		ForwardPort: "80",
	}, true
}

func runGoFTW(t ftwTarget) {
	GinkgoHelper()
	By(fmt.Sprintf("running CRS go-ftw against %s", t.Provider))

	// Do not use utils.Run: it resets cmd.Env and drops FTW_* variables.
	dir, err := utils.GetProjectDir()
	Expect(err).NotTo(HaveOccurred())
	script := filepath.Join(dir, "test", "e2e", "ftw", "run-ftw.sh")
	cmd := exec.Command("bash", script)
	cmd.Dir = dir
	logContainer := "envoy"
	if t.Provider == "istio" {
		logContainer = "istio-proxy"
	}
	// Cilium Envoy DaemonSet container is typically "cilium-envoy" or "envoy".
	if t.Provider == "cilium" {
		logContainer = "cilium-envoy"
	}
	cmd.Env = append(os.Environ(),
		"FTW_PROVIDER="+t.Provider,
		"FTW_LOG_NS="+t.LogNS,
		"FTW_LOG_SEL="+t.LogSel,
		"FTW_LOG_CONTAINER="+logContainer,
		"FTW_PF_NS="+t.ForwardNS,
		"FTW_PF_SVC="+t.ForwardSvc,
		"FTW_PF_PORT="+t.ForwardPort,
		"FTW_INCLUDE="+ftwInclude(),
		"FTW_HOST=demo.local",
	)
	if v := os.Getenv("E2E_FTW_CLOUDMODE"); v != "" {
		cmd.Env = append(cmd.Env, "FTW_CLOUDMODE="+v)
	}
	if v := os.Getenv("CRS_VERSION"); v != "" {
		cmd.Env = append(cmd.Env, "CRS_VERSION="+v)
	}
	if v := os.Getenv("GO_FTW_VERSION"); v != "" {
		cmd.Env = append(cmd.Env, "GO_FTW_VERSION="+v)
	}

	_, _ = fmt.Fprintf(GinkgoWriter, "running: %q (provider=%s include=%q)\n",
		strings.Join(cmd.Args, " "), t.Provider, ftwInclude())
	// Bound total wall time (script also uses `timeout` around docker go-ftw).
	cmd.Env = append(cmd.Env, "FTW_TIMEOUT=12m")
	out, err := cmd.CombinedOutput()
	if err != nil {
		Fail(fmt.Sprintf("go-ftw failed for %s: %v\n%s", t.Provider, err, string(out)))
	}
	_, _ = fmt.Fprintf(GinkgoWriter, "go-ftw output (%s):\n%s\n", t.Provider, string(out))
}

// pathBSmokeCRSFiles is the SecRule pack referenced by path-b-crs-ruleset.yaml
// (901/905/913/949/959/980). Full CRS is only applied when E2E_FTW_PATH_B_FULL=true.
var pathBSmokeCRSFiles = map[string]struct{}{
	"crs-request-901-initialization.yaml":       {},
	"crs-request-905-common-exceptions.yaml":    {},
	"crs-request-913-scanner-detection.yaml":    {},
	"crs-request-949-blocking-evaluation.yaml":  {},
	"crs-response-959-blocking-evaluation.yaml": {},
	"crs-response-980-correlation.yaml":         {},
}

func ftwPathBFull() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("E2E_FTW_PATH_B_FULL")))
	return v == "true" || v == "1" || v == "yes"
}

// applyStructuredCRSSamples installs Path B CRS SecRules from config/samples/crs/
// into the demo namespace (one CR per rule, multi-doc YAMLs).
func applyStructuredCRSSamples() {
	GinkgoHelper()
	full := ftwPathBFull()
	if full {
		By("applying full structured CRS SecRules (Path B samples)")
	} else {
		By("applying Path B smoke CRS SecRules (901/905/913/949/959/980)")
	}
	dir, err := utils.GetProjectDir()
	Expect(err).NotTo(HaveOccurred())
	crsDir := filepath.Join(dir, "config", "samples", "crs")
	// Apply request/response rule files only (skip ruleset/waf/optimized).
	entries, err := os.ReadDir(crsDir)
	Expect(err).NotTo(HaveOccurred(), "read %s", crsDir)
	var files []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			continue
		}
		if !strings.HasPrefix(name, "crs-request-") && !strings.HasPrefix(name, "crs-response-") {
			continue
		}
		if !full {
			if _, ok := pathBSmokeCRSFiles[name]; !ok {
				continue
			}
		}
		files = append(files, filepath.Join(crsDir, name))
	}
	Expect(files).NotTo(BeEmpty(), "no CRS sample rule files under %s", crsDir)
	for _, f := range files {
		_, err := kubectl("apply", "-n", demoNamespace, "-f", f)
		Expect(err).NotTo(HaveOccurred(), "apply CRS sample %s", f)
	}
	applyCRSPhraseLists()
	// Wait until a known CRS SecRule is present.
	Eventually(func(g Gomega) {
		out, err := kubectl("get", "secrules.seclang.kubewaf.io", "-n", demoNamespace,
			"-l", "app.kubernetes.io/part-of=coreruleset", "--no-headers")
		g.Expect(err).NotTo(HaveOccurred())
		// Smoke subset is ~119 CRs; full CRS samples ≈ 600+.
		min := 20
		if !full {
			min = 80
		}
		lines := strings.Split(strings.TrimSpace(out), "\n")
		g.Expect(len(lines)).To(BeNumerically(">", min), "expected many CRS SecRules, got:\n%s", out)
	}, 3*time.Minute, 3*time.Second).Should(Succeed())
}

func applyCRSPhraseLists() {
	GinkgoHelper()
	By("applying CRS PhraseLists for @pmFromFile basename discovery")
	_, err := kubectl("apply", "-n", demoNamespace, "-f",
		"config/samples/crs/phraselists/crs-data-phraselists.yaml")
	Expect(err).NotTo(HaveOccurred(), "apply CRS PhraseLists")
	Eventually(func(g Gomega) {
		out, err := kubectl("get", "phraselists.seclang.kubewaf.io", "-n", demoNamespace,
			"-l", "seclang.kubewaf.io/crs-data=true", "--no-headers")
		g.Expect(err).NotTo(HaveOccurred())
		lines := strings.Split(strings.TrimSpace(out), "\n")
		g.Expect(len(lines)).To(BeNumerically(">=", 21), "expected 21 CRS PhraseLists, got:\n%s", out)
	}, 2*time.Minute, 2*time.Second).Should(Succeed())
}

func applyPathBRuleset() {
	GinkgoHelper()
	path := "test/e2e/manifests/ftw/path-b-crs-ruleset.yaml"
	if ftwPathBFull() {
		path = "test/e2e/manifests/ftw/path-b-crs-ruleset-full.yaml"
		By("applying Path B full CRS RuleSet")
	} else {
		By("applying Path B smoke CRS RuleSet (901/905/913/949/959/980)")
	}
	applyFile(path)
	Eventually(func(g Gomega) {
		_, err := kubectl("get", "rulesets.waf.kubewaf.io", "ftw-crs-path-b", "-n", demoNamespace)
		g.Expect(err).NotTo(HaveOccurred())
	}, time.Minute, time.Second).Should(Succeed())
}

// waitForWAFPathBReady waits for Ready=True, or for ECDS/slot fields when status is slow
// under large Path B rule sets (leader lock churn).
func waitForWAFPathBReady(ns, name string, timeout time.Duration) {
	GinkgoHelper()
	Eventually(func(g Gomega) {
		ready, err := kubectl("get", wafResource, name, "-n", ns,
			"-o", "jsonpath={.status.conditions[?(@.type=='Ready')].status}")
		if err == nil && ready == "True" {
			return
		}
		// Fallback: dataplane has attached when these are populated.
		ecds, e1 := kubectl("get", wafResource, name, "-n", ns, "-o", "jsonpath={.status.ecdsResourceName}")
		slot, e2 := kubectl("get", wafResource, name, "-n", ns, "-o", "jsonpath={.status.slotKind}")
		g.Expect(e1).NotTo(HaveOccurred())
		g.Expect(e2).NotTo(HaveOccurred())
		if strings.TrimSpace(ecds) != "" && strings.TrimSpace(slot) != "" {
			return
		}
		g.Expect(ready).To(Equal("True"), "WAF not Ready (ready=%q ecds=%q slot=%q)", ready, ecds, slot)
	}, timeout, 3*time.Second).Should(Succeed())
}

// runProviderFTW is the shared FTW flow for each provider after WAF is Ready.
func runProviderFTW(provider, wafName string, targetFn func() (ftwTarget, bool)) {
	GinkgoHelper()
	if !ftwEnabled() && !ftwPathBEnabled() && !ftwPathAEnabled() {
		Skip("go-ftw disabled (set E2E_FTW_PATH_B=true, or E2E_FTW_PATH_A=true with full-catalog wasm)")
	}
	if !realWasmConfigured() {
		Skip("go-ftw requires modsecurity-proxy-wasm (embedded in operator image)")
	}

	// Data plane must be programmed before we rewrite routes / probe traffic.
	// Without this, FTW flaked with HTTP 000 while Gateway Programmed stayed False.
	if crdExists("gateways.gateway.networking.k8s.io") {
		waitForGatewayProgrammed(demoNamespace, "demo-gateway", 4*time.Minute)
	}

	target, ok := targetFn()
	if !ok {
		Skip(fmt.Sprintf("could not resolve go-ftw target for %s", provider))
	}
	// Prefer real Service port (EG may not use 80 as the first port on every version).
	if p := servicePort(target.ForwardNS, target.ForwardSvc); p != "" {
		target.ForwardPort = p
	}
	waitForServiceEndpoints(target.ForwardNS, target.ForwardSvc, 3*time.Minute)

	ensureAlbedoBackend()
	defer restoreHTTPBinRoute(provider)

	// Confirm L7 before the FTW overlay so a wedged proxy is obvious.
	waitForGatewayHTTPCode(target.ForwardNS, target.ForwardSvc, "demo.local", "/", "Mozilla/5.0",
		[]string{"200", "404", "403"}, 2*time.Minute,
		fmt.Sprintf("gateway not reachable before FTW profile (svc=%s/%s port=%s)",
			target.ForwardNS, target.ForwardSvc, target.ForwardPort))

	enableFTWProfileOnWAF(demoNamespace, wafName)
	defer disableFTWProfileOnWAF(demoNamespace, wafName)

	// Re-assert Ready after annotation (ECDS push).
	waitForWAFReady(demoNamespace, wafName, 3*time.Minute)

	// Smoke that gateway answers before go-ftw.
	// Probe "/" first (works for httpbin + albedo); /status/200 is albedo-specific.
	waitForGatewayHTTPCode(target.ForwardNS, target.ForwardSvc, "demo.local", "/", "Mozilla/5.0",
		[]string{"200", "404", "403"}, 3*time.Minute,
		fmt.Sprintf("gateway not reachable for FTW (svc=%s/%s port=%s)",
			target.ForwardNS, target.ForwardSvc, target.ForwardPort))

	runGoFTW(target)
}
