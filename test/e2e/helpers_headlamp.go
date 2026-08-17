//go:build e2e
// +build e2e

package e2e

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/kubewaf-io/kubewaf/test/utils"
)

const (
	headlampNS          = "headlamp"
	headlampRelease     = "headlamp"
	headlampPluginCM    = "kubewaf-headlamp-plugin"
	headlampLocalPort   = "4466"
	headlampHelmRepoURL = "https://kubernetes-sigs.github.io/headlamp/"
)

// headlampDP is the dataplane the screenshot suite attaches a Path B WAF to.
type headlampDP struct {
	provider string
	wafFile  string
	wafName  string
	gwFile   string
	findSvc  func() (ns, svc string)
}

func nsExists(name string) bool {
	_, err := kubectl("get", "ns", name)
	return err == nil
}

func pickHeadlampDataplane() headlampDP {
	switch {
	case crdExists("envoyproxies.gateway.envoyproxy.io") && nsExists("envoy-gateway-system"):
		return headlampDP{
			provider: "envoy-gateway",
			wafFile:  "test/e2e/manifests/envoygateway/waf-path-b.yaml",
			wafName:  "demo-waf-eg-path-b",
			gwFile:   "test/e2e/manifests/envoygateway/gateway.yaml",
			findSvc: func() (string, string) {
				return "envoy-gateway-system", findEnvoyGatewayService()
			},
		}
	case crdExists("envoyfilters.networking.istio.io"):
		return headlampDP{
			provider: "istio",
			wafFile:  "test/e2e/manifests/istio/waf-path-b.yaml",
			wafName:  "demo-waf-istio-path-b",
			gwFile:   "test/e2e/manifests/istio/gateway.yaml",
			findSvc: func() (string, string) {
				return splitNSName(findIstioIngressService(), demoNamespace)
			},
		}
	case crdExists("ciliumenvoyconfigs.cilium.io"):
		return headlampDP{
			provider: "cilium",
			wafFile:  "test/e2e/manifests/cilium/waf-path-b.yaml",
			wafName:  "demo-waf-cilium-path-b",
			gwFile:   "test/e2e/manifests/cilium/gateway.yaml",
			findSvc: func() (string, string) {
				return splitNSName(findCiliumGatewayService(), demoNamespace)
			},
		}
	default:
		return headlampDP{}
	}
}

func headlampEnabled() bool {
	if e2eProvider() == "headlamp" {
		return true
	}
	v := strings.ToLower(strings.TrimSpace(os.Getenv("E2E_HEADLAMP")))
	return v == "true" || v == "1" || v == "yes"
}

func headlampPluginDir() string {
	if v := strings.TrimSpace(os.Getenv("HEADLAMP_PLUGIN_DIR")); v != "" {
		return v
	}
	dir, err := utils.GetProjectDir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, "headlamp-plugin")
}

func applyFullPathBCRS() {
	GinkgoHelper()
	// Must set this before applyStructuredCRSSamples so the full SecRule pack
	// is installed (smoke mode otherwise skips 600-rule files).
	Expect(os.Setenv("E2E_FTW_PATH_B_FULL", "true")).To(Succeed())
	applyStructuredCRSSamples()
	applyPathBRuleset()
}

func installPathBWAFForHeadlamp(dp headlampDP) {
	GinkgoHelper()
	Expect(dp.wafName).NotTo(BeEmpty(), "no Gateway / Istio / Cilium dataplane in this cluster")
	if dp.gwFile != "" {
		applyFile(dp.gwFile)
		waitForGatewayProgrammed(demoNamespace, "demo-gateway", 4*time.Minute)
	}
	ensureExclusiveWAF(demoNamespace, "")
	applyFile(dp.wafFile)
	patchWAFTelemetry(demoNamespace, dp.wafName, "Managed")
	waitForWAFPathBReady(demoNamespace, dp.wafName, 6*time.Minute)
	Expect(wafStatusField(demoNamespace, dp.wafName, "{.spec.crsEnable}")).
		NotTo(Equal("true"), "Path B WAF must have crsEnable=false")
}

func generatePathBTraffic(dp headlampDP) {
	GinkgoHelper()
	if os.Getenv("E2E_HEADLAMP_SKIP_TRAFFIC") == "true" {
		By("skipping sample traffic (E2E_HEADLAMP_SKIP_TRAFFIC=true)")
		return
	}
	ns, svc := dp.findSvc()
	if svc == "" {
		By(fmt.Sprintf("skipping sample traffic: no %s proxy Service", dp.provider))
		return
	}
	host := "demo.local"

	// Benign + several CRS-shaped attacks so the Headlamp request/noisy tables have rows.
	requests := []struct {
		path string
		ua   string
	}{
		{"/get", "Mozilla/5.0"},
		{"/get", "sqlmap/1.7.2"},
		{"/get", "Nikto/2.1.5"},
		{"/get?id=1'+OR+'1'%3D'1", "Mozilla/5.0"},
		{"/get?q=%3Cscript%3Ealert(1)%3C/script%3E", "Mozilla/5.0"},
		{"/get?file=../../../../etc/passwd", "Mozilla/5.0"},
	}
	By(fmt.Sprintf("sending Path B sample traffic through %s", dp.provider))
	first := curlGatewayHTTP(ns, svc, host, requests[0].path, requests[0].ua)
	if first == "" || first == "000" {
		By("skipping remaining sample traffic: dataplane did not answer")
		return
	}
	for _, r := range requests[1:] {
		_ = curlGatewayHTTP(ns, svc, host, r.path, r.ua)
	}
}

func buildHeadlampPlugin() string {
	GinkgoHelper()
	pluginDir := headlampPluginDir()
	mainJS := filepath.Join(pluginDir, "dist", "main.js")
	if _, err := os.Stat(mainJS); err == nil && os.Getenv("E2E_HEADLAMP_REBUILD_PLUGIN") != "true" {
		By("using existing headlamp-plugin/dist/main.js")
		return pluginDir
	}
	_, err := os.Stat(filepath.Join(pluginDir, "package.json"))
	Expect(err).NotTo(HaveOccurred(),
		"headlamp plugin not found at %s (set HEADLAMP_PLUGIN_DIR)", pluginDir)
	By("building Headlamp plugin")
	cmd := exec.Command("npm", "run", "build")
	cmd.Dir = pluginDir
	_, err = utils.Run(cmd)
	Expect(err).NotTo(HaveOccurred(), "npm run build in %s", pluginDir)
	_, err = os.Stat(mainJS)
	Expect(err).NotTo(HaveOccurred(), "plugin build did not produce %s", mainJS)
	return pluginDir
}

func installHeadlampWithPlugin() {
	GinkgoHelper()
	pluginDir := buildHeadlampPlugin()
	dir, err := utils.GetProjectDir()
	Expect(err).NotTo(HaveOccurred())

	By("creating Headlamp namespace + plugin ConfigMap")
	_, _ = kubectl("create", "ns", headlampNS)
	mainJS := filepath.Join(pluginDir, "dist", "main.js")
	pkgJSON := filepath.Join(dir, "test", "e2e", "manifests", "headlamp", "plugin-package.json")
	_, _ = kubectl("delete", "configmap", headlampPluginCM, "-n", headlampNS, "--ignore-not-found")
	_, err = kubectl("create", "configmap", headlampPluginCM, "-n", headlampNS,
		"--from-file=main.js="+mainJS,
		"--from-file=package.json="+pkgJSON)
	Expect(err).NotTo(HaveOccurred(), "create plugin ConfigMap")

	By("installing Headlamp via Helm")
	cmd := exec.Command("helm", "repo", "add", "headlamp", headlampHelmRepoURL, "--force-update")
	_, err = utils.Run(cmd)
	Expect(err).NotTo(HaveOccurred(), "helm repo add headlamp")
	cmd = exec.Command("helm", "repo", "update", "headlamp")
	_, _ = utils.Run(cmd)

	values := filepath.Join(dir, "test", "e2e", "manifests", "headlamp", "values.yaml")
	cmd = exec.Command("helm", "upgrade", "--install", headlampRelease, "headlamp/headlamp",
		"--namespace", headlampNS,
		"--create-namespace",
		"-f", values,
		"--timeout=3m")
	_, err = utils.Run(cmd)
	Expect(err).NotTo(HaveOccurred(), "helm install headlamp")

	// Kind + Cilium: a CNI timeout leaves the pod in ContainerCreating. hostNetwork
	// skips endpoint allocation so Headlamp can still come up for screenshots.
	_, _ = kubectl("patch", "deploy", headlampRelease, "-n", headlampNS, "--type=json",
		"-p", `[{"op":"add","path":"/spec/template/spec/hostNetwork","value":true},{"op":"add","path":"/spec/template/spec/dnsPolicy","value":"ClusterFirstWithHostNet"}]`)
	_, _ = kubectl("delete", "pod", "-n", headlampNS, "-l", "app.kubernetes.io/name=headlamp", "--force", "--grace-period=0")
	waitForDeployment(headlampNS, headlampRelease, 3*time.Minute)

	// Extra grant for Alt B query subresources (cluster-admin already covers it).
	if _, err := kubectl("get", "clusterrole", "kubewaf-query"); err == nil {
		_, _ = kubectl("create", "clusterrolebinding", "headlamp-kubewaf-query",
			"--clusterrole=kubewaf-query",
			"--serviceaccount="+headlampNS+":"+headlampRelease)
	}
}

func startHeadlampPortForward() func() {
	GinkgoHelper()
	By(fmt.Sprintf("port-forward Headlamp svc/%s → localhost:%s", headlampRelease, headlampLocalPort))
	cmd := exec.Command("kubectl", "port-forward", "-n", headlampNS,
		"svc/"+headlampRelease, headlampLocalPort+":80")
	cmd.Stdout = GinkgoWriter
	cmd.Stderr = GinkgoWriter
	Expect(cmd.Start()).To(Succeed(), "start kubectl port-forward")
	Eventually(func(g Gomega) {
		c, err := net.DialTimeout("tcp", "127.0.0.1:"+headlampLocalPort, time.Second)
		g.Expect(err).NotTo(HaveOccurred())
		_ = c.Close()
	}, 30*time.Second, 500*time.Millisecond).Should(Succeed())
	return func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
		}
	}
}

func runHeadlampPlaywrightCmd(pwDir, shotDir string, extraEnv []string) ([]byte, error) {
	// Prefer the official Playwright image so we do not download Chromium
	// from cdn.playwright.dev (often rate-limited). Falls back to host npx.
	img := strings.TrimSpace(os.Getenv("E2E_HEADLAMP_PLAYWRIGHT_IMAGE"))
	if img == "" {
		img = "mcr.microsoft.com/playwright:v1.55.0-noble"
	}
	if _, err := exec.LookPath("docker"); err == nil && os.Getenv("E2E_HEADLAMP_NO_DOCKER") != "true" {
		script := `set -e
mkdir -p /tmp/pw/artifacts
cd /tmp/pw
npm init -y >/dev/null
PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 npm install --no-audit --no-fund @playwright/test@1.55.0
cp /src/screenshots.spec.ts .
export PLAYWRIGHT_BROWSERS_PATH=/ms-playwright
export HEADLAMP_SCREENSHOT_DIR=/tmp/pw/artifacts
status=0
npx playwright test screenshots.spec.ts --timeout=180000 --workers=1 --reporter=list || status=$?
cp -a /tmp/pw/artifacts/. /out/ 2>/dev/null || true
cp -a /tmp/pw/test-results /out/test-results 2>/dev/null || true
exit "$status"
`
		args := []string{
			"run", "--rm", "--network=host",
			"-u", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()),
			"-e", "HOME=/tmp",
			"-e", "npm_config_cache=/tmp/npm-cache",
			"-v", filepath.Join(pwDir, "screenshots.spec.ts") + ":/src/screenshots.spec.ts:ro",
			"-v", shotDir + ":/out",
		}
		for _, e := range extraEnv {
			if strings.HasPrefix(e, "HEADLAMP_SCREENSHOT_DIR=") {
				continue
			}
			args = append(args, "-e", e)
		}
		args = append(args, img, "bash", "-lc", script)
		cmd := exec.Command("docker", args...)
		return cmd.CombinedOutput()
	}

	install := exec.Command("npm", "install")
	install.Dir = pwDir
	if out, err := install.CombinedOutput(); err != nil {
		return out, err
	}
	cmd := exec.Command("npx", "playwright", "test")
	cmd.Dir = pwDir
	cmd.Env = append(os.Environ(), extraEnv...)
	return cmd.CombinedOutput()
}

func runHeadlampPlaywright(wafName string) {
	GinkgoHelper()
	dir, err := utils.GetProjectDir()
	Expect(err).NotTo(HaveOccurred())
	pwDir := filepath.Join(dir, "test", "e2e", "headlamp")
	shotDir := os.Getenv("HEADLAMP_SCREENSHOT_DIR")
	if shotDir == "" {
		shotDir = filepath.Join(pwDir, "artifacts")
	}
	Expect(os.MkdirAll(shotDir, 0o755)).To(Succeed())

	By("running Headlamp Playwright screenshots")
	env := []string{
		"HEADLAMP_URL=http://127.0.0.1:" + headlampLocalPort,
		"HEADLAMP_CLUSTER=main",
		"WAF_NS=" + demoNamespace,
		"WAF_NAME=" + wafName,
		"RULESET_NAME=ftw-crs-path-b",
		"HEADLAMP_SCREENSHOT_DIR=" + shotDir,
	}
	out, err := runHeadlampPlaywrightCmd(pwDir, shotDir, env)
	_, _ = fmt.Fprintf(GinkgoWriter, "playwright output:\n%s\n", string(out))
	Expect(err).NotTo(HaveOccurred(), "playwright test failed:\n%s", string(out))

	entries, err := os.ReadDir(shotDir)
	Expect(err).NotTo(HaveOccurred())
	var pngs []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".png") {
			pngs = append(pngs, e.Name())
		}
	}
	Expect(pngs).To(ContainElements(
		"01-overview.png",
		"02-waf-list.png",
		"03-waf-detail.png",
		"04-waf-detail-live.png",
		"05-ruleset-detail.png",
		"06-secrules-list.png",
		"08-observe.png",
		"09-observe-logs.png",
		"10-observe-metrics.png",
	), "missing Headlamp screenshots in %s", shotDir)
	By(fmt.Sprintf("Headlamp screenshots written to %s (%d pngs)", shotDir, len(pngs)))
}
