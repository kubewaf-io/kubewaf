//go:build e2e
// +build e2e

package e2e

import (
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/kubewaf-io/kubewaf/test/utils"
)

const (
	// operatorNamespace is where kubeWAF is installed for provider e2e.
	operatorNamespace = "kubewaf-system"
	// demoNamespace hosts the test app + WAF policies.
	demoNamespace = "demo"
	// When empty, e2e generates a placeholder .wasm so the operator can serve it
	// (resource-level tests pass; traffic blocking needs a real modsecurity-proxy-wasm binary).
	defaultProjectImage = "ghcr.io/kubewaf-io/kubewaf:e2e"
)

func projectImage() string {
	if v := os.Getenv("E2E_IMG"); v != "" {
		return v
	}
	return defaultProjectImage
}

// splitImageRepoTag splits "registry/repo:tag" into ("registry/repo", "tag").
// Used to map E2E_IMG onto Makefile CONTROLLER_IMG + KO_TAGS for ko.
func splitImageRepoTag(img string) (repo, tag string) {
	i := strings.LastIndex(img, ":")
	if i > 0 && !strings.Contains(img[i+1:], "/") {
		return img[:i], img[i+1:]
	}
	return img, "latest"
}

func e2eProvider() string {
	p := strings.ToLower(strings.TrimSpace(os.Getenv("E2E_PROVIDER")))
	if p == "" {
		return "all"
	}
	return p
}

func providerEnabled(name string) bool {
	p := e2eProvider()
	return p == "all" || p == name || p == strings.ReplaceAll(name, "-", "")
}

func kubectl(args ...string) (string, error) {
	cmd := exec.Command("kubectl", args...)
	return utils.Run(cmd)
}

func kubectlOK(args ...string) string {
	GinkgoHelper()
	out, err := kubectl(args...)
	Expect(err).NotTo(HaveOccurred(), "kubectl %v", args)
	return out
}

func applyFile(path string) {
	GinkgoHelper()
	_, err := kubectl("apply", "-f", path)
	Expect(err).NotTo(HaveOccurred(), "apply %s", path)
}

func deleteFile(path string) {
	GinkgoHelper()
	_, _ = kubectl("delete", "-f", path, "--ignore-not-found")
}

func waitForDeployment(ns, name string, timeout time.Duration) {
	GinkgoHelper()
	Eventually(func(g Gomega) {
		out, err := kubectl("get", "deploy", name, "-n", ns, "-o", "jsonpath={.status.availableReplicas}")
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(out).NotTo(BeEmpty())
		g.Expect(out).NotTo(Equal("0"))
	}, timeout, 2*time.Second).Should(Succeed())
}

// wafResource is the fully-qualified WAF CRD. Bare "waf" is ambiguous: it is both the
// shortName of kind WAF and a kubectl category that includes SecRule/RuleSet/WAF.
const wafResource = "wafs.waf.kubewaf.io"

func waitForWAFReady(ns, name string, timeout time.Duration) {
	GinkgoHelper()
	Eventually(func(g Gomega) {
		out, err := kubectl("get", wafResource, name, "-n", ns,
			"-o", "jsonpath={.status.conditions[?(@.type=='Ready')].status}")
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(out).To(Equal("True"), "WAF not Ready")
	}, timeout, 2*time.Second).Should(Succeed())
}

func wafStatusField(ns, name, jsonPath string) string {
	GinkgoHelper()
	out, err := kubectl("get", wafResource, name, "-n", ns, "-o", "jsonpath="+jsonPath)
	Expect(err).NotTo(HaveOccurred())
	return out
}

// gatewayCondition returns the status of a Gateway API condition (e.g. Programmed, Accepted).
func gatewayCondition(ns, name, condType string) string {
	out, err := kubectl("get", "gateways.gateway.networking.k8s.io", name, "-n", ns,
		"-o", fmt.Sprintf("jsonpath={.status.conditions[?(@.type=='%s')].status}", condType))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

// waitForGatewayProgrammed waits until the Gateway is usable for data-plane tests.
// Prefer Programmed=True; accept Accepted=True with at least one status address when
// Programmed is slow/missing (some EG versions briefly report Programmed=False).
func waitForGatewayProgrammed(ns, name string, timeout time.Duration) {
	GinkgoHelper()
	Eventually(func(g Gomega) {
		_, err := kubectl("get", "gateways.gateway.networking.k8s.io", name, "-n", ns)
		g.Expect(err).NotTo(HaveOccurred())

		programmed := gatewayCondition(ns, name, "Programmed")
		if programmed == "True" {
			return
		}
		accepted := gatewayCondition(ns, name, "Accepted")
		addrs, _ := kubectl("get", "gateways.gateway.networking.k8s.io", name, "-n", ns,
			"-o", "jsonpath={.status.addresses[*].value}")
		if accepted == "True" && strings.TrimSpace(addrs) != "" {
			return
		}
		// Last resort: dump conditions so CI logs show why we waited out.
		msg, _ := kubectl("get", "gateways.gateway.networking.k8s.io", name, "-n", ns,
			"-o", "jsonpath={range .status.conditions[*]}{.type}={.status} ({.reason}: {.message}); {end}")
		g.Expect(programmed).To(Equal("True"),
			"Gateway %s/%s not programmed (Programmed=%q Accepted=%q addresses=%q); conditions: %s",
			ns, name, programmed, accepted, strings.TrimSpace(addrs), msg)
	}, timeout, 3*time.Second).Should(Succeed())
}

// waitForServiceEndpoints waits until a Service has at least one ready endpoint address.
func waitForServiceEndpoints(ns, svc string, timeout time.Duration) {
	GinkgoHelper()
	Eventually(func(g Gomega) {
		// Classic Endpoints (still populated for most EG/Istio Services).
		out, err := kubectl("get", "endpoints", svc, "-n", ns,
			"-o", "jsonpath={.subsets[*].addresses[*].ip}")
		if err != nil || strings.TrimSpace(out) == "" {
			// EndpointSlice fallback (some clusters only have slices).
			out2, err2 := kubectl("get", "endpointslices", "-n", ns,
				"-l", "kubernetes.io/service-name="+svc,
				"-o", "jsonpath={.items[*].endpoints[*].addresses[*]}")
			g.Expect(err2).NotTo(HaveOccurred(), "endpoints/endpointslices for %s/%s", ns, svc)
			g.Expect(strings.TrimSpace(out2)).NotTo(BeEmpty(), "no ready endpoints for Service %s/%s", ns, svc)
			return
		}
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(strings.TrimSpace(out)).NotTo(BeEmpty(), "no ready endpoints for Service %s/%s", ns, svc)
	}, timeout, 2*time.Second).Should(Succeed())
}

// servicePort returns the best HTTP Service port (default "80").
// Istio Gateway Services list status-port (15021) first, then http (80) — using
// ports[0] made e2e curl the status admin endpoint and get 404 forever.
func servicePort(ns, svc string) string {
	// Prefer named http / appProtocol=http, then bare 80, then first non-status port.
	type port struct{ name, port, appProto string }
	// Use '|' separators — more reliable than tabs in kubectl jsonpath.
	raw, err := kubectl("get", "svc", svc, "-n", ns,
		"-o", `jsonpath={range .spec.ports[*]}{.name}{"|"}{.port}{"|"}{.appProtocol}{"\n"}{end}`)
	if err != nil || strings.TrimSpace(raw) == "" {
		// Fallback: first port only.
		out, err2 := kubectl("get", "svc", svc, "-n", ns, "-o", "jsonpath={.spec.ports[0].port}")
		if err2 != nil || strings.TrimSpace(out) == "" {
			return "80"
		}
		return strings.TrimSpace(out)
	}
	var ports []port
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Split(line, "|")
		for len(parts) < 3 {
			parts = append(parts, "")
		}
		ports = append(ports, port{name: parts[0], port: parts[1], appProto: parts[2]})
	}
	isStatus := func(p port) bool {
		n := strings.ToLower(p.name)
		return p.port == "15021" || p.port == "15020" ||
			strings.Contains(n, "status") || strings.Contains(n, "metrics") ||
			strings.Contains(n, "admin")
	}
	// 1) name http / http-*
	for _, p := range ports {
		n := strings.ToLower(p.name)
		if n == "http" || strings.HasPrefix(n, "http-") || n == "http2" {
			return p.port
		}
	}
	// 2) appProtocol http*
	for _, p := range ports {
		ap := strings.ToLower(p.appProto)
		if strings.HasPrefix(ap, "http") {
			return p.port
		}
	}
	// 3) port 80 / 8080
	for _, p := range ports {
		if p.port == "80" || p.port == "8080" {
			return p.port
		}
	}
	// 4) first non-status
	for _, p := range ports {
		if !isStatus(p) && p.port != "" {
			return p.port
		}
	}
	if len(ports) > 0 && ports[0].port != "" {
		return ports[0].port
	}
	return "80"
}

// curlHTTPCodeMarker is printed by curl -w so we can extract the status even when
// kubectl appends extra lines on the same stdout stream.
const curlHTTPCodeMarker = "__KUBEWAF_HTTP_CODE__="

// Long-lived probe pod reused by curlFromClusterInNS*. Creating a new
// `kubectl run --rm` pod on every Eventually tick flooded Kind (HTTP 000)
// during Path B FTW while Envoy was still up.
const curlProbePodName = "e2e-curl-probe"

var curlProbeMu sync.Mutex

// curlFromCluster runs curl inside a probe pod and returns status code + body snippet.
// Prefer curlFromClusterInNS so the probe pod shares the target Service namespace.
func curlFromCluster(host, path, userAgent string) (status string, body string) {
	return curlFromClusterInNS("", host, path, userAgent)
}

// curlFromClusterInNS is like curlFromCluster but schedules the probe pod in ns
// (empty ns → default). Running beside the gateway Service avoids flaky DNS/CNI races.
func curlFromClusterInNS(ns, host, path, userAgent string) (status string, body string) {
	return curlFromClusterInNSWithHeaders(ns, host, path, userAgent, nil)
}

func curlProbeNamespace(ns string) string {
	if ns == "" {
		return "default"
	}
	return ns
}

func ensureCurlProbePod(ns string) error {
	curlProbeMu.Lock()
	defer curlProbeMu.Unlock()
	ns = curlProbeNamespace(ns)
	phase, err := kubectl("get", "pod", curlProbePodName, "-n", ns, "-o", "jsonpath={.status.phase}")
	if err == nil && strings.TrimSpace(phase) == "Running" {
		return nil
	}
	_, _ = kubectl("delete", "pod", curlProbePodName, "-n", ns, "--ignore-not-found", "--wait=false")
	if _, err := kubectl("run", curlProbePodName, "-n", ns,
		"--restart=Never",
		"--image=curlimages/curl:8.5.0",
		"--labels=e2e.kubewaf.io/probe=true",
		"--command", "--", "sleep", "7200"); err != nil {
		return err
	}
	_, err = kubectl("wait", "--for=condition=Ready", "pod/"+curlProbePodName, "-n", ns, "--timeout=90s")
	return err
}

func curlExecArgs(ns, host, path, userAgent string, headers map[string]string) []string {
	ua := userAgent
	if ua == "" {
		ua = "e2e-client"
	}
	writeOut := curlHTTPCodeMarker + "%{http_code}"
	args := []string{"exec", curlProbePodName, "-n", curlProbeNamespace(ns), "--",
		"curl", "-sS", "-o", "/tmp/e2e-curl-body",
		"-w", writeOut,
		"-H", "Host: " + host,
		"-H", "User-Agent: " + ua,
	}
	for k, v := range headers {
		args = append(args, "-H", k+": "+v)
	}
	return append(args, "--connect-timeout", "5", "--max-time", "15", path)
}

// curlFromClusterInNSWithHeaders adds optional extra -H headers to the probe curl.
func curlFromClusterInNSWithHeaders(ns, host, path, userAgent string, headers map[string]string) (status string, body string) {
	GinkgoHelper()
	if err := ensureCurlProbePod(ns); err != nil {
		return "000", err.Error()
	}
	out, err := kubectl(curlExecArgs(ns, host, path, userAgent, headers)...)
	status = extractHTTPCode(out)
	if status == "" && err != nil {
		// Probe pod may have died mid-suite; recreate once.
		_, _ = kubectl("delete", "pod", curlProbePodName, "-n", curlProbeNamespace(ns),
			"--ignore-not-found", "--wait=false")
		if recErr := ensureCurlProbePod(ns); recErr == nil {
			out, err = kubectl(curlExecArgs(ns, host, path, userAgent, headers)...)
			status = extractHTTPCode(out)
		}
	}
	if status == "" && err != nil {
		// Connection failures often surface as empty status; normalize for Eventually messages.
		if out == "" {
			return "000", err.Error()
		}
		return "000", out
	}
	if status == "" {
		return "000", out
	}
	return status, out
}

// extractHTTPCode finds the curl -w marker, else a leading/standalone 3-digit HTTP code.
func extractHTTPCode(out string) string {
	if i := strings.LastIndex(out, curlHTTPCodeMarker); i >= 0 {
		rest := out[i+len(curlHTTPCodeMarker):]
		code := make([]byte, 0, 3)
		for _, r := range rest {
			if r >= '0' && r <= '9' {
				code = append(code, byte(r))
				if len(code) == 3 {
					return string(code)
				}
				continue
			}
			if len(code) > 0 {
				break
			}
		}
	}
	// Fallback: first standalone 3-digit token that looks like an HTTP status.
	for _, field := range strings.Fields(out) {
		if len(field) == 3 && field[0] >= '1' && field[0] <= '5' {
			ok := true
			for j := 0; j < 3; j++ {
				if field[j] < '0' || field[j] > '9' {
					ok = false
					break
				}
			}
			if ok {
				return field
			}
		}
	}
	return ""
}

// curlGatewayHTTP curls a ClusterIP gateway Service from an in-cluster probe pod.
// urlPath should start with "/". Port is taken from the Service when possible.
func curlGatewayHTTP(ns, svc, host, urlPath, userAgent string) (statusCode string) {
	return curlGatewayHTTPWithHeaders(ns, svc, host, urlPath, userAgent, nil)
}

// curlGatewayHTTPWithHeaders is curlGatewayHTTP plus extra request headers.
func curlGatewayHTTPWithHeaders(ns, svc, host, urlPath, userAgent string, headers map[string]string) (statusCode string) {
	GinkgoHelper()
	code, _ := curlGatewayHTTPDetail(ns, svc, host, urlPath, userAgent, headers)
	return code
}

// assertGatewayBlocksScannerUA is the shared provider traffic smoke:
// benign Mozilla UA → 200, scanner sqlmap UA → 403 (via common/rules.yaml).
// Used by Envoy Gateway, Istio, and Cilium dataplane e2e.
func assertGatewayBlocksScannerUA(ns, svc, host string) {
	GinkgoHelper()
	if host == "" {
		host = "demo.local"
	}
	By("sending benign request")
	waitForGatewayHTTPCode(ns, svc, host, "/get", "Mozilla/5.0", []string{"200"}, 3*time.Minute, "benign request should pass")

	By("sending sqlmap User-Agent (should be blocked)")
	waitForGatewayHTTPCode(ns, svc, host, "/get", "sqlmap/1.0", []string{"403"}, 2*time.Minute, "scanner UA should be denied")
}

func truncateForLog(s string, n int) string {
	s = strings.TrimSpace(s)
	if n <= 0 || len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// waitForGatewayHTTPCode polls the gateway until one of want codes is returned.
// Persistent HTTP 000 (connect failure) after 45s bounces the Envoy Gateway
// proxy once — Path B wasm reloads have wedged the listener on Kind.
func waitForGatewayHTTPCode(ns, svc, host, urlPath, userAgent string, want []string, timeout time.Duration, msg string) {
	GinkgoHelper()
	bounced := false
	start := time.Now()
	Eventually(func(g Gomega) {
		code, body := curlGatewayHTTPDetail(ns, svc, host, urlPath, userAgent, nil)
		if code == "000" && !bounced && time.Since(start) > 45*time.Second && ns == "envoy-gateway-system" {
			bounceEnvoyGatewayPods()
			bounced = true
			waitForServiceEndpoints(ns, svc, 2*time.Minute)
		}
		g.Expect(want).To(ContainElement(code), "%s: got %s body=%s", msg, code, truncateForLog(body, 400))
	}, timeout, 5*time.Second).Should(Succeed())
}

func curlGatewayHTTPDetail(ns, svc, host, urlPath, userAgent string, headers map[string]string) (code, body string) {
	GinkgoHelper()
	if !strings.HasPrefix(urlPath, "/") {
		urlPath = "/" + urlPath
	}
	port := servicePort(ns, svc)
	target := fmt.Sprintf("http://%s.%s.svc.cluster.local:%s%s", svc, ns, port, urlPath)
	return curlFromClusterInNSWithHeaders(ns, host, target, userAgent, headers)
}

func bounceEnvoyGatewayPods() {
	By("deleting Envoy Gateway proxy pods after persistent HTTP 000")
	pods, _ := kubectl("get", "pods", "-n", "envoy-gateway-system",
		"-l", "gateway.envoyproxy.io/owning-gateway-name=demo-gateway", "-o", "wide")
	_, _ = fmt.Fprintf(GinkgoWriter, "envoy proxy pods:\n%s\n", pods)
	logs, _ := kubectl("logs", "-n", "envoy-gateway-system",
		"-l", "gateway.envoyproxy.io/owning-gateway-name=demo-gateway",
		"-c", "envoy", "--tail=80")
	_, _ = fmt.Fprintf(GinkgoWriter, "envoy logs:\n%s\n", logs)
	_, _ = kubectl("delete", "pod", "-n", "envoy-gateway-system",
		"-l", "gateway.envoyproxy.io/owning-gateway-name=demo-gateway", "--wait=false")
}

// recoverEnvoyGatewayAfterPathB restores httpbin routing and waits until the
// proxy answers again so later provider specs are not poisoned by a wedged Envoy.
func recoverEnvoyGatewayAfterPathB() {
	restoreHTTPBinRoute("envoy-gateway")
	svc := findEnvoyGatewayService()
	if svc == "" {
		return
	}
	waitForServiceEndpoints("envoy-gateway-system", svc, 2*time.Minute)
	// Best-effort: do not fail the suite here; provider specs re-assert.
	code, body := curlGatewayHTTPDetail("envoy-gateway-system", svc, "demo.local", "/get", "Mozilla/5.0", nil)
	if code == "000" {
		bounceEnvoyGatewayPods()
		waitForServiceEndpoints("envoy-gateway-system", svc, 2*time.Minute)
		code, body = curlGatewayHTTPDetail("envoy-gateway-system", svc, "demo.local", "/get", "Mozilla/5.0", nil)
	}
	_, _ = fmt.Fprintf(GinkgoWriter, "gateway after Path B cleanup: code=%s body=%s\n", code, truncateForLog(body, 200))
}

// trafficOptIn returns true unless envKey is explicitly false/0/no/off.
// Empty/unset defaults to true so provider smoke runs real traffic like EG.
// Used for E2E_ISTIO_TRAFFIC and E2E_CILIUM_TRAFFIC (go-ftw still uses explicit true).
func trafficOptIn(envKey string) bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(envKey)))
	switch v {
	case "false", "0", "no", "off":
		return false
	default:
		return true
	}
}

// applyCiliumECDSBootstrap merges STATIC kubewaf_ecds into cilium-envoy bootstrap
// (ApiConfigSource rejects CEC-defined clusters). Helm-upgrade is skipped when
// Cilium already references the bootstrap ConfigMap.
func applyCiliumECDSBootstrap() {
	GinkgoHelper()
	By("merging kubewaf_ecds into Cilium Envoy bootstrap")
	args := []string{
		"--apply",
		"--ecds-namespace", operatorNamespace,
		"--ecds-service", "kubewaf-ecds",
		"--otel-service", "kubewaf-otel-collector",
	}
	if !ciliumEnvoyBootstrapConfigured() {
		args = append(args, "--helm-upgrade")
	}
	cmd := exec.Command("hack/scripts/merge-cilium-envoy-ecds-bootstrap.sh", args...)
	out, err := utils.Run(cmd)
	Expect(err).NotTo(HaveOccurred(), "merge Cilium Envoy ECDS bootstrap: %s", out)
}

func ciliumEnvoyBootstrapConfigured() bool {
	cmd := exec.Command("helm", "get", "values", "cilium", "-n", "kube-system", "-o", "json")
	out, err := utils.Run(cmd)
	if err != nil {
		return false
	}
	return strings.Contains(out, `"bootstrapConfigMap": "cilium-envoy-bootstrap-kubewaf"`) ||
		strings.Contains(out, `"bootstrapConfigMap":"cilium-envoy-bootstrap-kubewaf"`)
}

// applyIstioECDSBootstrap installs the bootstrap-static kubewaf_ecds ConfigMap
// required for Istio Gateway Envoy to accept ECDS Wasm filters.
func applyIstioECDSBootstrap() {
	GinkgoHelper()
	By("applying Istio ECDS bootstrap ConfigMap")
	applyFile("test/e2e/manifests/istio/ecds-bootstrap.yaml")
}

// ensureIstioGatewayServiceClusterIP forces demo-gateway-istio (and similar) to
// ClusterIP. Istio defaults to LoadBalancer; without a cloud LB, EXTERNAL-IP
// stays pending and Gateway Programmed=AddressNotAssigned. Prefer setting
// networking.istio.io/service-type=ClusterIP on the Gateway; this patches the
// Service if it already exists as LoadBalancer.
func ensureIstioGatewayServiceClusterIP() {
	GinkgoHelper()
	By("ensuring Istio Gateway Service is ClusterIP")
	// Annotation is the durable fix (controller rewrites Service from Gateway).
	_, _ = kubectl("annotate", "gateways.gateway.networking.k8s.io", "demo-gateway",
		"-n", demoNamespace, "networking.istio.io/service-type=ClusterIP", "--overwrite")
	// Direct patch if the Service is already present.
	for _, name := range []string{"demo-gateway-istio"} {
		typ, err := kubectl("get", "svc", name, "-n", demoNamespace, "-o", "jsonpath={.spec.type}")
		if err != nil {
			continue
		}
		if strings.TrimSpace(typ) != "ClusterIP" {
			_, _ = kubectl("patch", "svc", name, "-n", demoNamespace, "--type=merge",
				"-p", `{"spec":{"type":"ClusterIP"}}`)
		}
	}
	// Wait until the managed Service is ClusterIP (controller creates it shortly).
	Eventually(func(g Gomega) {
		typ, err := kubectl("get", "svc", "demo-gateway-istio", "-n", demoNamespace,
			"-o", "jsonpath={.spec.type}")
		g.Expect(err).NotTo(HaveOccurred(), "waiting for demo-gateway-istio Service")
		if strings.TrimSpace(typ) != "ClusterIP" {
			_, _ = kubectl("patch", "svc", "demo-gateway-istio", "-n", demoNamespace, "--type=merge",
				"-p", `{"spec":{"type":"ClusterIP"}}`)
		}
		typ2, err2 := kubectl("get", "svc", "demo-gateway-istio", "-n", demoNamespace,
			"-o", "jsonpath={.spec.type}")
		g.Expect(err2).NotTo(HaveOccurred())
		g.Expect(strings.TrimSpace(typ2)).To(Equal("ClusterIP"))
	}, 2*time.Minute, 2*time.Second).Should(Succeed())
}

// ensureIstioGatewayBootstrapMount patches the Istio Gateway Deployment so the
// proxy agent merges ecds-bootstrap ConfigMap into Envoy bootstrap.
//
// sidecar.istio.io/bootstrapOverride is honored by the *sidecar injector*, which
// mounts the CM and sets ISTIO_BOOTSTRAP_OVERRIDE. Gateway API pods set
// inject=false, so the annotation alone is a no-op and LDS fails with:
//
//	ApiConfigSource must have a statically defined non-EDS cluster: 'kubewaf_ecds'
//
// This mirrors the injector: volume custom-bootstrap-volume + env override.
func ensureIstioGatewayBootstrapMount() {
	GinkgoHelper()
	By("mounting ECDS bootstrap ConfigMap on Istio Gateway Deployment")
	applyIstioECDSBootstrap()
	Eventually(func(g Gomega) {
		_, err := kubectl("get", "deploy", "demo-gateway-istio", "-n", demoNamespace)
		g.Expect(err).NotTo(HaveOccurred(), "waiting for demo-gateway-istio Deployment")
	}, 2*time.Minute, 2*time.Second).Should(Succeed())

	// Strategic merge matches injector template (env + volumeMount + volume).
	patch := `{"spec":{"template":{"spec":{"containers":[{"name":"istio-proxy","env":[{"name":"ISTIO_BOOTSTRAP_OVERRIDE","value":"/etc/istio/custom-bootstrap/custom_bootstrap.json"}],"volumeMounts":[{"name":"custom-bootstrap-volume","mountPath":"/etc/istio/custom-bootstrap"}]}],"volumes":[{"name":"custom-bootstrap-volume","configMap":{"name":"kubewaf-ecds-bootstrap"}}]}}}}`
	_, err := kubectl("patch", "deploy", "demo-gateway-istio", "-n", demoNamespace,
		"--type", "strategic", "-p", patch)
	Expect(err).NotTo(HaveOccurred(), "patch demo-gateway-istio with bootstrap mount")

	// Wait for a Ready replica that has the mount (rollout after patch).
	Eventually(func(g Gomega) {
		// Re-apply patch if Istio controller rewrote the Deployment.
		mount, _ := kubectl("get", "deploy", "demo-gateway-istio", "-n", demoNamespace,
			"-o", "jsonpath={.spec.template.spec.volumes[?(@.name=='custom-bootstrap-volume')].configMap.name}")
		if strings.TrimSpace(mount) != "kubewaf-ecds-bootstrap" {
			_, _ = kubectl("patch", "deploy", "demo-gateway-istio", "-n", demoNamespace,
				"--type", "strategic", "-p", patch)
		}
		ready, err := kubectl("get", "deploy", "demo-gateway-istio", "-n", demoNamespace,
			"-o", "jsonpath={.status.readyReplicas}")
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(strings.TrimSpace(ready)).To(Equal("1"), "gateway deploy readyReplicas")
		// Confirm env on the live pod.
		out, err := kubectl("get", "pods", "-n", demoNamespace,
			"-l", "gateway.networking.k8s.io/gateway-name=demo-gateway",
			"-o", "jsonpath={.items[0].spec.containers[0].env[?(@.name=='ISTIO_BOOTSTRAP_OVERRIDE')].value}")
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(strings.TrimSpace(out)).To(ContainSubstring("custom_bootstrap.json"))
	}, 3*time.Minute, 3*time.Second).Should(Succeed())
}

func crdExists(name string) bool {
	_, err := kubectl("get", "crd", name)
	return err == nil
}

func skipUnlessCRD(name, reason string) {
	GinkgoHelper()
	if !crdExists(name) {
		Skip(fmt.Sprintf("CRD %s not installed (%s)", name, reason))
	}
}

func ensureNamespace(ns string) {
	GinkgoHelper()
	_, _ = kubectl("create", "ns", ns)
}

// ensureExclusiveWAF deletes every WAF in ns except keepName (if non-empty),
// so only one ECDS/Wasm filter attaches to a shared Gateway. Path A traffic
// smoke and Path B FTW otherwise race and return HTTP 500 on benign GETs.
func ensureExclusiveWAF(ns, keepName string) {
	GinkgoHelper()
	By(fmt.Sprintf("ensuring exclusive WAF in %s (keep=%q)", ns, keepName))
	out, err := kubectl("get", wafResource, "-n", ns, "-o", "jsonpath={.items[*].metadata.name}")
	if err != nil || strings.TrimSpace(out) == "" {
		return
	}
	for _, name := range strings.Fields(out) {
		if keepName != "" && name == keepName {
			continue
		}
		_, _ = kubectl("delete", wafResource, name, "-n", ns, "--ignore-not-found", "--wait=false")
	}
	// Wait until only the keeper remains (or none if keepName empty).
	Eventually(func(g Gomega) {
		got, err := kubectl("get", wafResource, "-n", ns, "-o", "jsonpath={.items[*].metadata.name}")
		g.Expect(err).NotTo(HaveOccurred())
		names := strings.Fields(strings.TrimSpace(got))
		if keepName == "" {
			g.Expect(names).To(BeEmpty())
			return
		}
		g.Expect(names).To(Equal([]string{keepName}))
	}, 2*time.Minute, 2*time.Second).Should(Succeed())
}

// splitImageRegistryRepoTag splits "registry/repo:tag" into parts for helm --set.
func splitImageRegistryRepoTag(img string) (registry, repo, tag string) {
	repo = img
	tag = "e2e"
	registry = "ghcr.io"
	if i := strings.LastIndex(img, ":"); i > 0 {
		tag = img[i+1:]
		repo = img[:i]
	}
	if i := strings.Index(repo, "/"); i > 0 {
		registry = repo[:i]
		repo = repo[i+1:]
	}
	return registry, repo, tag
}

// probeSubresourceImage returns the ko image for cmd/subresource-api (defaults alongside E2E_IMG).
func probeSubresourceImage() string {
	if v := os.Getenv("E2E_SUBRESOURCE_IMG"); v != "" {
		return v
	}
	// Derive from controller image: registry/repo-subresource-api:tag
	reg, repo, tag := splitImageRegistryRepoTag(projectImage())
	// repo is like kubewaf-io/kubewaf → kubewaf-io/kubewaf-subresource-api
	if !strings.HasSuffix(repo, "-subresource-api") {
		repo = repo + "-subresource-api"
	}
	return reg + "/" + repo + ":" + tag
}

// probeTestServerImage returns the ko image for cmd/probe-test-server.
func probeTestServerImage() string {
	if v := os.Getenv("E2E_PROBE_TEST_IMG"); v != "" {
		return v
	}
	reg, repo, tag := splitImageRegistryRepoTag(projectImage())
	if !strings.HasSuffix(repo, "-probe-test-server") {
		// kubewaf-io/kubewaf → kubewaf-io/kubewaf-probe-test-server
		if strings.HasSuffix(repo, "-subresource-api") {
			repo = strings.TrimSuffix(repo, "-subresource-api") + "-probe-test-server"
		} else {
			repo = repo + "-probe-test-server"
		}
	}
	return reg + "/" + repo + ":" + tag
}

func installOperatorHelm() {
	GinkgoHelper()
	installOperatorHelmOpts(false)
}

// installOperatorHelmWithProbes installs the operator and enables Subresource API + Test Server.
func installOperatorHelmWithProbes() {
	GinkgoHelper()
	installOperatorHelmOpts(true)
}

func installOperatorHelmOpts(enableProbes bool) {
	GinkgoHelper()
	By("installing kubeWAF via Helm")
	img := projectImage()
	registry, repo, tag := splitImageRegistryRepoTag(img)

	// Orphaned cluster-scoped resources (e.g. APIService from a partial install) block helm upgrade.
	if enableProbes {
		_, _ = kubectl("delete", "apiservice", "v1alpha1.subresources.kubewaf.io", "--ignore-not-found")
	}

	// Operator image includes wasm under KO_DATA_PATH (see make wasm-stage-kodata).
	args := []string{
		"upgrade", "--install", "kubewaf", "charts/kubewaf",
		"--namespace", operatorNamespace,
		"--create-namespace",
		"--set", "replicaCount=2",
		"--set", "leaderElection.enabled=true",
		"--set", "image.registry=" + registry,
		"--set", "image.repository=" + repo,
		"--set", "image.tag=" + tag,
		"--set", "image.pullPolicy=IfNotPresent",
		"--set", "crds.install=true",
		// Validating webhooks (Helm self-signed CA) — shift-left CR validation in e2e.
		"--set", "webhooks.enabled=true",
		"--set", "webhooks.failurePolicy=Fail",
		// Managed observability (EG-lite first; full adds VT + span transform).
		"--set", "observability.managed.enabled=true",
		"--set", "observability.managed.profile=full",
		"--set", "observability.managed.victoriaMetrics.enabled=true",
		"--set", "observability.managed.victoriaTraces.enabled=true",
		"--set", "observability.managed.injectConfigured=true",
		"--set", "observability.managed.networkPolicy.enabled=true",
		"--set", "observability.managed.alerts.enabled=false",
	}
	// Alt B: query via subresource API (not Service proxy). Always deploy the API.
	sReg, sRepo, sTag := splitImageRegistryRepoTag(probeSubresourceImage())
	args = append(args,
		"--set", "subresourceApi.enabled=true",
		"--set", "subresourceApi.probes.enabled=false",
		"--set", "subresourceApi.directives.enabled=true",
		"--set", "subresourceApi.query.enabled=true",
		"--set", "subresourceApi.image.registry="+sReg,
		"--set", "subresourceApi.image.repository="+sRepo,
		"--set", "subresourceApi.image.tag="+sTag,
		"--set", "subresourceApi.image.pullPolicy=IfNotPresent",
		"--set", "subresourceApi.networkPolicy.enabled=false",
		"--set", "probeTestServer.enabled=false",
	)
	if enableProbes {
		By("enabling subresourceApi probes + probeTestServer")
		tReg, tRepo, tTag := splitImageRegistryRepoTag(probeTestServerImage())
		args = append(args,
			"--set", "subresourceApi.probes.enabled=true",
			"--set", "probeTestServer.enabled=true",
			"--set", "probeTestServer.image.registry="+tReg,
			"--set", "probeTestServer.image.repository="+tRepo,
			"--set", "probeTestServer.image.tag="+tTag,
			"--set", "probeTestServer.image.pullPolicy=IfNotPresent",
			"--set", "probeTestServer.networkPolicy.enabled=false",
		)
	}
	args = append(args, "--wait", "--timeout=8m")
	cmd := exec.Command("helm", args...)
	_, err := utils.Run(cmd)
	Expect(err).NotTo(HaveOccurred(), "helm install kubewaf")
	waitForDeployment(operatorNamespace, "kubewaf", 3*time.Minute)
	waitForDeployment(operatorNamespace, "kubewaf-otel-collector", 4*time.Minute)
	waitForDeployment(operatorNamespace, "kubewaf-victoria-metrics", 4*time.Minute)
	waitForDeployment(operatorNamespace, "kubewaf-victoria-traces", 4*time.Minute)
	waitForDeployment(operatorNamespace, "kubewaf-subresource-api", 3*time.Minute)
	if enableProbes {
		waitForDeployment(operatorNamespace, "kubewaf-probe-test-server", 3*time.Minute)
	}
}

func uninstallOperatorHelm() {
	By("uninstalling kubeWAF Helm release")
	cmd := exec.Command("helm", "uninstall", "kubewaf", "-n", operatorNamespace, "--ignore-not-found")
	_, _ = utils.Run(cmd)
	_, _ = kubectl("delete", "ns", operatorNamespace, "--ignore-not-found", "--wait=false")
}

func applyCommonAppAndRules() {
	GinkgoHelper()
	applyFile("test/e2e/manifests/00-test-application.yaml")
	applyFile("test/e2e/manifests/common/rules.yaml")
	Eventually(func(g Gomega) {
		_, err := kubectl("get", "pod", "httpbin", "-n", demoNamespace)
		g.Expect(err).NotTo(HaveOccurred())
	}, 2*time.Minute, time.Second).Should(Succeed())
	_, _ = kubectl("wait", "--for=condition=Ready", "pod/httpbin", "-n", demoNamespace, "--timeout=2m")
}

func realWasmConfigured() bool {
	// Operator image embeds modsecurity-proxy-wasm via ko kodata (make wasm-stage-kodata).
	return true
}

func patchWAFTelemetry(ns, name, mode string) {
	GinkgoHelper()
	patch := fmt.Sprintf(`{"spec":{"telemetry":{"mode":%q}}}`, mode)
	if mode == "Managed" {
		// Pin traces on so the wasm export path does not depend on operator --telemetry-profile.
		patch = `{"spec":{"telemetry":{"mode":"Managed","traces":{"enabled":true,"sampleDisruptive":"1.0"}}}}`
	}
	_, err := kubectl("patch", wafResource, name, "-n", ns, "--type", "merge", "-p", patch)
	Expect(err).NotTo(HaveOccurred(), "patch WAF telemetry.mode=%s", mode)
}

func wafCondition(ns, name, condType string) (status, reason string) {
	st, err := kubectl("get", wafResource, name, "-n", ns,
		"-o", fmt.Sprintf("jsonpath={.status.conditions[?(@.type=='%s')].status}", condType))
	if err != nil {
		return "", ""
	}
	reason, _ = kubectl("get", wafResource, name, "-n", ns,
		"-o", fmt.Sprintf("jsonpath={.status.conditions[?(@.type=='%s')].reason}", condType))
	return strings.TrimSpace(st), strings.TrimSpace(reason)
}

// queryInClusterGETs a cluster-local HTTP URL from a curl pod (no Host override).
func queryInClusterGET(url string) string {
	GinkgoHelper()
	pod := fmt.Sprintf("e2e-q-%d", time.Now().UnixNano())
	out, err := kubectl("run", pod, "--rm", "-i", "--restart=Never",
		"--image=curlimages/curl:8.5.0", "-n", operatorNamespace, "--",
		"curl", "-sS", "--connect-timeout", "5", "--max-time", "20", url)
	if err != nil {
		return out
	}
	return out
}

func queryVictoriaMetrics(ns, name, promQL string) string {
	GinkgoHelper()
	return queryWAFMetrics(ns, name, promQL)
}

func queryWAFMetrics(ns, name, promQL string) string {
	GinkgoHelper()
	path := fmt.Sprintf("/apis/subresources.kubewaf.io/v1alpha1/namespaces/%s/wafs/%s/metrics?query=%s",
		ns, name, url.QueryEscape(promQL))
	out, err := kubectl("get", "--raw", path)
	if err != nil {
		return out
	}
	return out
}

func queryWAFTraces(ns, name string) string {
	GinkgoHelper()
	path := fmt.Sprintf("/apis/subresources.kubewaf.io/v1alpha1/namespaces/%s/wafs/%s/traces?limit=50", ns, name)
	out, err := kubectl("get", "--raw", path)
	if err != nil {
		return out
	}
	return out
}

func queryVictoriaTracesServices() string {
	GinkgoHelper()
	// Presence of kubewaf is implied by a scoped traces search for the demo WAF.
	out := queryWAFTraces(demoNamespace, "demo-waf-eg")
	if strings.TrimSpace(out) != "" {
		return out
	}
	return out
}

func uniqueTraceIDs(jaegerJSON string) []string {
	seen := map[string]struct{}{}
	var ids []string
	// Jaeger search uses "traceID" (mixed case).
	for _, key := range []string{`"traceID":"`, `"traceId":"`} {
		rest := jaegerJSON
		for {
			i := strings.Index(rest, key)
			if i < 0 {
				break
			}
			rest = rest[i+len(key):]
			j := strings.Index(rest, `"`)
			if j <= 0 {
				break
			}
			id := rest[:j]
			rest = rest[j+1:]
			if _, ok := seen[id]; ok {
				continue
			}
			seen[id] = struct{}{}
			ids = append(ids, id)
		}
	}
	return ids
}

// queryVictoriaMetricsDirect hits VM ClusterIP from an unlabeled pod (negative NP case).
func queryVictoriaMetricsDirect(promQL string) string {
	GinkgoHelper()
	return queryInClusterGET("http://kubewaf-victoria-metrics." + operatorNamespace +
		".svc.cluster.local:8428/api/v1/query?query=" + url.QueryEscape(promQL))
}

func envoyProxyPodIP() string {
	out, err := kubectl("get", "pods", "-n", "envoy-gateway-system",
		"-l", "gateway.envoyproxy.io/owning-gateway-name=demo-gateway",
		"-o", "jsonpath={.items[0].status.podIP}")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

func queryEnvoyPrometheus(substr string) string {
	GinkgoHelper()
	ip := envoyProxyPodIP()
	if ip == "" {
		return ""
	}
	return queryInClusterGET("http://" + ip + ":19001/stats/prometheus")
}
