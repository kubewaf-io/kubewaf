//go:build e2e
// +build e2e

package e2e

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
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
	// defaultWasmSourceURL can be overridden with E2E_WASM_SOURCE_URL.
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

func waitForWAFReady(ns, name string, timeout time.Duration) {
	GinkgoHelper()
	Eventually(func(g Gomega) {
		out, err := kubectl("get", "waf", name, "-n", ns,
			"-o", "jsonpath={.status.conditions[?(@.type=='Ready')].status}")
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(out).To(Equal("True"), "WAF not Ready")
	}, timeout, 2*time.Second).Should(Succeed())
}

func wafStatusField(ns, name, jsonPath string) string {
	GinkgoHelper()
	out, err := kubectl("get", "waf", name, "-n", ns, "-o", "jsonpath="+jsonPath)
	Expect(err).NotTo(HaveOccurred())
	return out
}

// curlFromCluster runs curl inside a short-lived pod and returns status code + body snippet.
func curlFromCluster(host, path, userAgent string) (status string, body string) {
	GinkgoHelper()
	// Use a unique pod name per call.
	pod := fmt.Sprintf("e2e-curl-%d", time.Now().UnixNano())
	ua := userAgent
	if ua == "" {
		ua = "e2e-client"
	}
	args := []string{
		"run", pod, "--rm", "-i", "--restart=Never",
		"--image=curlimages/curl:8.5.0",
		"--",
		"curl", "-sS", "-o", "/tmp/body", "-w", "%{http_code}",
		"-H", "Host: " + host,
		"-H", "User-Agent: " + ua,
		"--max-time", "15",
		path,
	}
	out, err := kubectl(args...)
	// kubectl run -i may mix pod logs; try to get body from a follow-up if needed.
	status = strings.TrimSpace(out)
	if err != nil {
		// Still return output for debugging.
		body = out
		return status, body
	}
	// When curl -w prints only status code at the end of stdout.
	if len(status) >= 3 {
		// status might be "200" or include logs; take last 3 digits if possible.
		for i := len(status) - 3; i >= 0; i-- {
			chunk := status[i : i+3]
			if chunk[0] >= '1' && chunk[0] <= '5' {
				return chunk, status
			}
		}
	}
	return status, body
}

// curlGatewayViaPortForward curls the gateway service through a background port-forward.
// target is "svc/name" or "deploy/name" in namespace ns.
func curlGatewayHTTP(ns, svc, host, urlPath, userAgent string) (statusCode string) {
	GinkgoHelper()
	// Use an in-cluster curl pod that targets the ClusterIP service DNS.
	target := fmt.Sprintf("http://%s.%s.svc.cluster.local%s", svc, ns, urlPath)
	code, _ := curlFromCluster(host, target, userAgent)
	return code
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

func installOperatorHelm() {
	GinkgoHelper()
	By("installing kubeWAF via Helm")
	img := projectImage()
	// Split registry/repo:tag for helm values.
	// Expect form registry/repo:tag
	repo := img
	tag := "e2e"
	registry := "ghcr.io"
	if i := strings.LastIndex(img, ":"); i > 0 {
		tag = img[i+1:]
		repo = img[:i]
	}
	if i := strings.Index(repo, "/"); i > 0 {
		registry = repo[:i]
		repo = repo[i+1:]
	}

	wasmURL := os.Getenv("E2E_WASM_SOURCE_URL")
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
		"--wait", "--timeout=5m",
	}
	if wasmURL != "" {
		args = append(args, "--set", "dataplane.wasmSourceURL="+wasmURL)
	} else {
		// Placeholder binary so operator-hosted wasm serve works without external CDN.
		// Traffic tests that require a real wasm binary will Skip when E2E_WASM_SOURCE_URL is unset.
		args = append(args, "--set", "dataplane.wasmSourceURL=https://github.com/proxy-wasm/proxy-wasm-cpp-sdk/raw/master/proxy_wasm_intrinsics.wasm")
	}

	cmd := exec.Command("helm", args...)
	_, err := utils.Run(cmd)
	Expect(err).NotTo(HaveOccurred(), "helm install kubewaf")
	waitForDeployment(operatorNamespace, "kubewaf", 3*time.Minute)
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
	return os.Getenv("E2E_WASM_SOURCE_URL") != ""
}
