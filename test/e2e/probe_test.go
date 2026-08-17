//go:build e2e
// +build e2e

package e2e

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/kubewaf-io/kubewaf/test/utils"
)

// Probe / aggregated subresources.kubewaf.io e2e (design PR8/PR9).
//
//	E2E_PROVIDER=probe|all   or   E2E_PROBE=true
//
// Builds/loads kubewaf-subresource-api + kubewaf-probe-test-server images and
// enables chart values subresourceApi + probeTestServer.

const (
	probeAPIService = "v1alpha1.subresources.kubewaf.io"
	probeAPIGroup   = "subresources.kubewaf.io"
)

func probeE2EEnabled() bool {
	if os.Getenv("E2E_PROBE") == "true" {
		return true
	}
	p := e2eProvider()
	return p == "probe" || p == "all"
}

var _ = Describe("Subresource probe API", Ordered, func() {
	BeforeAll(func() {
		if !probeE2EEnabled() {
			Skip("set E2E_PROVIDER=probe|all or E2E_PROBE=true to run probe e2e")
		}
		if os.Getenv("E2E_SKIP_OPERATOR_INSTALL") != "true" {
			installOperatorHelmWithProbes()
		} else {
			waitForDeployment(operatorNamespace, "kubewaf-subresource-api", 3*time.Minute)
			waitForDeployment(operatorNamespace, "kubewaf-probe-test-server", 3*time.Minute)
		}
		// Demo SecRule used by pass-through probes (explicit metadata.id in rules.yaml).
		applyFile("test/e2e/manifests/common/rules.yaml")
		Eventually(func(g Gomega) {
			_, err := kubectl("get", "secrules.seclang.kubewaf.io", "block-bad-user-agent", "-n", demoNamespace)
			g.Expect(err).NotTo(HaveOccurred())
		}, 2*time.Minute, 2*time.Second).Should(Succeed())
	})

	It("registers APIService Available and lists the API group", func() {
		Eventually(func(g Gomega) {
			out, err := kubectl("get", "apiservice", probeAPIService,
				"-o", "jsonpath={.status.conditions[?(@.type=='Available')].status}")
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(out).To(Equal("True"), "APIService Available")
		}, 3*time.Minute, 3*time.Second).Should(Succeed())

		// Prefer raw discovery: kubectl api-resources often omits empty-verb parents
		// and does not list slash-form subresources (secrules/probes).
		out, err := kubectl("get", "--raw", "/apis/"+probeAPIGroup+"/v1alpha1")
		Expect(err).NotTo(HaveOccurred())
		Expect(out).To(ContainSubstring("secrules/probes"))
		Expect(out).To(ContainSubstring(`"verbs":["get","create","update","patch","delete"]`))
	})

	It("pass-through probe returns 200 with EngineParity for a SecRule", func() {
		path := fmt.Sprintf(
			"/apis/%s/v1alpha1/namespaces/%s/secrules/block-bad-user-agent/probes/http/search",
			probeAPIGroup, demoNamespace,
		)
		body, code, err := apiserverHTTP("GET", path, map[string]string{
			"User-Agent": "sqlmap/1.0",
		}, "")
		Expect(err).NotTo(HaveOccurred(), "body=%s", body)
		Expect(code).To(Equal(200), "body=%s", body)

		var probe map[string]any
		Expect(json.Unmarshal([]byte(body), &probe)).To(Succeed())
		status, _ := probe["status"].(map[string]any)
		Expect(status).NotTo(BeNil(), body)

		conds, _ := status["conditions"].([]any)
		var parity map[string]any
		for _, c := range conds {
			cm, _ := c.(map[string]any)
			if cm["type"] == "EngineParity" {
				parity = cm
				break
			}
		}
		Expect(parity).NotTo(BeNil(), "EngineParity missing: %s", body)
		Expect(parity["status"]).To(Equal("False"))
		Expect(fmt.Sprint(parity["reason"])).To(ContainSubstring("Coraza"))

		// Would-block: scanner UA should match deny rule when assembly loads the SecRule.
		inter, _ := status["interruption"].(map[string]any)
		matches, _ := status["matches"].([]any)
		if inter != nil {
			Expect(inter["disrupted"]).To(BeTrue(), "expected disrupted: %s", body)
		} else {
			Expect(matches).NotTo(BeEmpty(), "expected matches or interruption: %s", body)
		}
	})

	It("returns 403 when SA can probe but cannot get parent SecRule", func() {
		sa := "probe-no-get"
		_, _ = kubectl("delete", "sa", sa, "-n", demoNamespace, "--ignore-not-found")
		_, _ = kubectl("delete", "role", "probe-only", "-n", demoNamespace, "--ignore-not-found")
		_, _ = kubectl("delete", "rolebinding", "probe-only", "-n", demoNamespace, "--ignore-not-found")
		kubectlOK("create", "sa", sa, "-n", demoNamespace)

		applyYAML(fmt.Sprintf(`
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: probe-only
  namespace: %s
rules:
- apiGroups: ["subresources.kubewaf.io"]
  resources: ["secrules/probes"]
  verbs: ["get", "create", "update", "patch", "delete"]
`, demoNamespace))
		applyYAML(fmt.Sprintf(`
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: probe-only
  namespace: %s
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: probe-only
subjects:
- kind: ServiceAccount
  name: %s
  namespace: %s
`, demoNamespace, sa, demoNamespace))

		path := fmt.Sprintf(
			"/apis/%s/v1alpha1/namespaces/%s/secrules/block-bad-user-agent/probes",
			probeAPIGroup, demoNamespace,
		)
		asUser := fmt.Sprintf("system:serviceaccount:%s:%s", demoNamespace, sa)
		body, code, err := apiserverHTTP("GET", path, nil, asUser)
		// Apiserver RBAC or extension SAR both yield 403.
		if err != nil && code == 0 {
			Expect(strings.Contains(body, "403") || strings.Contains(err.Error(), "403") ||
				strings.Contains(body, "Forbidden")).To(BeTrue(), "body=%s err=%v", body, err)
			return
		}
		Expect(code).To(Equal(403), "body=%s", body)
	})
})

// apiserverHTTP starts kubectl proxy and curls the aggregated path with optional headers/impersonation.
func apiserverHTTP(method, path string, headers map[string]string, impersonateUser string) (string, int, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", 0, err
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	proxy := exec.Command("kubectl", "proxy", fmt.Sprintf("--port=%d", port), "--accept-hosts=^.*$")
	if err := proxy.Start(); err != nil {
		return "", 0, err
	}
	defer func() {
		_ = proxy.Process.Kill()
		_, _ = proxy.Process.Wait()
	}()

	base := fmt.Sprintf("http://127.0.0.1:%d", port)
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if err := exec.Command("curl", "-sf", base+"/version").Run(); err == nil {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}

	url := base + path
	args := []string{"-sS", "-D", "/tmp/probe-e2e-headers.txt", "-o", "/tmp/probe-e2e-body.json", "-w", "%{http_code}", "-X", method, url}
	for k, v := range headers {
		args = append(args, "-H", k+": "+v)
	}
	if impersonateUser != "" {
		args = append(args, "-H", "Impersonate-User: "+impersonateUser)
		// Impersonation requires the proxy user to have impersonate permission (kind-admin does).
	}
	out, err := exec.Command("curl", args...).CombinedOutput()
	codeStr := strings.TrimSpace(string(out))
	code := 0
	_, _ = fmt.Sscanf(codeStr, "%d", &code)
	b, readErr := os.ReadFile("/tmp/probe-e2e-body.json")
	body := string(b)
	if readErr != nil {
		body = ""
	}
	if err != nil && code == 0 {
		return body, code, fmt.Errorf("curl: %w (%s)", err, string(out))
	}
	return body, code, nil
}

func applyYAML(yaml string) {
	GinkgoHelper()
	cmd := exec.Command("kubectl", "apply", "-f", "-")
	cmd.Stdin = strings.NewReader(yaml)
	_, err := utils.Run(cmd)
	Expect(err).NotTo(HaveOccurred())
}
