/*
Copyright 2025 Buzz-IT GmbH.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package chartv1alpha1

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

func TestChartIsTheV1Alpha1Operator(t *testing.T) {
	helm, err := exec.LookPath("helm")
	if err != nil {
		t.Skip("helm not found")
	}
	dir, err := filepath.Abs(filepath.Join("..", "..", "charts", "kubewaf"))
	if err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(helm, "template", "kubewaf", dir, "--namespace", "kubewaf-system", "--include-crds").CombinedOutput()
	if err != nil {
		t.Fatal(string(out), err)
	}
	s := string(out)
	for _, want := range []string{
		"--proxy-namespace=envoy-gateway-system",
		"--enable-webhooks=true",
		"includes.seclang.kubewaf.io",
		"containerPort: 8081",
		"resources: [\"envoyproxies\"]",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("rendered chart missing %q", want)
		}
	}
	for _, banned := range []string{
		":18001", ":18002", ":5005", "dynamicModule.image", "victoria-metrics", "ecds-bind-address",
	} {
		if strings.Contains(s, banned) {
			t.Fatalf("rendered chart still contains %s", banned)
		}
	}
	idx := strings.Index(s, "resources: [\"envoyproxies\"]")
	window := s[idx : idx+120]
	if strings.Contains(window, "create") || strings.Contains(window, "patch") || strings.Contains(window, "delete") {
		t.Fatalf("envoyproxies rule is not read-only:\n%s", window)
	}
	if os.Getenv("KUBEBUILDER_ASSETS") != "" {
		env := &envtest.Environment{
			CRDDirectoryPaths:     []string{filepath.Join(dir, "crds")},
			ErrorIfCRDPathMissing: true,
			BinaryAssetsDirectory: os.Getenv("KUBEBUILDER_ASSETS"),
		}
		if _, err := env.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = env.Stop() })
	}
	crds, err := os.ReadDir(filepath.Join(dir, "crds"))
	if err != nil || len(crds) != 7 {
		t.Fatalf("crds: %v %v", crds, err)
	}
}
