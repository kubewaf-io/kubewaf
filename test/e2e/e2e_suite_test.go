//go:build e2e
// +build e2e

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

package e2e

import (
	"fmt"
	"os"
	"os/exec"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/kubewaf-io/kubewaf/test/utils"
)

var (
	// Optional Environment Variables:
	// - CERT_MANAGER_INSTALL_SKIP=true: Skips CertManager installation during test setup.
	// - E2E_PROVIDER=envoy-gateway|istio|cilium|all|manager: which provider suite to run.
	// - E2E_IMG: operator image (default ghcr.io/kubewaf-io/kubewaf:e2e).
	// - E2E_WASM_SOURCE_URL: real modsecurity-proxy-wasm .wasm URL for traffic tests.
	// - E2E_SKIP_OPERATOR_INSTALL=true: assume operator already installed (provider tests).
	// - E2E_SKIP_IMAGE_BUILD=true: skip ko-build + kind load.
	skipCertManagerInstall = os.Getenv("CERT_MANAGER_INSTALL_SKIP") == "true"
	// isCertManagerAlreadyInstalled will be set true when CertManager CRDs be found on the cluster
	isCertManagerAlreadyInstalled = false
)

// TestE2E runs the end-to-end (e2e) test suite for the project.
//
// Provider matrix (set E2E_PROVIDER):
//
//	all            – manager smoke + all available providers (default)
//	manager        – controller deploy/metrics only
//	envoy-gateway  – Envoy Gateway WAF attachment
//	istio          – Istio EnvoyFilter ECDS slot
//	cilium         – CiliumEnvoyConfig slot
func TestE2E(t *testing.T) {
	RegisterFailHandler(Fail)
	_, _ = fmt.Fprintf(GinkgoWriter, "Starting kubeWAF e2e suite (E2E_PROVIDER=%s)\n", e2eProvider())
	RunSpecs(t, "e2e suite")
}

var _ = BeforeSuite(func() {
	if os.Getenv("E2E_SKIP_IMAGE_BUILD") == "true" {
		_, _ = fmt.Fprintf(GinkgoWriter, "Skipping image build (E2E_SKIP_IMAGE_BUILD=true)\n")
	} else {
		By("building the manager(Operator) image")
		// ko-build-all uses CONTROLLER_IMG (repo, no tag) + KO_TAGS, not IMG.
		// Pass make args so the image is tagged as E2E_IMG (default :e2e).
		// utils.Run also resets cmd.Env, so make args are more reliable than env.
		img := projectImage()
		repo, tag := splitImageRepoTag(img)
		cmd := exec.Command("make", "ko-build-all",
			"CONTROLLER_IMG="+repo,
			"KO_TAGS="+tag,
		)
		_, err := utils.Run(cmd)
		ExpectWithOffset(1, err).NotTo(HaveOccurred(), "Failed to build the manager(Operator) image")

		By("loading the manager(Operator) image on Kind")
		err = utils.LoadImageToKindClusterWithName(img)
		ExpectWithOffset(1, err).NotTo(HaveOccurred(), "Failed to load the manager(Operator) image into Kind")
	}

	// CertManager is only required for the legacy manager smoke path that uses
	// metrics certs in some setups; keep optional.
	if !skipCertManagerInstall && e2eProvider() == "manager" {
		By("checking if cert manager is installed already")
		isCertManagerAlreadyInstalled = utils.IsCertManagerCRDsInstalled()
		if !isCertManagerAlreadyInstalled {
			_, _ = fmt.Fprintf(GinkgoWriter, "Installing CertManager...\n")
			Expect(utils.InstallCertManager()).To(Succeed(), "Failed to install CertManager")
		} else {
			_, _ = fmt.Fprintf(GinkgoWriter, "WARNING: CertManager is already installed. Skipping installation...\n")
		}
	}
})

var _ = AfterSuite(func() {
	if !skipCertManagerInstall && !isCertManagerAlreadyInstalled && e2eProvider() == "manager" {
		_, _ = fmt.Fprintf(GinkgoWriter, "Uninstalling CertManager...\n")
		utils.UninstallCertManager()
	}
})
