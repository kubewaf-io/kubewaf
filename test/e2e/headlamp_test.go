//go:build e2e
// +build e2e

package e2e

import (
	"os"
	"time"

	. "github.com/onsi/ginkgo/v2"
)

// Headlamp e2e: install in-cluster Headlamp + kubeWAF plugin, attach a Path B
// WAF with the full structured CRS, generate traffic, then screenshot the UI.
//
//	make test-e2e-headlamp
//
// Opt-in: E2E_HEADLAMP=true or E2E_PROVIDER=headlamp. Needs a plugin checkout
// at HEADLAMP_PLUGIN_DIR (default ./headlamp-plugin) and network to pull the
// Headlamp Helm chart + Chromium.
var _ = Describe("Headlamp Path B CRS screenshots", Ordered, func() {
	BeforeAll(func() {
		if !headlampEnabled() {
			return
		}
		if os.Getenv("E2E_SKIP_OPERATOR_INSTALL") != "true" {
			installOperatorHelm()
		}
		applyCommonAppAndRules()
		applyFullPathBCRS()
	})

	BeforeEach(func() {
		if !headlampEnabled() {
			Skip("Headlamp e2e disabled (set E2E_HEADLAMP=true or E2E_PROVIDER=headlamp)")
		}
	})

	It("loads full Path B CRS and screenshots Headlamp", func() {
		dp := pickHeadlampDataplane()
		installPathBWAFForHeadlamp(dp)
		generatePathBTraffic(dp)

		// Catalog is best-effort: screenshots still run if OTLP is slow.
		_ = queryWAFMetrics(demoNamespace, dp.wafName, `kubewaf_waf_tx_total`)

		installHeadlampWithPlugin()
		stopPF := startHeadlampPortForward()
		DeferCleanup(stopPF)

		time.Sleep(2 * time.Second)
		runHeadlampPlaywright(dp.wafName)
	})
})
