package waf

import (
	"context"
	"fmt"
	"strings"
	"testing"

	wafv1beta1 "github.com/kubewaf-io/kubewaf/api/waf/v1beta1"
	"github.com/kubewaf-io/kubewaf/internal/controller"
	"github.com/kubewaf-io/kubewaf/internal/dataplane/config"
	"github.com/kubewaf-io/kubewaf/internal/dataplane/ecds"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

var _ = Describe("WAF Controller", func() {
	Context("When reconciling a resource", func() {
		const resourceName = "test-resource"
		ctx := context.Background()
		typeNamespacedName := types.NamespacedName{
			Name:      resourceName,
			Namespace: metav1.NamespaceDefault,
		}
		waf := &wafv1beta1.WAF{}
		BeforeEach(func() {
			By("creating the custom resource for the Kind WAF")
			err := k8sClient.Get(ctx, typeNamespacedName, waf)
			if err != nil && errors.IsNotFound(err) {
				resource := &wafv1beta1.WAF{
					ObjectMeta: metav1.ObjectMeta{
						Name:      resourceName,
						Namespace: metav1.NamespaceDefault,
					},
					Spec: wafv1beta1.WAFSpec{
						CRSEnable:             true,
						LogLevel:              2,
						CorazaProxyWasmImage:  "ghcr.io/corazawaf/coraza-proxy-wasm:0.6.0",
						CorazaProxyWasmHTTP:   "https://example.com/coraza-proxy-wasm.wasm",
						CorazaProxyWasmSHA256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
						Provider: &wafv1beta1.WAFProvider{
							Type: wafv1beta1.ProviderEnvoyGateway,
						},
					},
				}
				Expect(k8sClient.Create(ctx, resource)).To(Succeed())
			}
		})
		AfterEach(func() {
			resource := &wafv1beta1.WAF{}
			err := k8sClient.Get(ctx, typeNamespacedName, resource)
			if err == nil {
				By("Cleanup the specific resource instance WAF")
				Expect(k8sClient.Delete(ctx, resource)).To(Succeed())
			}
		})
		It("should reconcile via ECDS without EnvoyExtensionPolicy", func() {
			By("Reconciling the created resource")
			ecdsSrv := ecds.New(ctx, GinkgoLogr)
			controllerReconciler := &WAFReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
				ECDS:   ecdsSrv,
				BuildOpts: config.BuildOptions{
					DefaultECDSHost:    "kubewaf-ecds.kubewaf-system.svc.cluster.local",
					DefaultECDSPort:    18001,
					DefaultWasmHTTPURL: "https://example.com/coraza-proxy-wasm.wasm",
				},
			}

			// First reconcile adds finalizer.
			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{NamespacedName: typeNamespacedName})
			Expect(err).NotTo(HaveOccurred())

			// Second reconcile performs ECDS upsert.
			_, err = controllerReconciler.Reconcile(ctx, reconcile.Request{NamespacedName: typeNamespacedName})
			if err != nil {
				fmt.Fprintf(GinkgoWriter, "Reconcile error was: %v\n", err)
			}
			Expect(err).NotTo(HaveOccurred())

			updated := &wafv1beta1.WAF{}
			Expect(k8sClient.Get(ctx, typeNamespacedName, updated)).To(Succeed())

			Expect(ecdsSrv.Has(config.ExtensionName(updated.Namespace, updated.Name))).To(BeTrue())

			cond := meta.FindStatusCondition(updated.Status.Conditions, controller.ConditionTypeReady)
			if cond != nil {
				Expect(cond.Status).To(Equal(metav1.ConditionTrue))
			}
			Expect(updated.Status.Provider).To(Equal(wafv1beta1.ProviderEnvoyGateway))
			Expect(updated.Status.SlotKind).To(Equal("ExtensionServer"))
		})
	})
})

// TestCRSTuningDirectives contains plain Go tests for the CRS declarative tuning
// helpers (now in internal/dataplane/config).
func TestCRSTuningDirectives(t *testing.T) {
	t.Parallel()

	intPtr := func(i int) *int { return &i }

	t.Run("crsSetupActions produces nothing for nil or empty tuning", func(t *testing.T) {
		if got := config.CRSSetupActions(nil); got != nil {
			t.Errorf("expected nil for nil input, got %v", got)
		}
		if got := config.CRSSetupActions(&wafv1beta1.CRSTuning{}); got != nil {
			t.Errorf("expected nil for zero-value tuning, got %v", got)
		}
	})

	t.Run("crsSetupActions emits single id:900000 SecAction with requested setvars", func(t *testing.T) {
		got := config.CRSSetupActions(&wafv1beta1.CRSTuning{
			ParanoiaLevel:            intPtr(2),
			InboundAnomalyThreshold:  intPtr(10),
			OutboundAnomalyThreshold: intPtr(4),
		})
		if len(got) != 1 {
			t.Fatalf("expected exactly one directive, got %d: %#v", len(got), got)
		}
		d := got[0]
		if !strings.Contains(d, "id:900000") ||
			!strings.Contains(d, "phase:1") ||
			!strings.Contains(d, "nolog,pass") {
			t.Errorf("missing required action attributes in %s", d)
		}
		if !strings.Contains(d, "detection_paranoia_level=2") ||
			!strings.Contains(d, "blocking_paranoia_level=2") {
			t.Errorf("paranoia levels not both set: %s", d)
		}
		if !strings.Contains(d, "inbound_anomaly_score_threshold=10") ||
			!strings.Contains(d, "outbound_anomaly_score_threshold=4") {
			t.Errorf("thresholds missing or wrong: %s", d)
		}
	})

	t.Run("crsExclusions emits remove + update directives in input order", func(t *testing.T) {
		crs := &wafv1beta1.CRSTuning{
			RemoveByID:  []int{942100},
			RemoveByTag: []string{"attack-sqli", "attack-xss"},
			UpdateTargetByID: []wafv1beta1.TargetExclusion{
				{ID: 920273, RemoveTargets: []string{"ARGS:json_blob"}},
				{ID: 942100, RemoveTargets: []string{"ARGS:csrf_token", "REQUEST_COOKIES:sessionid"}},
			},
		}
		got := config.CRSExclusions(crs)
		wantCount := 1 + 2 + 2
		if len(got) != wantCount {
			t.Fatalf("expected %d directives, got %d: %v", wantCount, len(got), got)
		}
		if got[0] != "SecRuleRemoveById 942100" {
			t.Errorf("first removeById wrong: %s", got[0])
		}
		if got[1] != "SecRuleRemoveByTag attack-sqli" {
			t.Errorf("first removeByTag wrong: %s", got[1])
		}
		if !strings.Contains(got[3], `SecRuleUpdateTargetById 920273 "!ARGS:json_blob"`) {
			t.Errorf("first updateTarget wrong: %s", got[3])
		}
		if !strings.Contains(got[4], `|!REQUEST_COOKIES:sessionid"`) {
			t.Errorf("multi-target join should use | : %s", got[4])
		}
	})

	t.Run("composition enforces the exact ordering required by CRS", func(t *testing.T) {
		waf := &wafv1beta1.WAF{
			Spec: wafv1beta1.WAFSpec{
				CRSEnable: true,
				LogLevel:  3,
				CRS: &wafv1beta1.CRSTuning{
					ParanoiaLevel:           intPtr(2),
					InboundAnomalyThreshold: intPtr(10),
					RemoveByID:              []int{942100},
					UpdateTargetByID: []wafv1beta1.TargetExclusion{
						{ID: 920273, RemoveTargets: []string{"ARGS:json_blob"}},
					},
				},
			},
		}
		defaultCfg := config.BuildDirectives(waf, []string{
			`SecRule REQUEST_URI "@rx ^/evil" "id:100001,phase:2,deny"`,
		})

		iSetupInc := find(defaultCfg, func(s string) bool { return s == "Include @crs-setup-conf" })
		iSetupAct := find(defaultCfg, func(s string) bool { return strings.Contains(s, "id:900000") })
		iOwaspInc := find(defaultCfg, func(s string) bool { return s == "Include @owasp_crs/*.conf" })
		iRemoveID := find(defaultCfg, func(s string) bool { return s == "SecRuleRemoveById 942100" })
		iUpdate := find(defaultCfg, func(s string) bool { return strings.Contains(s, "SecRuleUpdateTargetById 920273") })
		iUserRule := find(defaultCfg, func(s string) bool { return strings.Contains(s, "id:100001") })

		if iSetupInc == -1 || iSetupAct == -1 || iOwaspInc == -1 || iRemoveID == -1 || iUpdate == -1 {
			t.Fatalf("missing expected directives in composed list: %v", defaultCfg)
		}

		if !(iSetupInc < iSetupAct &&
			iSetupAct < iOwaspInc &&
			iOwaspInc < iRemoveID &&
			iRemoveID < iUpdate &&
			iUpdate < iUserRule) {
			t.Errorf("CRS tuning directive ordering contract violated:\n%v", defaultCfg)
		}
	})
}

func find(ss []string, pred func(string) bool) int {
	for i, s := range ss {
		if pred(s) {
			return i
		}
	}
	return -1
}
