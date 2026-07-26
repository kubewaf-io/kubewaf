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

package waf

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	wafv1beta1 "github.com/kubewaf-io/kubewaf/api/waf/v1beta1"
	"github.com/kubewaf-io/kubewaf/internal/controller"
	"github.com/kubewaf-io/kubewaf/internal/dataplane/config"
	"github.com/kubewaf-io/kubewaf/internal/dataplane/ecds"
	"github.com/kubewaf-io/kubewaf/internal/dataplane/extensionserver"
	ciliumslot "github.com/kubewaf-io/kubewaf/internal/dataplane/slot/cilium"
	istioslot "github.com/kubewaf-io/kubewaf/internal/dataplane/slot/istio"
	"github.com/kubewaf-io/kubewaf/internal/metrics"
	"github.com/kubewaf-io/kubewaf/internal/references2"
)

const wafFinalizer = "waf.kubewaf.io/ecds"

// WAFReconciler reconciles a WAF object into:
//  1. gRPC ECDS extension configs (Coraza Wasm + directives)
//  2. A platform-specific filter slot (EG Extension Server index, or Istio EnvoyFilter)
type WAFReconciler struct {
	client.Client
	Scheme *runtime.Scheme

	// ECDS publishes TypedExtensionConfig to Envoy.
	ECDS *ecds.Server
	// EGExtension indexes WAFs for Envoy Gateway Extension Server hooks.
	EGExtension *extensionserver.Server
	// BuildOpts carries operator-level defaults (ECDS host, wasm HTTP URL).
	BuildOpts config.BuildOptions
}

// +kubebuilder:rbac:groups=waf.kubewaf.io,resources=wafs,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=waf.kubewaf.io,resources=wafs/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=waf.kubewaf.io,resources=wafs/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=networking.istio.io,resources=envoyfilters,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=cilium.io,resources=ciliumenvoyconfigs,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=gateway.networking.k8s.io,resources=gateways;httproutes;gatewayclasses,verbs=get;list;watch

// Reconcile resolves rules, pushes ECDS, and ensures the platform filter slot.
func (r *WAFReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := logf.FromContext(ctx)

	var waf wafv1beta1.WAF
	if _, err := controller.InitHandler(ctx, req, &waf, r.Client); err != nil {
		return ctrl.Result{}, err
	}

	// Deletion: remove ECDS + slots, then drop finalizer.
	if !waf.DeletionTimestamp.IsZero() {
		return r.reconcileDelete(ctx, &waf)
	}

	if !controllerutil.ContainsFinalizer(&waf, wafFinalizer) {
		controllerutil.AddFinalizer(&waf, wafFinalizer)
		if err := r.Update(ctx, &waf); err != nil {
			return ctrl.Result{}, err
		}
		// Requeue after finalizer add so subsequent logic runs on a fresh object.
		return ctrl.Result{Requeue: true}, nil
	}

	resolver := references2.NewRuleRefResolver(r.Client, r.Scheme)
	objects, errs, err := resolver.AddUpdateReconcile(ctx, waf.Spec.RuleSetRefs, &waf)
	if err != nil {
		return ctrl.Result{}, err
	}
	logger.V(3).Info("Resolver", "objects", objects, "errs", errs)

	refOK := len(errs) == 0
	changed := meta.SetStatusCondition(&waf.Status.Conditions, metav1.Condition{
		Type:               controller.ConditionTypeReferencesResolved,
		Status:             boolStatus(refOK),
		Reason:             "ReferenceResolve",
		Message:            refsMessage(errs),
		ObservedGeneration: waf.Generation,
	})
	if !refOK {
		logger.Error(fmt.Errorf("reference resolve failed"), "Resolver", "errs", errs)
		if changed {
			_ = r.Status().Update(ctx, &waf)
		}
		// Still continue so ECDS can be cleared/updated with partial rules if desired.
		// For safety we stop before ECDS push when refs fail.
		return ctrl.Result{}, nil
	}
	if changed {
		if err := r.Status().Update(ctx, &waf); err != nil {
			return ctrl.Result{}, err
		}
	}

	rules, err := references2.GetSecRule(objects)
	if err != nil {
		return ctrl.Result{}, err
	}

	buildOpts := r.BuildOpts
	var challengeHMAC ChallengeHMACResult
	if ChallengeEnabled(waf.Spec.Challenge) {
		challengeHMAC, err = ResolveChallengeHMAC(ctx, r.Client, r.Scheme, &waf)
		if err != nil {
			return ctrl.Result{}, r.markNotReady(ctx, &waf, "ChallengeSecret", err.Error())
		}
		buildOpts.ChallengeHMAC = challengeHMAC.Value
	}

	portable, err := config.BuildFromWAF(&waf, rules, buildOpts)
	if err != nil {
		return ctrl.Result{}, r.markNotReady(ctx, &waf, "BuildConfig", err.Error())
	}

	if r.ECDS == nil {
		return ctrl.Result{}, r.markNotReady(ctx, &waf, "ECDSNotConfigured", "ECDS server is not configured on the reconciler")
	}
	if err := r.ECDS.Upsert(portable); err != nil {
		return ctrl.Result{}, r.markNotReady(ctx, &waf, "ECDSUpsertFailed", err.Error())
	}

	slotKind, slotName, err := r.ensureSlot(ctx, &waf, portable)
	if err != nil {
		return ctrl.Result{}, r.markNotReady(ctx, &waf, "SlotFailed", err.Error())
	}

	// Refresh object for status write (avoid conflict after earlier status updates).
	if err := r.Get(ctx, req.NamespacedName, &waf); err != nil {
		return ctrl.Result{}, err
	}

	waf.Status.Provider = portable.Provider
	waf.Status.Engine = portable.Engine
	waf.Status.ChallengeEnabled = false
	waf.Status.ChallengeSecretName = ""
	for _, f := range portable.Filters {
		if f.Role == config.FilterRoleChallenge {
			waf.Status.ChallengeEnabled = true
			waf.Status.ChallengeSecretName = challengeHMAC.SecretName
			break
		}
	}
	waf.Status.ECDSResourceName = portable.ExtensionName
	waf.Status.ECDSVersion = r.ECDS.Version()
	waf.Status.SlotKind = slotKind
	waf.Status.SlotName = slotName

	msg := fmt.Sprintf("engine=%s ECDS %s filters=%d slot=%s",
		portable.Engine, portable.ExtensionName, len(portable.Filters), slotKind)
	meta.SetStatusCondition(&waf.Status.Conditions, metav1.Condition{
		Type:               controller.ConditionTypeReady,
		Status:             metav1.ConditionTrue,
		Reason:             "Ready",
		Message:            msg,
		ObservedGeneration: waf.Generation,
	})
	if err := r.Status().Update(ctx, &waf); err != nil {
		return ctrl.Result{}, err
	}

	metrics.WAFReady.WithLabelValues(waf.Namespace, waf.Name).Set(1)
	crsEnabled := 0.0
	if waf.Spec.CRSEnable {
		crsEnabled = 1.0
	}
	metrics.WAFCRSEnabled.WithLabelValues(waf.Namespace, waf.Name).Set(crsEnabled)
	metrics.RulesLoaded.WithLabelValues(waf.Namespace, waf.Name, "waf").Set(float64(len(objects)))

	return ctrl.Result{}, nil
}

func (r *WAFReconciler) ensureSlot(ctx context.Context, waf *wafv1beta1.WAF, p *config.PortableConfig) (kind, name string, err error) {
	switch p.Provider {
	case wafv1beta1.ProviderIstio:
		if r.EGExtension != nil {
			r.EGExtension.Delete(p.Namespace, p.Name)
		}
		_ = ciliumslot.DeleteCiliumEnvoyConfig(ctx, r.Client, p.Namespace, p.Name)
		if err := istioslot.EnsureEnvoyFilter(ctx, r.Client, waf, p); err != nil {
			return "", "", err
		}
		return "EnvoyFilter", istioslot.ResourceName(p.Name), nil

	case wafv1beta1.ProviderCilium:
		if r.EGExtension != nil {
			r.EGExtension.Delete(p.Namespace, p.Name)
		}
		_ = istioslot.DeleteEnvoyFilter(ctx, r.Client, p.Namespace, p.Name)
		if err := ciliumslot.EnsureCiliumEnvoyConfig(ctx, r.Client, waf, p); err != nil {
			return "", "", err
		}
		return "CiliumEnvoyConfig", ciliumslot.ResourceName(p.Name), nil

	case wafv1beta1.ProviderEnvoyGateway, wafv1beta1.ProviderAuto, "":
		_ = istioslot.DeleteEnvoyFilter(ctx, r.Client, p.Namespace, p.Name)
		_ = ciliumslot.DeleteCiliumEnvoyConfig(ctx, r.Client, p.Namespace, p.Name)
		if r.EGExtension != nil {
			r.EGExtension.Upsert(p)
		}
		return "ExtensionServer", p.ExtensionName, nil

	default:
		return "", "", fmt.Errorf("unsupported provider %q", p.Provider)
	}
}

func (r *WAFReconciler) reconcileDelete(ctx context.Context, waf *wafv1beta1.WAF) (ctrl.Result, error) {
	logger := logf.FromContext(ctx)
	extName := config.ExtensionName(waf.Namespace, waf.Name)

	if r.ECDS != nil {
		if err := r.ECDS.Delete(extName); err != nil {
			logger.Error(err, "ECDS delete failed")
			return ctrl.Result{}, err
		}
	}
	if r.EGExtension != nil {
		r.EGExtension.Delete(waf.Namespace, waf.Name)
	}
	if err := istioslot.DeleteEnvoyFilter(ctx, r.Client, waf.Namespace, waf.Name); err != nil {
		return ctrl.Result{}, err
	}
	if err := ciliumslot.DeleteCiliumEnvoyConfig(ctx, r.Client, waf.Namespace, waf.Name); err != nil {
		return ctrl.Result{}, err
	}

	if controllerutil.ContainsFinalizer(waf, wafFinalizer) {
		controllerutil.RemoveFinalizer(waf, wafFinalizer)
		if err := r.Update(ctx, waf); err != nil {
			return ctrl.Result{}, err
		}
	}

	metrics.WAFReady.WithLabelValues(waf.Namespace, waf.Name).Set(0)
	return ctrl.Result{}, nil
}

func (r *WAFReconciler) markNotReady(ctx context.Context, waf *wafv1beta1.WAF, reason, msg string) error {
	if err := r.Get(ctx, client.ObjectKeyFromObject(waf), waf); err != nil && !errors.IsNotFound(err) {
		return err
	}
	meta.SetStatusCondition(&waf.Status.Conditions, metav1.Condition{
		Type:               controller.ConditionTypeReady,
		Status:             metav1.ConditionFalse,
		Reason:             reason,
		Message:            msg,
		ObservedGeneration: waf.Generation,
	})
	_ = r.Status().Update(ctx, waf)
	metrics.WAFReady.WithLabelValues(waf.Namespace, waf.Name).Set(0)
	return fmt.Errorf("%s: %s", reason, msg)
}

// SetupWithManager sets up the controller with the Manager.
func (r *WAFReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&wafv1beta1.WAF{}).
		Owns(&corev1.Secret{}).
		Named("waf").
		Complete(r)
}

func boolStatus(ok bool) metav1.ConditionStatus {
	if ok {
		return metav1.ConditionTrue
	}
	return metav1.ConditionFalse
}

func refsMessage(errs []references2.ReferenceError) string {
	if len(errs) == 0 {
		return "all references resolved"
	}
	return fmt.Sprintf("%d reference error(s): %v", len(errs), errs)
}
