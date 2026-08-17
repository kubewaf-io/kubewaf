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
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	seclangv1beta1 "github.com/kubewaf-io/kubewaf/api/seclang/v1beta1"
	wafv1beta1 "github.com/kubewaf-io/kubewaf/api/waf/v1beta1"
	"github.com/kubewaf-io/kubewaf/internal/controller"
	"github.com/kubewaf-io/kubewaf/internal/dataplane/config"
	"github.com/kubewaf-io/kubewaf/internal/dataplane/ecds"
	"github.com/kubewaf-io/kubewaf/internal/dataplane/extensionserver"
	dpindex "github.com/kubewaf-io/kubewaf/internal/dataplane/index"
	"github.com/kubewaf-io/kubewaf/internal/dataplane/pipeline"
	"github.com/kubewaf-io/kubewaf/internal/dataplane/slot"
	"github.com/kubewaf-io/kubewaf/internal/metrics"
	"github.com/kubewaf-io/kubewaf/internal/references2"
)

const wafFinalizer = "waf.kubewaf.io/ecds"

// maxRenderedDirectivesBytes caps status.renderedDirectives to keep etcd objects small.
// Full CRS Path B assemblies can exceed this; truncation is recorded in status.
const maxRenderedDirectivesBytes = 64 * 1024

// WAFReconciler reconciles a WAF object into:
//  1. gRPC ECDS extension configs (Wasm + directives)
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
	// Recorder emits Kubernetes events (optional; nil-safe).
	Recorder record.EventRecorder

	// slots is the platform filter-slot registry (lazy-init).
	slots *slot.Registry
}

func (r *WAFReconciler) slotRegistry() *slot.Registry {
	if r.slots == nil {
		r.slots = slot.NewRegistry(r.EGExtension)
	}
	return r.slots
}

func (r *WAFReconciler) publishers() pipeline.Publishers {
	return pipeline.Publishers{ECDS: r.ECDS, EGExtension: r.EGExtension}
}

// +kubebuilder:rbac:groups=waf.kubewaf.io,resources=wafs,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=waf.kubewaf.io,resources=wafs/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=waf.kubewaf.io,resources=wafs/finalizers,verbs=update
// +kubebuilder:rbac:groups=seclang.kubewaf.io,resources=phraselists,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch
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

	// Shared pipeline: lock refs + challenge ensure + discover + build + ECDS/EG publish.
	res, err := pipeline.Build(ctx, r.Client, &waf, pipeline.Options{
		BuildOpts:             r.BuildOpts,
		Scheme:                r.Scheme,
		EnsureChallengeSecret: true,
		LockRefs:              true,
	})
	if err != nil {
		// Reference errors return a Result with ReferenceErrors when RequireRefsOK;
		// other failures are hard errors.
		if res != nil && len(res.ReferenceErrors) > 0 {
			refOK := false
			changed := meta.SetStatusCondition(&waf.Status.Conditions, metav1.Condition{
				Type:               controller.ConditionTypeReferencesResolved,
				Status:             boolStatus(refOK),
				Reason:             "ReferenceResolve",
				Message:            refsMessage(res.ReferenceErrors),
				ObservedGeneration: waf.Generation,
			})
			if changed {
				_ = r.Status().Update(ctx, &waf)
			}
			logger.Error(err, "reference resolve failed", "errs", res.ReferenceErrors)
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, r.markNotReady(ctx, &waf, "BuildFailed", err.Error())
	}

	refOK := len(res.ReferenceErrors) == 0
	changed := meta.SetStatusCondition(&waf.Status.Conditions, metav1.Condition{
		Type:               controller.ConditionTypeReferencesResolved,
		Status:             boolStatus(refOK),
		Reason:             "ReferenceResolve",
		Message:            refsMessage(res.ReferenceErrors),
		ObservedGeneration: waf.Generation,
	})
	if !refOK {
		logger.Error(fmt.Errorf("reference resolve failed"), "Resolver", "errs", res.ReferenceErrors)
		if changed {
			_ = r.Status().Update(ctx, &waf)
		}
		return ctrl.Result{}, nil
	}
	if changed {
		if err := r.Status().Update(ctx, &waf); err != nil {
			return ctrl.Result{}, err
		}
	}

	if err := pipeline.Publish(res.Portable, r.publishers(), pipeline.Options{}); err != nil {
		reason, msg := publishErrorReason(err)
		return ctrl.Result{}, r.markNotReady(ctx, &waf, reason, msg)
	}

	slotKind, slotName, err := r.slotRegistry().EnsureDesired(ctx, r.Client, &waf, res.Portable)
	if err != nil {
		return ctrl.Result{}, r.markNotReady(ctx, &waf, "SlotFailed", err.Error())
	}

	// Refresh object for status write (avoid conflict after earlier status updates).
	if err := r.Get(ctx, req.NamespacedName, &waf); err != nil {
		return ctrl.Result{}, err
	}

	rulesN, actionsN := references2.CountSecLangObjects(res.ResolvedObjects)
	rendered, truncated := renderDirectivesForStatus(res.Portable.Directives)
	providerDetection := res.ProviderDetection

	waf.Status.Provider = res.Portable.Provider
	waf.Status.ProviderDetection = providerDetection
	waf.Status.Engine = res.Portable.Engine
	waf.Status.Mode = effectiveMode(waf.Spec.Mode)
	waf.Status.ChallengeEnabled = false
	waf.Status.ChallengeSecretName = ""
	for _, f := range res.Portable.Filters {
		if f.Role == config.FilterRoleChallenge {
			waf.Status.ChallengeEnabled = true
			waf.Status.ChallengeSecretName = res.Challenge.SecretName
			break
		}
	}
	waf.Status.ECDSResourceName = res.Portable.ExtensionName
	if r.ECDS != nil {
		waf.Status.ECDSVersion = r.ECDS.Version()
	}
	waf.Status.SlotKind = slotKind
	waf.Status.SlotName = slotName
	waf.Status.RulesLoaded = int32(rulesN)
	waf.Status.ActionsLoaded = int32(actionsN)
	waf.Status.DirectivesCount = int32(len(res.Portable.Directives))
	waf.Status.RenderedDirectives = rendered
	waf.Status.RenderedDirectivesTruncated = truncated
	refs, omitted, truncatedRefs := leafRuleRefs(res.ResolvedObjects)
	waf.Status.RuleRefs = refs
	waf.Status.RuleRefsOmitted = omitted
	waf.Status.RuleRefsTruncated = truncatedRefs
	r.applyTelemetrySink(ctx, &waf)

	if res.PhraseFiles != nil {
		waf.Status.DataFilesCount = int32(len(res.PhraseFiles.Files))
		waf.Status.DataFilesRawBytes = res.PhraseFiles.RawBytes
		waf.Status.DataFilesContentHash = res.PhraseFiles.ContentHash
		plStatus := metav1.ConditionTrue
		if !res.PhraseFiles.Ready {
			plStatus = metav1.ConditionFalse
		}
		meta.SetStatusCondition(&waf.Status.Conditions, metav1.Condition{
			Type:               "PhraseListsResolved",
			Status:             plStatus,
			Reason:             res.PhraseFiles.ConditionReason,
			Message:            res.PhraseFiles.ConditionMessage,
			ObservedGeneration: waf.Generation,
		})
	}

	msg := fmt.Sprintf("engine=%s mode=%s provider=%s ECDS %s rules=%d actions=%d directives=%d slot=%s (%s)",
		res.Portable.Engine, waf.Status.Mode, res.Portable.Provider, res.Portable.ExtensionName,
		rulesN, actionsN, len(res.Portable.Directives), slotKind, providerDetection)
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

	r.eventf(&waf, corev1.EventTypeNormal, "Ready", msg)

	metrics.WAFReady.WithLabelValues(waf.Namespace, waf.Name).Set(1)
	crsEnabled := 0.0
	if waf.Spec.CRSEnable {
		crsEnabled = 1.0
	}
	metrics.WAFCRSEnabled.WithLabelValues(waf.Namespace, waf.Name).Set(crsEnabled)
	// Metric is SecRule count only (not RuleSet wrappers / total objects).
	metrics.RulesLoaded.WithLabelValues(waf.Namespace, waf.Name, "waf").Set(float64(rulesN))

	return ctrl.Result{}, nil
}

func (r *WAFReconciler) reconcileDelete(ctx context.Context, waf *wafv1beta1.WAF) (ctrl.Result, error) {
	logger := logf.FromContext(ctx)

	pipeline.DropLocal(waf.Namespace, waf.Name, r.publishers())
	// Provider slots: ignore missing CRDs (EG-only clusters have neither Istio nor Cilium).
	if err := r.slotRegistry().DeleteAll(ctx, r.Client, waf.Namespace, waf.Name); err != nil {
		logger.Error(err, "slot delete failed")
		return ctrl.Result{}, err
	}

	// Unlock SecLang back-references written during AddUpdateReconcile.
	if err := controller.CleanupBackReferences(ctx, r.Client, waf); err != nil {
		logger.Error(err, "cleanup back-references failed")
		return ctrl.Result{}, err
	}

	// Drop both finalizers written during reconcile:
	//  - waf.kubewaf.io/ecds (ECDS/slot ownership)
	//  - finalizer.kubewaf.io (generic InitHandler finalizer)
	removed := controllerutil.RemoveFinalizer(waf, wafFinalizer)
	if controllerutil.RemoveFinalizer(waf, controller.Finalizer) {
		removed = true
	}
	if removed {
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
	r.eventf(waf, corev1.EventTypeWarning, reason, msg)
	return fmt.Errorf("%s: %s", reason, msg)
}

func (r *WAFReconciler) eventf(waf *wafv1beta1.WAF, eventtype, reason, message string) {
	if r == nil || r.Recorder == nil || waf == nil {
		return
	}
	r.Recorder.Event(waf, eventtype, reason, message)
}

func effectiveMode(m wafv1beta1.WAFMode) wafv1beta1.WAFMode {
	if m == wafv1beta1.WAFModeDetectionOnly {
		return wafv1beta1.WAFModeDetectionOnly
	}
	return wafv1beta1.WAFModeBlocking
}

func renderDirectivesForStatus(directives []string) (text string, truncated bool) {
	if len(directives) == 0 {
		return "", false
	}
	text = strings.Join(directives, "\n")
	if len(text) <= maxRenderedDirectivesBytes {
		return text, false
	}
	// Truncate on a byte boundary; append marker for operators.
	cut := maxRenderedDirectivesBytes
	// Avoid cutting mid-line when possible.
	if i := strings.LastIndex(text[:cut], "\n"); i > cut/2 {
		cut = i
	}
	return text[:cut] + "\n# ... truncated by kubeWAF (status size cap) ...\n", true
}

// SetupWithManager sets up the controller with the Manager.
// Watches RuleSet, SecRule, and SecAction via reverse indexes (status.RuleSetRefs / field index)
// so Path B rule changes republish ECDS without requeueing every WAF in the cluster.
func (r *WAFReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &wafv1beta1.WAF{}, dpindex.WAFRuleRefField, dpindex.IndexWAFRuleRefs); err != nil {
		return fmt.Errorf("index WAF %s: %w", dpindex.WAFRuleRefField, err)
	}
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &wafv1beta1.RuleSet{}, dpindex.RuleSetRuleRefField, dpindex.IndexRuleSetRuleRefs); err != nil {
		return fmt.Errorf("index RuleSet %s: %w", dpindex.RuleSetRuleRefField, err)
	}

	mapRuleSet := handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, obj client.Object) []reconcile.Request {
		return dpindex.MapRuleSetToWAFs(ctx, r.Client, obj)
	})
	mapSecLang := handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, obj client.Object) []reconcile.Request {
		return dpindex.MapSecLangToWAFs(ctx, r.Client, obj)
	})
	mapPhraseList := handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, obj client.Object) []reconcile.Request {
		return dpindex.MapPhraseListToWAFs(ctx, r.Client, obj)
	})
	mapIPList := handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, obj client.Object) []reconcile.Request {
		return dpindex.MapIPListToWAFs(ctx, r.Client, obj)
	})
	mapObsCM := handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, obj client.Object) []reconcile.Request {
		if obj == nil || obj.GetNamespace() != operatorNamespace() || !isObservabilityConfigMap(obj.GetName()) {
			return nil
		}
		var list wafv1beta1.WAFList
		if err := r.List(ctx, &list); err != nil {
			return nil
		}
		var reqs []reconcile.Request
		for i := range list.Items {
			w := &list.Items[i]
			if w.Spec.Telemetry != nil && w.Spec.Telemetry.Mode == wafv1beta1.TelemetryModeManaged {
				reqs = append(reqs, reconcile.Request{NamespacedName: types.NamespacedName{
					Name: w.Name, Namespace: w.Namespace,
				}})
			}
		}
		return reqs
	})
	return ctrl.NewControllerManagedBy(mgr).
		For(&wafv1beta1.WAF{}).
		Owns(&corev1.Secret{}).
		Watches(&wafv1beta1.RuleSet{}, mapRuleSet).
		Watches(&seclangv1beta1.SecRule{}, mapSecLang).
		Watches(&seclangv1beta1.SecAction{}, mapSecLang).
		Watches(&seclangv1beta1.PhraseList{}, mapPhraseList).
		Watches(&seclangv1beta1.IPList{}, mapIPList).
		Watches(&corev1.ConfigMap{}, mapObsCM).
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

// publishErrorReason maps pipeline.Publish errors to stable Ready condition reasons.
func publishErrorReason(err error) (reason, msg string) {
	if err == nil {
		return "PublishFailed", ""
	}
	s := err.Error()
	switch {
	case strings.HasPrefix(s, "ECDSNotConfigured:"):
		return "ECDSNotConfigured", strings.TrimSpace(strings.TrimPrefix(s, "ECDSNotConfigured:"))
	case strings.HasPrefix(s, "ECDSUpsertFailed:"):
		return "ECDSUpsertFailed", strings.TrimSpace(strings.TrimPrefix(s, "ECDSUpsertFailed:"))
	default:
		return "PublishFailed", s
	}
}
