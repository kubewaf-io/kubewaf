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

// Package sync keeps the local ECDS snapshot and Envoy Gateway extension index
// warm on EVERY operator replica (not only the leader).
//
// Kubernetes writes (status, finalizers, EnvoyFilter slots) stay on the
// leader-elected WAF controller. Envoy and Envoy Gateway load-balance against
// the Service, so every pod must serve the same ECDS configs.
//
// Build+publish uses the shared internal/dataplane/pipeline package so this
// path cannot drift from the leader reconciler.
package sync

import (
	"context"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	seclangv1beta1 "github.com/kubewaf-io/kubewaf/api/seclang/v1beta1"
	wafv1beta1 "github.com/kubewaf-io/kubewaf/api/waf/v1beta1"
	"github.com/kubewaf-io/kubewaf/internal/dataplane/config"
	"github.com/kubewaf-io/kubewaf/internal/dataplane/ecds"
	"github.com/kubewaf-io/kubewaf/internal/dataplane/extensionserver"
	dpindex "github.com/kubewaf-io/kubewaf/internal/dataplane/index"
	"github.com/kubewaf-io/kubewaf/internal/dataplane/pipeline"
)

// Reconciler publishes portable WAF config into local ECDS / EG extension indexes.
// It must run with NeedLeaderElection=false.
type Reconciler struct {
	client.Client
	Scheme      *runtime.Scheme
	ECDS        *ecds.Server
	EGExtension *extensionserver.Server
	BuildOpts   config.BuildOptions
}

func (r *Reconciler) publishers() pipeline.Publishers {
	return pipeline.Publishers{ECDS: r.ECDS, EGExtension: r.EGExtension}
}

// Reconcile keeps this pod's dataplane caches in sync with the WAF CR.
func (r *Reconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := logf.FromContext(ctx).WithValues("controller", "waf-dataplane-sync")

	var waf wafv1beta1.WAF
	if err := r.Get(ctx, req.NamespacedName, &waf); err != nil {
		if client.IgnoreNotFound(err) == nil {
			pipeline.DropLocal(req.Namespace, req.Name, r.publishers())
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	if !waf.DeletionTimestamp.IsZero() {
		pipeline.DropLocal(waf.Namespace, waf.Name, r.publishers())
		return ctrl.Result{}, nil
	}

	// Same pipeline as the leader, but read-only refs and read-only challenge Secret.
	// RequireRefsOK keeps the last good ECDS snapshot when RuleSets/SecLang are missing.
	res, err := pipeline.BuildAndPublish(ctx, r.Client, &waf, r.publishers(), pipeline.Options{
		BuildOpts:             r.BuildOpts,
		Scheme:                r.Scheme,
		EnsureChallengeSecret: false,
		LockRefs:              false,
		RequireRefsOK:         true,
	})
	if err != nil {
		// Secret may not exist yet on non-leader; requeue until leader creates it.
		// Do not DropLocal — unresolved refs must not wipe a last-good snapshot.
		return ctrl.Result{}, err
	}

	logger.V(1).Info("dataplane cache updated",
		"extension", res.Portable.ExtensionName,
		"provider", res.Portable.Provider,
		"objects", res.ResolvedObjectN,
	)
	return ctrl.Result{}, nil
}

// SetupWithManager registers a non-leader-elected controller so every replica
// serves current ECDS configs.
func (r *Reconciler) SetupWithManager(mgr ctrl.Manager) error {
	// Field indexes may already be registered by the leader WAF controller; ignore duplicate errors.
	_ = mgr.GetFieldIndexer().IndexField(context.Background(), &wafv1beta1.WAF{}, dpindex.WAFRuleRefField, dpindex.IndexWAFRuleRefs)
	_ = mgr.GetFieldIndexer().IndexField(context.Background(), &wafv1beta1.RuleSet{}, dpindex.RuleSetRuleRefField, dpindex.IndexRuleSetRuleRefs)

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

	return ctrl.NewControllerManagedBy(mgr).
		For(&wafv1beta1.WAF{}).
		Watches(&wafv1beta1.RuleSet{}, mapRuleSet).
		Watches(&seclangv1beta1.SecRule{}, mapSecLang).
		Watches(&seclangv1beta1.SecAction{}, mapSecLang).
		Watches(&seclangv1beta1.PhraseList{}, mapPhraseList).
		Watches(&seclangv1beta1.IPList{}, mapIPList).
		WithOptions(controller.Options{NeedLeaderElection: ptr.To(false)}).
		Named("waf-dataplane-sync").
		Complete(r)
}
