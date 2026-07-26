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
package sync

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
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
	"github.com/kubewaf-io/kubewaf/internal/references2"
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

// Reconcile keeps this pod's dataplane caches in sync with the WAF CR.
func (r *Reconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := logf.FromContext(ctx).WithValues("controller", "waf-dataplane-sync")

	var waf wafv1beta1.WAF
	if err := r.Get(ctx, req.NamespacedName, &waf); err != nil {
		if client.IgnoreNotFound(err) == nil {
			// Deleted: drop from local caches.
			name := config.ExtensionName(req.Namespace, req.Name)
			if r.ECDS != nil {
				_ = r.ECDS.Delete(name)
			}
			if r.EGExtension != nil {
				r.EGExtension.Delete(req.Namespace, req.Name)
			}
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	if !waf.DeletionTimestamp.IsZero() {
		name := config.ExtensionName(waf.Namespace, waf.Name)
		if r.ECDS != nil {
			_ = r.ECDS.Delete(name)
		}
		if r.EGExtension != nil {
			r.EGExtension.Delete(waf.Namespace, waf.Name)
		}
		return ctrl.Result{}, nil
	}

	resolver := references2.NewRuleRefResolver(r.Client, r.Scheme)
	objects, errs, err := resolver.Resolve(ctx, waf.Spec.RuleSetRefs, &waf)
	if err != nil {
		return ctrl.Result{}, err
	}
	if len(errs) > 0 {
		logger.V(1).Info("reference errors during dataplane sync", "errs", errs)
		// Still attempt with whatever resolved; leader status will reflect failures.
	}

	rules, err := references2.GetSecRule(objects)
	if err != nil {
		return ctrl.Result{}, err
	}

	portable, err := config.BuildFromWAF(&waf, rules, r.BuildOpts)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("build portable config: %w", err)
	}

	if r.ECDS != nil {
		if err := r.ECDS.Upsert(portable); err != nil {
			return ctrl.Result{}, fmt.Errorf("ecds upsert: %w", err)
		}
	}
	if r.EGExtension != nil {
		// Index for EG hooks; no-op for Istio provider inside Upsert.
		r.EGExtension.Upsert(portable)
	}

	logger.V(1).Info("dataplane cache updated",
		"extension", portable.ExtensionName,
		"provider", portable.Provider,
		"rules", len(rules),
	)
	return ctrl.Result{}, nil
}

// SetupWithManager registers a non-leader-elected controller so every replica
// serves current ECDS configs.
func (r *Reconciler) SetupWithManager(mgr ctrl.Manager) error {
	mapAllWAFs := handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, obj client.Object) []reconcile.Request {
		var list wafv1beta1.WAFList
		if err := r.List(ctx, &list); err != nil {
			return nil
		}
		reqs := make([]reconcile.Request, 0, len(list.Items))
		for i := range list.Items {
			reqs = append(reqs, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      list.Items[i].Name,
					Namespace: list.Items[i].Namespace,
				},
			})
		}
		return reqs
	})

	return ctrl.NewControllerManagedBy(mgr).
		For(&wafv1beta1.WAF{}).
		Watches(&wafv1beta1.RuleSet{}, mapAllWAFs).
		Watches(&seclangv1beta1.SecRule{}, mapAllWAFs).
		Named("waf-dataplane-sync").
		WithOptions(controller.Options{
			// Critical for multi-replica: run on every pod, not only the leader.
			NeedLeaderElection: ptr.To(false),
		}).
		Complete(r)
}
