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

package seclang

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
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
	internalseclang "github.com/kubewaf-io/kubewaf/internal/seclang"
)

// SecRuleReconciler reconciles a SecRule object: id allocation, label mirrors, SecLang validation.
type SecRuleReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=seclang.kubewaf.io,resources=secrules,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=seclang.kubewaf.io,resources=secrules/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=seclang.kubewaf.io,resources=secrules/finalizers,verbs=update
// +kubebuilder:rbac:groups=seclang.kubewaf.io,resources=secruleidpools,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups=seclang.kubewaf.io,resources=secruleidpools/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=seclang.kubewaf.io,resources=phraselists,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch

// Reconcile allocates rule ids (cluster-scoped pool), mirrors tags to labels, and validates SecLang.
func (r *SecRuleReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	l := logf.FromContext(ctx)
	secRule := &seclangv1beta1.SecRule{}

	updated, err := controller.InitHandler(ctx, req, secRule, r.Client)
	if err != nil {
		return ctrl.Result{}, err
	}

	// Deletion: drop finalizers after RuleSet refs are gone.
	if !secRule.DeletionTimestamp.IsZero() {
		for _, ruleSetRef := range secRule.Status.RuleSetRefs {
			var ruleSet wafv1beta1.RuleSet
			if err := r.Get(ctx, types.NamespacedName{Name: ruleSetRef.Name, Namespace: ruleSetRef.Namespace}, &ruleSet); !errors.IsNotFound(err) && err != nil {
				return ctrl.Result{}, err
			}
		}
		updatedF := controllerutil.RemoveFinalizer(secRule, controller.RuleSetRefFinalizer)
		updatedF2 := controllerutil.RemoveFinalizer(secRule, controller.Finalizer)
		if updatedF || updatedF2 {
			if err := r.Update(ctx, secRule); err != nil {
				return ctrl.Result{}, err
			}
		}
		return ctrl.Result{}, nil
	}

	if updated {
		if err := r.Update(ctx, secRule); err != nil {
			return ctrl.Result{}, err
		}
		l.Info("Added finalizer to SecRule")
		// Re-fetch after update.
		if err := r.Get(ctx, req.NamespacedName, secRule); err != nil {
			return ctrl.Result{}, err
		}
	}

	// --- Cluster-scoped id allocation ---
	used, err := collectUsedIDs(ctx, r.Client)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("list secrules for id pool: %w", err)
	}
	// Free our own previous assignments so we can reuse them.
	for _, id := range secRule.Status.AssignedIDs {
		delete(used, id)
	}
	if secRule.Status.RuleID > 0 {
		delete(used, secRule.Status.RuleID)
	}

	assigned, primary, idSource, err := allocateIDs(ctx, r.Client, secRule, used)
	if err != nil {
		meta.SetStatusCondition(&secRule.Status.Conditions, metav1.Condition{
			Type:               controller.ConditionTypeReady,
			Status:             metav1.ConditionFalse,
			Reason:             "IDAllocationFailed",
			Message:            err.Error(),
			ObservedGeneration: secRule.Generation,
		})
		_ = r.Status().Update(ctx, secRule)
		return ctrl.Result{}, err
	}

	// --- Labels: id, phase, tags ---
	if syncSecRuleLabels(secRule, primary, idSource) {
		if err := r.Update(ctx, secRule); err != nil {
			return ctrl.Result{}, err
		}
		if err := r.Get(ctx, req.NamespacedName, secRule); err != nil {
			return ctrl.Result{}, err
		}
	}

	// Shared render+validate path (same convert used by dataplane assembly).
	// Convert errors (e.g. empty/unknown t: transforms that would emit t:unknown
	// and trap ModSecurity wasm) must keep Ready=False and clear any prior
	// SecRuleString so poison never stays advertised in status.
	// PhraseList/IPList bodies in this namespace are merged into the Coraza root FS so
	// custom @pmFromFile / @ipMatchFromFile basenames can validate (CRS is go:embed).
	overrides, ovErr := r.dataFileOverrides(ctx, secRule)
	if ovErr != nil {
		meta.SetStatusCondition(&secRule.Status.Conditions, metav1.Condition{
			Type:               controller.ConditionTypeReady,
			Status:             metav1.ConditionFalse,
			Reason:             "DataFileLookupFailed",
			Message:            ovErr.Error(),
			ObservedGeneration: secRule.Generation,
		})
		secRule.Status.RuleID = primary
		secRule.Status.IDSource = idSource
		secRule.Status.AssignedIDs = assigned
		_ = r.Status().Update(ctx, secRule)
		return ctrl.Result{}, ovErr
	}
	rendered, err := internalseclang.RenderAndValidateWithOverrides(secRule, assigned, overrides)
	if err != nil {
		meta.SetStatusCondition(&secRule.Status.Conditions, metav1.Condition{
			Type:               controller.ConditionTypeReady,
			Status:             metav1.ConditionFalse,
			Reason:             "ConvertFailed",
			Message:            err.Error(),
			ObservedGeneration: secRule.Generation,
		})
		secRule.Status.RuleID = primary
		secRule.Status.IDSource = idSource
		secRule.Status.AssignedIDs = assigned
		secRule.Status.SecRuleString = ""
		_ = r.Status().Update(ctx, secRule)
		// Do not return err: condition is durable; avoid hot-loop requeue on
		// permanent Spec convert failures (unknown transform, etc.).
		return ctrl.Result{}, nil
	}
	if rendered.ValidateErr == nil {
		meta.SetStatusCondition(&secRule.Status.Conditions, metav1.Condition{
			Type:               controller.ConditionTypeReady,
			Status:             metav1.ConditionTrue,
			Reason:             "CouldLoadRulesToCoraza",
			Message:            fmt.Sprintf("ruleId=%d idSource=%s", primary, idSource),
			ObservedGeneration: secRule.Generation,
		})
	} else {
		reason := "CouldNotLoadRulesToCoraza"
		msg := fmt.Sprintf("Could not load rules to Coraza: %v", rendered.ValidateErr)
		// Surface missing custom phrase lists more clearly when Coraza fails open on FS.
		if internalseclang.LooksLikeMissingDataFile(rendered.ValidateErr) {
			reason = "MissingPhraseList"
		}
		meta.SetStatusCondition(&secRule.Status.Conditions, metav1.Condition{
			Type:               controller.ConditionTypeReady,
			Status:             metav1.ConditionFalse,
			Reason:             reason,
			Message:            msg,
			ObservedGeneration: secRule.Generation,
		})
	}

	secRule.Status.RuleID = primary
	secRule.Status.IDSource = idSource
	secRule.Status.AssignedIDs = assigned
	secRule.Status.SecRuleString = rendered.SecLang

	if err := r.Status().Update(ctx, secRule); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

// dataFileOverrides builds basename→body for Ready PhraseLists and IPLists in the SecRule namespace.
func (r *SecRuleReconciler) dataFileOverrides(ctx context.Context, sr *seclangv1beta1.SecRule) (map[string][]byte, error) {
	out := map[string][]byte{}
	var list seclangv1beta1.PhraseListList
	if err := r.List(ctx, &list, client.InNamespace(sr.Namespace)); err != nil {
		// PhraseList CRD may not be installed yet — treat as no overrides.
		if !meta.IsNoMatchError(err) {
			return nil, err
		}
	} else {
		for i := range list.Items {
			pl := &list.Items[i]
			if !meta.IsStatusConditionTrue(pl.Status.Conditions, controller.ConditionTypeReady) {
				continue
			}
			body, err := config.ResolvePhraseListBody(ctx, r.Client, pl)
			if err != nil {
				// Skip unreadable; Coraza will fail if SecRule needs it.
				continue
			}
			if pl.Spec.FileName != "" {
				out[pl.Spec.FileName] = body
			}
		}
	}
	var ipList seclangv1beta1.IPListList
	if err := r.List(ctx, &ipList, client.InNamespace(sr.Namespace)); err != nil {
		if !meta.IsNoMatchError(err) {
			return nil, err
		}
	} else {
		for i := range ipList.Items {
			ipl := &ipList.Items[i]
			if !meta.IsStatusConditionTrue(ipl.Status.Conditions, controller.ConditionTypeReady) {
				continue
			}
			body, err := config.ResolveIPListBody(ctx, r.Client, ipl)
			if err != nil {
				continue
			}
			if ipl.Spec.FileName != "" {
				out[ipl.Spec.FileName] = body
			}
		}
	}
	return out, nil
}

// SetupWithManager sets up the controller with the Manager.
// Leader election is inherited from the manager (id allocation must be single-writer).
func (r *SecRuleReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&seclangv1beta1.SecRule{}).
		Watches(&seclangv1beta1.PhraseList{}, handler.EnqueueRequestsFromMapFunc(r.mapDataFileToSecRules)).
		Watches(&seclangv1beta1.IPList{}, handler.EnqueueRequestsFromMapFunc(r.mapDataFileToSecRules)).
		Named("secrule").
		Complete(r)
}

func (r *SecRuleReconciler) mapDataFileToSecRules(ctx context.Context, obj client.Object) []reconcile.Request {
	if obj == nil {
		return nil
	}
	// Revalidate all SecRules in the namespace (v1; refine later by basename scan).
	var list seclangv1beta1.SecRuleList
	if err := r.List(ctx, &list, client.InNamespace(obj.GetNamespace())); err != nil {
		return nil
	}
	reqs := make([]reconcile.Request, 0, len(list.Items))
	for i := range list.Items {
		sr := &list.Items[i]
		reqs = append(reqs, reconcile.Request{NamespacedName: types.NamespacedName{
			Namespace: sr.Namespace,
			Name:      sr.Name,
		}})
	}
	return reqs
}
