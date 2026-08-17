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
	"strings"

	wafv1beta1 "github.com/kubewaf-io/kubewaf/api/waf/v1beta1"
	"github.com/kubewaf-io/kubewaf/internal/controller"
	"github.com/kubewaf-io/kubewaf/internal/references2"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// RuleSetReconciler reconciles a RuleSet object
type RuleSetReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=waf.kubewaf.io,resources=rulesets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=waf.kubewaf.io,resources=rulesets/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=waf.kubewaf.io,resources=rulesets/finalizers,verbs=update
// +kubebuilder:rbac:groups=seclang.kubewaf.io,resources=secrules;secactions,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=seclang.kubewaf.io,resources=secrules/status;secactions/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=seclang.kubewaf.io,resources=secrules/finalizers;secactions/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=namespaces,verbs=get;list;watch

// Reconcile resolves RuleRefs, enforces allowedRules, sets ReferencesResolved, and
// cleans SecLang back-references on deletion.
func (r *RuleSetReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	l := logf.FromContext(ctx)
	ruleSet := wafv1beta1.RuleSet{}

	updated, err := controller.InitHandler(ctx, req, &ruleSet, r.Client)
	if err != nil {
		if errors.IsNotFound(err) {
			l.V(1).Info("RuleSet not found, skipping")
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	// Handle deletion: drop back-refs on SecRule/SecAction, then finalizer.
	if !ruleSet.DeletionTimestamp.IsZero() {
		if err := controller.CleanupBackReferences(ctx, r.Client, &ruleSet); err != nil {
			return ctrl.Result{}, err
		}
		if controllerutil.RemoveFinalizer(&ruleSet, controller.Finalizer) {
			if err := r.Update(ctx, &ruleSet); err != nil {
				return ctrl.Result{}, err
			}
		}
		return ctrl.Result{}, nil
	}

	// Persist finalizer before status work so deletion cannot race past cleanup.
	if updated {
		if err := r.Update(ctx, &ruleSet); err != nil {
			return ctrl.Result{}, err
		}
		if err := r.Get(ctx, req.NamespacedName, &ruleSet); err != nil {
			return ctrl.Result{}, err
		}
	}

	_, resolved, err := r.ruleRefHandler(ctx, &ruleSet)
	if err != nil {
		return ctrl.Result{}, err
	}

	// Surface resolved member names for kubectl / UI (best-effort, not exhaustive for selectors).
	refs := make([]wafv1beta1.RuleRefStatus, 0, len(resolved))
	for i := range resolved {
		refs = append(refs, wafv1beta1.RuleRefStatus{
			Kind:      resolved[i].GetKind(),
			Name:      resolved[i].GetName(),
			Namespace: resolved[i].GetNamespace(),
		})
	}
	ruleSet.Status.RuleRefs = refs
	rulesN, actionsN := references2.CountSecLangObjects(resolved)
	ruleSet.Status.RulesLoaded = int32(rulesN)
	ruleSet.Status.ActionsLoaded = int32(actionsN)

	if err = r.Status().Update(ctx, &ruleSet); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *RuleSetReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&wafv1beta1.RuleSet{}).
		Named("waf-ruleset").
		Complete(r)
}

// ruleRefHandler uses the shared references2.RuleRefResolver to resolve RuleRefs
// (RuleSets can reference any kind; non-RuleSet owners restricted to RuleSet only),
// manage automatic back-references (finalizers + status.RuleSetRefs on targets),
// recursively flatten RuleSet references, aggregate errors.
func (r *RuleSetReconciler) ruleRefHandler(ctx context.Context, ruleSet *wafv1beta1.RuleSet) (bool, []unstructured.Unstructured, error) {
	var (
		updated      bool
		newCondition metav1.Condition
	)
	resolver := references2.NewRuleRefResolver(r.Client, r.Scheme)

	resolved, errs, err := resolver.AddUpdateReconcile(ctx, ruleSet.Spec.RuleRefs, ruleSet)
	if err != nil {
		return updated, nil, err
	}

	if len(errs) > 0 {
		msgs := make([]string, len(errs))
		for i, e := range errs {
			msgs[i] = e.Error()
		}
		message := strings.Join(msgs, " ")
		newCondition = metav1.Condition{
			Type:               controller.ConditionTypeReferencesResolved,
			Status:             metav1.ConditionFalse,
			ObservedGeneration: ruleSet.Generation,
			Reason:             "ResolvedRefsFailed",
			Message:            message,
		}

	} else {
		newCondition = metav1.Condition{
			Type:               controller.ConditionTypeReferencesResolved,
			Status:             metav1.ConditionTrue,
			ObservedGeneration: ruleSet.Generation,
			Reason:             "ResolvedRefs",
		}
	}
	updated = meta.SetStatusCondition(&ruleSet.Status.Conditions, newCondition)

	return updated, resolved, nil
}
