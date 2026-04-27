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

	wafv1beta1 "github.com/buzz-it/kubewaf/api/waf/v1beta1"
	"github.com/buzz-it/kubewaf/internal/controller"
	"github.com/buzz-it/kubewaf/internal/references2"
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

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the RuleSet object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.22.4/pkg/reconcile
func (r *RuleSetReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	l := logf.FromContext(ctx)
	ruleSet := wafv1beta1.RuleSet{}

	_, err := controller.InitHandler(ctx, req, &ruleSet, r.Client)
	if err != nil {
		if errors.IsNotFound(err) {
			l.V(1).Info("RuleSet not found, skipping")
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	// Handle deletion
	if !ruleSet.DeletionTimestamp.IsZero() {
		fmt.Println("hi")
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

	_, _, err = r.ruleRefHandler(ctx, &ruleSet)
	fmt.Println(ruleSet.Status.Conditions)
	if err != nil {
		return ctrl.Result{}, err
	}

	// TODO(user): your logic here (use resolved rules from ruleRefHandler if needed)

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
