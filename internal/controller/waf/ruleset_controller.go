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

	seclangv1beta1 "github.com/buzz-it/kubewaf/api/seclang/v1beta1"
	wafv1beta1 "github.com/buzz-it/kubewaf/api/waf/v1beta1"
	"github.com/buzz-it/kubewaf/internal/controller"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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

	// getRefs
	_, err = r.ruleRefHandler(ctx, &ruleSet)
	if err != nil {
		return ctrl.Result{}, err
	}

	// TODO(user): your logic here
	// err = r.Client.Update(ctx, &ruleSet)
	// if err != nil {
	// 	return ctrl.Result{}, err
	// }

	err = r.Client.Status().Update(ctx, &ruleSet)
	return ctrl.Result{}, err
}

// SetupWithManager sets up the controller with the Manager.
func (r *RuleSetReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&wafv1beta1.RuleSet{}).
		Named("waf-ruleset").
		Complete(r)
}

func (r *RuleSetReconciler) ruleRefHandler(ctx context.Context, ruleSet *wafv1beta1.RuleSet) ([]seclangv1beta1.SecRule, error) {
	var (
		errs     []string
		secRules []seclangv1beta1.SecRule
	)
	const conditionType = "ReferencesResolved"

	for i, ruleRef := range ruleSet.Spec.RuleRefs {
		switch ruleRef.Kind {
		case "SecRule":
			var secRuleList seclangv1beta1.SecRuleList
			if ruleRef.Selector != nil {
				if err := r.Client.List(ctx, &secRuleList, client.InNamespace(ruleRef.Namespace), client.MatchingLabels(ruleRef.Selector.MatchLabels)); err != nil {
					return secRules, err

				}
				for _, secRule := range secRuleList.Items {
					if err := r.ruleRefHandlerAdd(ctx, &secRule, ruleSet); err != nil {
						return secRules, err
					}
				}
			}
		// case "RuleSet":
		// 	var ruleSetList wafv1beta1.RuleSetList
		// 	if ruleRef.Selector != nil {
		// 		if err := r.Client.List(ctx, &ruleSetList, client.InNamespace(ruleRef.Namespace), client.MatchingLabels(ruleRef.Selector.MatchLabels)); err != nil {
		// 			return secRules, err
		// 		}
		// 		for _, ref := range ruleSetList.Items {
		// 			// var secLangRules []string
		// 			for _, ruleRefs := range ref.Status.RuleRefs {
		// 				if ruleRefs.Kind == ref.Kind && ruleRefs.Name == ref.Name && ruleRefs.Namespace == ref.Namespace {
		// 					return secRules, nil
		// 				}
		// 			}
		// 			ruleRefStatus := wafv1beta1.RuleRefStatus{Name: ref.GetName(), Namespace: ref.GetNamespace(), SecLangRule: ref.GetSecLangRule(), Kind: "RuleSet"}
		// 			ruleSet.Status.RuleRefs = append(ruleSet.Status.RuleRefs, ruleRefStatus)
		// 		}

		// 	}

		default:
			errs = append(errs, fmt.Sprintf("RuleRef[%d]: unsupported kind %q (only SecLang allowed)", i, ruleRef.Kind))
		}
	}

	// Condition Handler
	if len(errs) > 0 {
		meta.SetStatusCondition(&ruleSet.Status.Conditions, metav1.Condition{
			Type:               conditionType,
			Status:             metav1.ConditionFalse,
			Reason:             "InvalidReferences",
			Message:            fmt.Sprintf("Invalid RuleRefs: %s", strings.Join(errs, "; ")),
			ObservedGeneration: ruleSet.Generation,
			LastTransitionTime: metav1.Now(),
		})
	} else {
		meta.SetStatusCondition(&ruleSet.Status.Conditions, metav1.Condition{
			Type:               conditionType,
			Status:             metav1.ConditionTrue,
			Reason:             "Resolved",
			Message:            "All RuleRefs are valid",
			ObservedGeneration: ruleSet.Generation,
			LastTransitionTime: metav1.Now(),
		})
	}

	return secRules, nil

}

func (r *RuleSetReconciler) ruleRefHandlerAdd(ctx context.Context, obj seclangv1beta1.SecLang, ruleSet *wafv1beta1.RuleSet) error {
	if updated := controllerutil.AddFinalizer(obj, "secrule.waf.kubewaf.io"); updated {
		err := r.Client.Update(ctx, obj)
		if err != nil {
			return err
		}
	}
	if updated := obj.AddRuleSetRef(seclangv1beta1.RuleSetRef{Name: ruleSet.Name, Namespace: ruleSet.Namespace}); updated {
		err := r.Client.Status().Update(ctx, obj)
		if err != nil {
			return err
		}
	}
	ruleRefStatus := wafv1beta1.RuleRefStatus{Name: obj.GetName(), Namespace: obj.GetNamespace(), Kind: obj.GetObjectKind().GroupVersionKind().Kind}

	for _, ref := range ruleSet.Status.RuleRefs {
		if ref.Kind == ruleRefStatus.Kind && ref.Namespace == ruleRefStatus.Namespace && ref.Name == ruleRefStatus.Name {
			return nil
		}
	}
	ruleSet.Status.RuleRefs = append(ruleSet.Status.RuleRefs, ruleRefStatus)
	return nil
}
