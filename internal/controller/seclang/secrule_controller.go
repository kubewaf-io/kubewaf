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
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	seclangv1beta1 "github.com/buzz-it/kubewaf/api/seclang/v1beta1"
	"github.com/buzz-it/kubewaf/api/seclang/v1beta1/convert"
	wafv1beta1 "github.com/buzz-it/kubewaf/api/waf/v1beta1"
	"github.com/buzz-it/kubewaf/internal/controller"
	"github.com/buzz-it/kubewaf/internal/coraza"
)

// SecRuleReconciler reconciles a SecRule object
type SecRuleReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=seclan.kubewaf.io,resources=secrules,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=seclan.kubewaf.io,resources=secrules/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=seclan.kubewaf.io,resources=secrules/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the SecRule object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.22.4/pkg/reconcile
func (r *SecRuleReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	l := logf.FromContext(ctx)
	var (
		secRule = &seclangv1beta1.SecRule{}
		updated bool
	)

	updated, err := controller.InitHandler(ctx, req, secRule, r.Client)
	if err != nil {
		return ctrl.Result{}, err
	}

	// delete
	if !secRule.DeletionTimestamp.IsZero() {
		var refNotDeleted map[string]bool
		for _, ruleSetRef := range secRule.Status.RuleSetRefs {
			var ruleSet wafv1beta1.RuleSet
			if err := r.Client.Get(ctx, types.NamespacedName{Name: ruleSetRef.Name, Namespace: ruleSetRef.Namespace}, &ruleSet); !errors.IsNotFound(err) {
				return ctrl.Result{}, err
			} else if err != nil {
				refNotDeleted[fmt.Sprintf("%s/%s", ruleSet.Namespace, ruleSetRef.Name)] = false
			}
		}

		if refNotDeleted == nil {
			updated := controllerutil.RemoveFinalizer(secRule, controller.RuleSetRefFinalizer)
			updated2 := controllerutil.RemoveFinalizer(secRule, controller.Finalizer)
			if updated || updated2 {
				if err := r.Client.Delete(ctx, secRule); err != nil {
					return ctrl.Result{}, err
				}
			}
		}
	}

	if updated {
		if err := r.Client.Update(ctx, secRule); err != nil {
			return ctrl.Result{}, err
		}
		l.Info("Added finalizer to SecRule")
	}

	crslangSecRule, err := convert.ConvertSecRule(*secRule)
	if err != nil {
		return ctrl.Result{}, err
	}

	// validate Rule
	_, validateErr := coraza.LoadAndValidateSeclangDirectives(crslangSecRule)
	var conditionChanged bool
	if validateErr == nil {
		conditionChanged = meta.SetStatusCondition(&secRule.Status.Conditions, metav1.Condition{
			Type:               controller.ConditionTypeReady,
			Status:             metav1.ConditionTrue,
			Reason:             "CouldLoadRulesToCoraza",
			ObservedGeneration: secRule.Generation,
		})
		if conditionChanged {
			l.Info("Updated Ready condition to True")
		}
	} else {
		conditionChanged = meta.SetStatusCondition(&secRule.Status.Conditions, metav1.Condition{
			Type:               controller.ConditionTypeReady,
			Status:             metav1.ConditionFalse,
			Reason:             "CouldNotLoadRulesToCoraza",
			Message:            fmt.Sprintf("Could load Rules to Coraza: %v", validateErr),
			ObservedGeneration: secRule.Generation,
		})
		if conditionChanged {
			l.Info("Updated Ready condition to False")
		}
	}

	if conditionChanged {
		l.Info("Updated SecRule status with generated SecLang string")
		if err := r.Client.Status().Update(ctx, secRule); err != nil {
			return ctrl.Result{}, err
		}
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *SecRuleReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&seclangv1beta1.SecRule{}).
		Named("secrule").
		Complete(r)
}

// func secRuleSpecToSecRule(secRuleSpec seclangv1beta1.SecRuleSpec) (crslang_types.SecRule, error) {
// 	data, err := json.Marshal(secRuleSpec)
// 	if err != nil {
// 		return crslang_types.SecRule{}, err
// 	}
// 	fmt.Println(fmt.Println(string(data)))
// 	var rule crslang_types.SecRule
// 	if err := json.Unmarshal(data, &rule); err != nil {
// 		return crslang_types.SecRule{}, fmt.Errorf("Could not Unmarshal Object into crs Object=%s", err.Error())
// 	}
// 	ruleData, err := json.Marshal(rule)
// 	if err != nil {
// 		return crslang_types.SecRule{}, err
// 	}
// 	fmt.Println(string(ruleData))

// 	return rule, nil
// }

//	func copySecRuleSpecToCRS(secRule *seclangv1beta1.SecRule) crslang_types.SecRule {
//		return crslang_types.SecRule{}
//	}
