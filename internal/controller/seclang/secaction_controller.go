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

	seclangv1beta1 "github.com/kubewaf-io/kubewaf/api/seclang/v1beta1"
	"github.com/kubewaf-io/kubewaf/api/seclang/v1beta1/convert"
	wafv1beta1 "github.com/kubewaf-io/kubewaf/api/waf/v1beta1"
	"github.com/kubewaf-io/kubewaf/internal/controller"
	"github.com/kubewaf-io/kubewaf/internal/coraza"
)

// SecActionReconciler validates SecAction CRs and stores rendered SecLang in status.
type SecActionReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=seclang.kubewaf.io,resources=secactions,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=seclang.kubewaf.io,resources=secactions/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=seclang.kubewaf.io,resources=secactions/finalizers,verbs=update

// Reconcile renders and validates SecLang for a SecAction.
func (r *SecActionReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	l := logf.FromContext(ctx)
	sa := &seclangv1beta1.SecAction{}

	updated, err := controller.InitHandler(ctx, req, sa, r.Client)
	if err != nil {
		return ctrl.Result{}, err
	}

	if !sa.DeletionTimestamp.IsZero() {
		for _, ruleSetRef := range sa.Status.RuleSetRefs {
			var ruleSet wafv1beta1.RuleSet
			if err := r.Get(ctx, types.NamespacedName{Name: ruleSetRef.Name, Namespace: ruleSetRef.Namespace}, &ruleSet); !errors.IsNotFound(err) && err != nil {
				return ctrl.Result{}, err
			}
		}
		updatedF := controllerutil.RemoveFinalizer(sa, controller.RuleSetRefFinalizer)
		updatedF2 := controllerutil.RemoveFinalizer(sa, controller.Finalizer)
		if updatedF || updatedF2 {
			if err := r.Update(ctx, sa); err != nil {
				return ctrl.Result{}, err
			}
		}
		return ctrl.Result{}, nil
	}

	if updated {
		if err := r.Update(ctx, sa); err != nil {
			return ctrl.Result{}, err
		}
		l.Info("Added finalizer to SecAction")
		if err := r.Get(ctx, req.NamespacedName, sa); err != nil {
			return ctrl.Result{}, err
		}
	}

	// Mirror id / phase / tags as labels (same keys as SecRule).
	primaryID := 0
	if sa.Spec.Metadata != nil {
		primaryID = sa.Spec.Metadata.Id
	}
	// Reuse SecRule label helper via a thin wrapper shape.
	pseudo := &seclangv1beta1.SecRule{
		ObjectMeta: *sa.ObjectMeta.DeepCopy(),
		Spec: seclangv1beta1.SecRuleSpec{
			Metadata: sa.Spec.Metadata,
		},
	}
	idSource := seclangv1beta1.IDSourceSpec
	if primaryID <= 0 {
		idSource = ""
	}
	if syncSecRuleLabels(pseudo, primaryID, idSource) {
		sa.Labels = pseudo.Labels
		sa.Annotations = pseudo.Annotations
		if err := r.Update(ctx, sa); err != nil {
			return ctrl.Result{}, err
		}
		if err := r.Get(ctx, req.NamespacedName, sa); err != nil {
			return ctrl.Result{}, err
		}
	}

	dirs, err := convert.ConvertSecAction(*sa)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("convert SecAction: %w", err)
	}
	secLangString := convert.ConvertToSecLangString(dirs)

	_, validateErr := coraza.LoadAndValidateSeclangDirectives(dirs)
	if validateErr == nil {
		meta.SetStatusCondition(&sa.Status.Conditions, metav1.Condition{
			Type:               controller.ConditionTypeReady,
			Status:             metav1.ConditionTrue,
			Reason:             "CouldLoadRulesToCoraza",
			Message:            fmt.Sprintf("SecAction rendered (%d bytes)", len(secLangString)),
			ObservedGeneration: sa.Generation,
		})
	} else {
		meta.SetStatusCondition(&sa.Status.Conditions, metav1.Condition{
			Type:               controller.ConditionTypeReady,
			Status:             metav1.ConditionFalse,
			Reason:             "CouldNotLoadRulesToCoraza",
			Message:            fmt.Sprintf("Could not load SecAction to Coraza: %v", validateErr),
			ObservedGeneration: sa.Generation,
		})
	}

	sa.Status.SecRuleString = secLangString
	if err := r.Status().Update(ctx, sa); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *SecActionReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&seclangv1beta1.SecAction{}).
		Named("secaction").
		Complete(r)
}
