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

package v1alpha1

import (
	"context"

	seclangv1alpha1 "github.com/kubewaf-io/kubewaf/api/seclang/v1alpha1"
	"github.com/kubewaf-io/kubewaf/internal/compile"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	conditionReady = "Ready"
	reasonCompiled = "Compiled"
	reasonInvalid  = "Invalid"
)

// SecRuleReconciler compiles one SecRule into status.secLang.
type SecRuleReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=seclang.kubewaf.io,resources=secrules,verbs=get;list;watch
// +kubebuilder:rbac:groups=seclang.kubewaf.io,resources=secrules/status,verbs=get;update;patch

// Reconcile compiles the rule and sets Ready. It does not write other objects.
func (r *SecRuleReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	obj := &seclangv1alpha1.SecRule{}
	if err := r.Get(ctx, req.NamespacedName, obj); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if !obj.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, nil
	}
	text, err := compile.EmitRule(obj)
	if err == nil {
		err = compile.Parse(text)
	}
	applyLang(&obj.Status, obj.Generation, text, err)
	return ctrl.Result{}, r.Status().Update(ctx, obj)
}

// SetupWithManager registers the reconciler.
func (r *SecRuleReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).For(&seclangv1alpha1.SecRule{}).Complete(r)
}

// SecActionReconciler compiles one SecAction into status.secLang.
type SecActionReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=seclang.kubewaf.io,resources=secactions,verbs=get;list;watch
// +kubebuilder:rbac:groups=seclang.kubewaf.io,resources=secactions/status,verbs=get;update;patch

// Reconcile compiles the action and sets Ready. It does not write other objects.
func (r *SecActionReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	obj := &seclangv1alpha1.SecAction{}
	if err := r.Get(ctx, req.NamespacedName, obj); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if !obj.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, nil
	}
	text, err := compile.EmitAction(obj)
	if err == nil {
		err = compile.Parse(text)
	}
	applyLang(&obj.Status, obj.Generation, text, err)
	return ctrl.Result{}, r.Status().Update(ctx, obj)
}

// SetupWithManager registers the reconciler.
func (r *SecActionReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).For(&seclangv1alpha1.SecAction{}).Complete(r)
}

// IncludeReconciler compiles one Include into status.secLang.
type IncludeReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=seclang.kubewaf.io,resources=includes,verbs=get;list;watch
// +kubebuilder:rbac:groups=seclang.kubewaf.io,resources=includes/status,verbs=get;update;patch

// Reconcile compiles the include and sets Ready. It does not write other objects.
func (r *IncludeReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	obj := &seclangv1alpha1.Include{}
	if err := r.Get(ctx, req.NamespacedName, obj); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if !obj.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, nil
	}
	text, err := compile.EmitInclude(obj)
	if err == nil {
		err = compile.Parse(text)
	}
	applyLang(&obj.Status, obj.Generation, text, err)
	return ctrl.Result{}, r.Status().Update(ctx, obj)
}

// SetupWithManager registers the reconciler.
func (r *IncludeReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).For(&seclangv1alpha1.Include{}).Complete(r)
}

func applyLang(status *seclangv1alpha1.SecLangStatus, generation int64, text string, err error) {
	if err != nil {
		status.SecLang = ""
		setCondition(&status.Conditions, generation, conditionReady, metav1.ConditionFalse, reasonInvalid, err.Error())
		return
	}
	status.SecLang = text
	setCondition(&status.Conditions, generation, conditionReady, metav1.ConditionTrue, reasonCompiled, "SecLang compiled")
}

func setCondition(conds *[]metav1.Condition, generation int64, typ string, st metav1.ConditionStatus, reason, message string) {
	meta.SetStatusCondition(conds, metav1.Condition{
		Type:               typ,
		Status:             st,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: generation,
	})
}
