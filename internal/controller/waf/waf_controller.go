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
	"encoding/json"
	"fmt"
	"strconv"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	envoygatewayv1alpha1 "github.com/envoyproxy/gateway/api/v1alpha1"
	wafv1beta1 "github.com/kubewaf-io/kubewaf/api/waf/v1beta1"
	"github.com/kubewaf-io/kubewaf/internal/controller"
	"github.com/kubewaf-io/kubewaf/internal/metrics"
	"github.com/kubewaf-io/kubewaf/internal/references2"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
)

// WAFReconciler reconciles a WAF object
type WAFReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=waf.kubewaf.io,resources=wafs,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=waf.kubewaf.io,resources=wafs/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=waf.kubewaf.io,resources=wafs/finalizers,verbs=update
// +kubebuilder:rbac:groups=gateway.envoyproxy.io,resources=envoyextensionpolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=gateway.envoyproxy.io,resources=envoyextensionpolicies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=gateway.envoyproxy.io,resources=envoyextensionpolicies/finalizers,verbs=update
//
// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the WAF object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.23.3/pkg/reconcile
func (r *WAFReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := logf.FromContext(ctx)
	var (
		waf                        wafv1beta1.WAF
		envoyExtensionPolicy       envoygatewayv1alpha1.EnvoyExtensionPolicy
		envoyExtensionPolicyCreate = false
	)

	_, err := controller.InitHandler(ctx, req, &waf, r.Client)
	if err != nil {
		return ctrl.Result{}, err
	}

	if err := r.Get(ctx, types.NamespacedName{Namespace: waf.Namespace, Name: waf.Name}, &envoyExtensionPolicy); errors.IsNotFound(err) {
		envoyExtensionPolicyCreate = true
	} else if err != nil {
		return ctrl.Result{}, err
	}

	// copy content meta
	envoyExtensionPolicy.Name = waf.Name
	envoyExtensionPolicy.Namespace = waf.Namespace
	envoyExtensionPolicy.Finalizers = waf.Finalizers
	envoyExtensionPolicy.Labels = waf.Labels
	envoyExtensionPolicy.Spec = envoygatewayv1alpha1.EnvoyExtensionPolicySpec{
		PolicyTargetReferences: waf.Spec.ParentRefs,
	}

	resolver := references2.NewRuleRefResolver(r.Client, r.Scheme)
	objects, errs, err := resolver.AddUpdateReconcile(ctx, waf.Spec.RuleSetRefs, &waf)
	if err != nil {
		return ctrl.Result{}, err
	}
	logger.V(3).Info("Resolver", "objects", objects)
	logger.V(3).Info("Resolver", "errs", errs)

	var changed = false
	if len(errs) > 0 {
		logger.Error(fmt.Errorf("Error"), "Resolver", "errs", errs)
		changed = meta.SetStatusCondition(&waf.Status.Conditions, metav1.Condition{
			Type:               controller.ConditionTypeReferencesResolved,
			Status:             metav1.ConditionFalse,
			Reason:             "ReferenceResolve",
			ObservedGeneration: waf.Generation,
		})
	} else {
		changed = meta.SetStatusCondition(&waf.Status.Conditions, metav1.Condition{
			Type:               controller.ConditionTypeReferencesResolved,
			Status:             metav1.ConditionTrue,
			Reason:             "ReferenceResolve",
			ObservedGeneration: waf.Generation,
		})
	}

	if changed {
		if err := r.Status().Update(ctx, &waf); err != nil {
			return ctrl.Result{}, err
		}
	}

	rules, err := references2.GetSecRule(objects)
	logger.V(3).Info("Rules", "rules", rules)
	if err != nil {
		return ctrl.Result{}, err
	}

	// Determine Wasm filter name (affects metric prefixes)
	wasmName := "kubewaf.io"
	if m := waf.Spec.Metrics; m != nil && m.Name != nil && *m.Name != "" {
		wasmName = *m.Name
	}

	// Build base directives
	defaultCfg := []string{
		"SecRuleEngine On",
		"SecDebugLogLevel " + strconv.Itoa(waf.Spec.LogLevel),
	}
	if waf.Spec.CRSEnable {
		enableCrs := []string{
			"Include @crs-setup-conf",
			"Include @owasp_crs/*.conf",
		}
		defaultCfg = append(defaultCfg, enableCrs...)
	}

	// Build configuration object for coraza-proxy-wasm
	cfg := map[string]any{
		"default_directives": "default",
		"directives_map": map[string]any{
			"default": append(defaultCfg, rules...),
		},
	}

	// Pass extra metric labels (used by coraza for waf_filter_tx_interruptions)
	if m := waf.Spec.Metrics; m != nil && len(m.ExtraLabels) > 0 {
		cfg["metric_labels"] = m.ExtraLabels
	}

	cfgJson, err := ToJSON(cfg)
	if err != nil {
		return ctrl.Result{}, err
	}

	// Wasm image
	wasmImage := waf.Spec.CorazaProxyWasmImage
	if wasmImage == "" {
		wasmImage = "ghcr.io/corazawaf/coraza-proxy-wasm:0.6.0"
	}

	// Build the Wasm attachment for EnvoyExtensionPolicy
	wasmAttachment := envoygatewayv1alpha1.Wasm{
		Name: &wasmName,
		Code: envoygatewayv1alpha1.WasmCodeSource{
			Type: envoygatewayv1alpha1.ImageWasmCodeSourceType,
			Image: &envoygatewayv1alpha1.ImageWasmCodeSource{
				URL: wasmImage,
			},
		},
		Config: cfgJson,
	}

	// Set RootID if provided (useful for stats and advanced module configuration)
	if m := waf.Spec.Metrics; m != nil && m.RootID != nil && *m.RootID != "" {
		wasmAttachment.RootID = m.RootID
	}

	envoyExtensionPolicy.Spec.Wasm = []envoygatewayv1alpha1.Wasm{wasmAttachment}

	if err := r.Update(ctx, &waf); err != nil {
		return ctrl.Result{}, err
	}

	if envoyExtensionPolicyCreate {
		if err := r.Create(ctx, &envoyExtensionPolicy); err != nil {
			return ctrl.Result{}, err
		}
	} else {
		if err := r.Update(ctx, &envoyExtensionPolicy); err != nil {
			return ctrl.Result{}, err
		}
	}

	if meta.SetStatusCondition(&waf.Status.Conditions, metav1.Condition{
		Type:               controller.ConditionTypeReady,
		Status:             metav1.ConditionTrue,
		Reason:             "Ready",
		ObservedGeneration: waf.Generation,
	}) {
		if err := r.Status().Update(ctx, &waf); err != nil {
			return ctrl.Result{}, err
		}
	}

	// === Publish operator metrics ===
	metrics.WAFReady.WithLabelValues(waf.Namespace, waf.Name).
		Set(1)

	crsEnabled := 0.0
	if waf.Spec.CRSEnable {
		crsEnabled = 1.0
	}
	metrics.WAFCRSEnabled.WithLabelValues(waf.Namespace, waf.Name).
		Set(crsEnabled)

	// RulesLoaded will be updated by the resolver in a future improvement.
	// For now we publish a placeholder based on resolved objects.
	metrics.RulesLoaded.WithLabelValues(waf.Namespace, waf.Name, "waf").
		Set(float64(len(objects)))

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *WAFReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&wafv1beta1.WAF{}).
		Named("waf").
		Complete(r)
}

func ToJSON(v any) (*apiextensionsv1.JSON, error) {
	if v == nil {
		return nil, nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return &apiextensionsv1.JSON{Raw: b}, nil
}
