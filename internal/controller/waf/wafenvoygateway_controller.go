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
	"github.com/kubewaf-io/kubewaf/internal/references2"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
)

// WAFEnvoyGatewayReconciler reconciles a WAFEnvoyGateway object
type WAFEnvoyGatewayReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=waf.kubewaf.io,resources=wafenvoygateways,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=waf.kubewaf.io,resources=wafenvoygateways/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=waf.kubewaf.io,resources=wafenvoygateways/finalizers,verbs=update
// +kubebuilder:rbac:groups=gateway.envoyproxy.io,resources=envoyextensionpolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=gateway.envoyproxy.io,resources=envoyextensionpolicies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=gateway.envoyproxy.io,resources=envoyextensionpolicies/finalizers,verbs=update
//
// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the WAFEnvoyGateway object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.23.3/pkg/reconcile
func (r *WAFEnvoyGatewayReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := logf.FromContext(ctx)
	var (
		wafEnvoyGateway            wafv1beta1.WAFEnvoyGateway
		envoyExtensionPolicy       envoygatewayv1alpha1.EnvoyExtensionPolicy
		envoyExtensionPolicyCreate = false
	)

	_, err := controller.InitHandler(ctx, req, &wafEnvoyGateway, r.Client)
	if err != nil {
		return ctrl.Result{}, err
	}

	if err := r.Get(ctx, types.NamespacedName{Namespace: wafEnvoyGateway.Namespace, Name: wafEnvoyGateway.Name}, &envoyExtensionPolicy); errors.IsNotFound(err) {
		envoyExtensionPolicyCreate = true
	} else if err != nil {
		return ctrl.Result{}, err
	}

	// copy content meta
	envoyExtensionPolicy.Name = wafEnvoyGateway.Name
	envoyExtensionPolicy.Namespace = wafEnvoyGateway.Namespace
	envoyExtensionPolicy.Finalizers = wafEnvoyGateway.Finalizers
	envoyExtensionPolicy.Labels = wafEnvoyGateway.Labels
	envoyExtensionPolicy.Spec = envoygatewayv1alpha1.EnvoyExtensionPolicySpec{
		PolicyTargetReferences: wafEnvoyGateway.Spec.ParentRefs,
	}

	resolver := references2.NewRuleRefResolver(r.Client, r.Scheme)
	objects, errs, err := resolver.AddUpdateReconcile(ctx, wafEnvoyGateway.Spec.RuleSetRefs, &wafEnvoyGateway)
	if err != nil {
		return ctrl.Result{}, err
	}
	logger.V(3).Info("Resolver", "objects", objects)
	logger.V(3).Info("Resolver", "errs", errs)

	var changed = false
	if len(errs) > 0 {
		logger.Error(fmt.Errorf("Error"), "Resolver", "errs", errs)
		changed = meta.SetStatusCondition(&wafEnvoyGateway.Status.Conditions, metav1.Condition{
			Type:               controller.ConditionTypeReferencesResolved,
			Status:             metav1.ConditionFalse,
			Reason:             "ReferenceResolve",
			ObservedGeneration: wafEnvoyGateway.Generation,
		})
	} else {
		changed = meta.SetStatusCondition(&wafEnvoyGateway.Status.Conditions, metav1.Condition{
			Type:               controller.ConditionTypeReferencesResolved,
			Status:             metav1.ConditionTrue,
			Reason:             "ReferenceResolve",
			ObservedGeneration: wafEnvoyGateway.Generation,
		})
	}

	if changed {
		if err := r.Status().Update(ctx, &wafEnvoyGateway); err != nil {
			return ctrl.Result{}, err
		}
	}

	rules, err := references2.GetSecRule(objects)
	logger.Info("hi", "ho", "ho")
	logger.Info("Rules", "rules", rules)
	if err != nil {
		return ctrl.Result{}, err
	}

	name := "kubewaf.io"
	defaultCfg := []string{
		"SecRuleEngine On",
		"SecDebugLogLevel " + strconv.Itoa(wafEnvoyGateway.Spec.LogLevel),
	}
	if wafEnvoyGateway.Spec.CRSEnable {
		enableCrs := []string{
			"Include @crs-setup-conf",
			"Include @owasp_crs/*.conf",
		}
		defaultCfg = append(defaultCfg, enableCrs...)
	}
	cfg := map[string]any{
		"default_directives": "default",
		"directives_map": map[string]any{
			"default": append(defaultCfg, rules...),
		},
	}

	cfgJson, err := ToJSON(cfg)
	if err != nil {
		return ctrl.Result{}, err
	}

	// Use spec value (defaulted by CRD) or fallback to original default
	wasmImage := wafEnvoyGateway.Spec.CorazaProxyWasmImage
	if wasmImage == "" {
		wasmImage = "ghcr.io/corazawaf/coraza-proxy-wasm:0.6.0"
	}

	envoyExtensionPolicy.Spec.Wasm = []envoygatewayv1alpha1.Wasm{
		{
			Name: &name,
			Code: envoygatewayv1alpha1.WasmCodeSource{
				Type: envoygatewayv1alpha1.ImageWasmCodeSourceType,
				Image: &envoygatewayv1alpha1.ImageWasmCodeSource{
					URL: wasmImage,
				},
			},
			Config: cfgJson,
		},
	}

	if err := r.Update(ctx, &wafEnvoyGateway); err != nil {
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

	if meta.SetStatusCondition(&wafEnvoyGateway.Status.Conditions, metav1.Condition{
		Type:               controller.ConditionTypeReady,
		Status:             metav1.ConditionTrue,
		Reason:             "Ready",
		ObservedGeneration: wafEnvoyGateway.Generation,
	}) {
		if err := r.Status().Update(ctx, &wafEnvoyGateway); err != nil {
			return ctrl.Result{}, err
		}
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *WAFEnvoyGatewayReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&wafv1beta1.WAFEnvoyGateway{}).
		Named("waf-wafenvoygateway").
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
