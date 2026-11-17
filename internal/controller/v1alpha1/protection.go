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
	"fmt"
	"slices"

	egv1a1 "github.com/envoyproxy/gateway/api/v1alpha1"
	seclangv1alpha1 "github.com/kubewaf-io/kubewaf/api/seclang/v1alpha1"
	wafv1alpha1 "github.com/kubewaf-io/kubewaf/api/waf/v1alpha1"
	"github.com/kubewaf-io/kubewaf/internal/compile"
	"github.com/kubewaf-io/kubewaf/internal/provider"
	"github.com/kubewaf-io/kubewaf/internal/provider/registry"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

const (
	protectionFinalizer = "waf.kubewaf.io/protection"
	protectionLabel     = "waf.kubewaf.io/protection"
)

// ProtectionReconciler compiles a Protection to a SecLang bundle and optional
// local BackendTrafficPolicy objects. It does not create SecRule objects.
type ProtectionReconciler struct {
	client.Client
	Scheme            *runtime.Scheme
	Registry          *registry.Registry
	ProxyNamespace    string
	WaitForProjection bool
}

// +kubebuilder:rbac:groups=waf.kubewaf.io,resources=protections,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=waf.kubewaf.io,resources=protections/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=waf.kubewaf.io,resources=protections/finalizers,verbs=update
// +kubebuilder:rbac:groups=gateway.envoyproxy.io,resources=backendtrafficpolicies,verbs=get;list;watch;create;update;patch;delete

// Reconcile programs one Protection.
func (r *ProtectionReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	obj := &wafv1alpha1.Protection{}
	if err := r.Get(ctx, req.NamespacedName, obj); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	p, ok := r.Registry.Get(provider.NameEnvoyGateway)
	if !ok {
		return ctrl.Result{}, fmt.Errorf("provider %s is not registered", provider.NameEnvoyGateway)
	}
	if !obj.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, r.remove(ctx, p, obj)
	}
	if !controllerHasFinalizer(obj, protectionFinalizer) {
		obj.Finalizers = append(obj.Finalizers, protectionFinalizer)
		if err := r.Update(ctx, obj); err != nil {
			return ctrl.Result{}, err
		}
	}
	return r.reconcile(ctx, p, obj)
}

func (r *ProtectionReconciler) remove(ctx context.Context, p provider.Provider, obj *wafv1alpha1.Protection) error {
	if err := r.deleteRateLimits(ctx, obj); err != nil {
		return err
	}
	if err := p.Delete(ctx, r.Client, obj.Namespace, wafv1alpha1.ObjectName(obj.Name), r.ProxyNamespace); err != nil {
		return err
	}
	if controllerHasFinalizer(obj, protectionFinalizer) {
		obj.Finalizers = removeString(obj.Finalizers, protectionFinalizer)
		return r.Update(ctx, obj)
	}
	return nil
}

func (r *ProtectionReconciler) reconcile(ctx context.Context, p provider.Provider, obj *wafv1alpha1.Protection) (ctrl.Result, error) {
	input, resolved, reason, message := r.resolve(ctx, obj)
	if !resolved {
		setCondition(&obj.Status.Conditions, obj.Generation, conditionRulesResolved, metav1.ConditionFalse, reason, message)
		return ctrl.Result{}, r.writeStatus(ctx, obj)
	}
	setCondition(&obj.Status.Conditions, obj.Generation, conditionRulesResolved, metav1.ConditionTrue, reasonReady, "rules are ready")

	conflict, message, err := r.dualAttachment(ctx, obj)
	if err != nil {
		return ctrl.Result{}, err
	}
	if conflict {
		setCondition(&obj.Status.Conditions, obj.Generation, conditionAccepted, metav1.ConditionFalse, reasonDualAttachment, message)
		_ = p.Retract(ctx, r.Client, obj.Namespace, wafv1alpha1.ObjectName(obj.Name))
		_ = r.deleteRateLimits(ctx, obj)
		setCondition(&obj.Status.Conditions, obj.Generation, conditionProgrammed, metav1.ConditionFalse, reasonDualAttachment, message)
		return ctrl.Result{}, r.writeStatus(ctx, obj)
	}
	setCondition(&obj.Status.Conditions, obj.Generation, conditionAccepted, metav1.ConditionTrue, reasonReady, "targets are owned by this protection")

	gateways, reason, message, err := gatewaysFor(ctx, r.Client, obj.Namespace, obj.Spec.TargetRefs)
	if err != nil {
		return ctrl.Result{}, err
	}
	if reason != "" {
		setCondition(&obj.Status.Conditions, obj.Generation, conditionAccepted, metav1.ConditionFalse, reason, message)
		return ctrl.Result{}, r.writeStatus(ctx, obj)
	}
	module := obj.Spec.ModuleName
	if module == "" {
		module = "composer"
	}
	engine, err := p.CheckEngine(ctx, r.Client, gateways, module, r.ProxyNamespace)
	if err != nil {
		return ctrl.Result{}, err
	}
	obj.Status.GatewayName = engine.GatewayName
	obj.Status.EnvoyProxyNamespace = engine.EnvoyProxyNamespace
	obj.Status.EnvoyProxyName = engine.EnvoyProxyName
	if !engine.Ready {
		setCondition(&obj.Status.Conditions, obj.Generation, conditionEngineReady, metav1.ConditionFalse, engine.Reason, engine.Message)
		_ = p.Retract(ctx, r.Client, obj.Namespace, wafv1alpha1.ObjectName(obj.Name))
		setCondition(&obj.Status.Conditions, obj.Generation, conditionProgrammed, metav1.ConditionFalse, engine.Reason, "extension policy removed because the engine is not ready")
		return ctrl.Result{}, r.writeStatus(ctx, obj)
	}
	setCondition(&obj.Status.Conditions, obj.Generation, conditionEngineReady, metav1.ConditionTrue, reasonReady, engine.Message)

	bundle, err := compile.BuildProtection(input)
	if err != nil {
		setCondition(&obj.Status.Conditions, obj.Generation, conditionProgrammed, metav1.ConditionFalse, reasonParseError, err.Error())
		return ctrl.Result{}, r.writeStatus(ctx, obj)
	}
	if err := compile.ParseProtection(bundle); err != nil {
		setCondition(&obj.Status.Conditions, obj.Generation, conditionProgrammed, metav1.ConditionFalse, reasonParseError, err.Error())
		return ctrl.Result{}, r.writeStatus(ctx, obj)
	}
	applied, reason, message, err := stageAndApply(ctx, r.Client, p, r.ProxyNamespace, r.WaitForProjection, &bundle, obj.Spec.TargetRefs, gateways)
	if err != nil {
		setCondition(&obj.Status.Conditions, obj.Generation, conditionProgrammed, metav1.ConditionFalse, applyReason(err), err.Error())
		return ctrl.Result{}, r.writeStatus(ctx, obj)
	}
	if !applied {
		if reason == provider.ReasonEnvoyNotReady {
			setCondition(&obj.Status.Conditions, obj.Generation, conditionEngineReady, metav1.ConditionFalse, reason, "no Ready Envoy pod has the SecLang volume")
		}
		setCondition(&obj.Status.Conditions, obj.Generation, conditionProgrammed, metav1.ConditionFalse, reason, message)
		return ctrl.Result{}, r.writeStatus(ctx, obj)
	}
	if err := r.syncRateLimits(ctx, obj); err != nil {
		return ctrl.Result{}, err
	}
	obj.Status.SecLangHash = bundle.Hash
	obj.Status.RulesLoaded = int32(len(input.Rules))
	obj.Status.ActionsLoaded = int32(len(input.Actions))
	obj.Status.IncludesLoaded = int32(len(input.Includes))
	obj.Status.EnvoyExtensionPolicyName = "kubewaf-" + wafv1alpha1.ObjectName(obj.Name)
	obj.Status.ConfigMapName = compile.ConfigMapName
	obj.Status.ConfigMapNamespace = r.ProxyNamespace
	view, err := p.Programmed(ctx, r.Client, obj.Namespace, wafv1alpha1.ObjectName(obj.Name))
	if err != nil {
		return ctrl.Result{}, err
	}
	if view.Accepted {
		setCondition(&obj.Status.Conditions, obj.Generation, conditionProgrammed, metav1.ConditionTrue, reasonReady, "EnvoyExtensionPolicy is accepted")
		return ctrl.Result{}, r.writeStatus(ctx, obj)
	}
	if view.Reason == "" {
		view.Reason = reasonPending
	}
	setCondition(&obj.Status.Conditions, obj.Generation, conditionProgrammed, metav1.ConditionFalse, view.Reason, view.Message)
	return ctrl.Result{}, r.writeStatus(ctx, obj)
}

func (r *ProtectionReconciler) resolve(ctx context.Context, obj *wafv1alpha1.Protection) (compile.ProtectionInput, bool, string, string) {
	in := compile.ProtectionInput{Namespace: obj.Namespace, Name: obj.Name, Spec: obj.Spec}
	seenID := map[int]string{}
	for _, sel := range obj.Spec.CustomRules {
		switch sel.Kind {
		case "SecRule":
			rules, ok, reason, message := listRules(ctx, r.Client, obj.Namespace, sel)
			if !ok {
				return in, false, reason, message
			}
			if len(rules) == 0 && sel.Selector != nil {
				return in, false, reasonSelectorEmpty, "selector matched no SecRule"
			}
			for _, rule := range rules {
				if !ready(rule.Status.Conditions) {
					return in, false, reasonNotReady, fmt.Sprintf("SecRule %s is not Ready", rule.Name)
				}
				if prev, ok := seenID[rule.Spec.Metadata.ID]; ok && prev != rule.Name {
					return in, false, reasonDuplicateID, fmt.Sprintf("id %d is used by %s and %s", rule.Spec.Metadata.ID, prev, rule.Name)
				}
				seenID[rule.Spec.Metadata.ID] = rule.Name
				in.Rules = append(in.Rules, rule)
			}
		case "SecAction":
			actions, ok, reason, message := listActions(ctx, r.Client, obj.Namespace, sel)
			if !ok {
				return in, false, reason, message
			}
			if len(actions) == 0 && sel.Selector != nil {
				return in, false, reasonSelectorEmpty, "selector matched no SecAction"
			}
			for _, action := range actions {
				if !ready(action.Status.Conditions) {
					return in, false, reasonNotReady, fmt.Sprintf("SecAction %s is not Ready", action.Name)
				}
				in.Actions = append(in.Actions, action)
			}
		case "Include":
			includes, ok, reason, message := listIncludes(ctx, r.Client, obj.Namespace, sel)
			if !ok {
				return in, false, reason, message
			}
			if len(includes) == 0 && sel.Selector != nil {
				return in, false, reasonSelectorEmpty, "selector matched no Include"
			}
			for _, inc := range includes {
				if !ready(inc.Status.Conditions) {
					return in, false, reasonNotReady, fmt.Sprintf("Include %s is not Ready", inc.Name)
				}
				content, err := includeContent(ctx, r.Client, obj.Namespace, inc)
				if err != nil {
					return in, false, reasonNotFound, err.Error()
				}
				in.Includes = append(in.Includes, compile.IncludeInput{Include: inc, Content: content})
			}
		default:
			return in, false, reasonInvalid, fmt.Sprintf("unsupported custom rule kind %s", sel.Kind)
		}
	}
	return in, true, "", ""
}

func (r *ProtectionReconciler) dualAttachment(ctx context.Context, obj *wafv1alpha1.Protection) (bool, string, error) {
	var others wafv1alpha1.ProtectionList
	if err := r.List(ctx, &others, client.InNamespace(obj.Namespace)); err != nil {
		return false, "", err
	}
	for i := range others.Items {
		other := &others.Items[i]
		if other.Name == obj.Name || !other.DeletionTimestamp.IsZero() {
			continue
		}
		if overlap(obj.Spec.TargetRefs, other.Spec.TargetRefs) {
			return true, fmt.Sprintf("Protection %s already targets the same resource", other.Name), nil
		}
	}
	var policies seclangv1alpha1.SecPolicyList
	if err := r.List(ctx, &policies, client.InNamespace(obj.Namespace)); err != nil {
		return false, "", err
	}
	for i := range policies.Items {
		policy := &policies.Items[i]
		if !policy.DeletionTimestamp.IsZero() {
			continue
		}
		if overlap(obj.Spec.TargetRefs, policy.Spec.TargetRefs) {
			return true, fmt.Sprintf("SecPolicy %s already targets the same resource", policy.Name), nil
		}
	}
	return false, "", nil
}

func (r *ProtectionReconciler) syncRateLimits(ctx context.Context, obj *wafv1alpha1.Protection) error {
	want := map[string]wafv1alpha1.RateLimit{}
	for _, rl := range obj.Spec.RateLimit {
		want[wafv1alpha1.RateLimitPolicyName(obj.Name, rl.Name)] = rl
	}
	var existing egv1a1.BackendTrafficPolicyList
	if err := r.List(ctx, &existing, client.InNamespace(obj.Namespace), client.MatchingLabels{protectionLabel: obj.Name}); err != nil {
		return err
	}
	for i := range existing.Items {
		item := &existing.Items[i]
		if _, ok := want[item.Name]; ok {
			continue
		}
		if err := r.Delete(ctx, item); err != nil && !apierrors.IsNotFound(err) {
			return err
		}
	}
	names := make([]string, 0, len(want))
	for name, rl := range want {
		if err := r.upsertRateLimit(ctx, obj, name, rl); err != nil {
			return err
		}
		names = append(names, name)
	}
	slices.Sort(names)
	obj.Status.RateLimitPolicies = names
	return nil
}

func (r *ProtectionReconciler) upsertRateLimit(ctx context.Context, obj *wafv1alpha1.Protection, name string, rl wafv1alpha1.RateLimit) error {
	unit := egv1a1.RateLimitUnit(rl.Unit)
	if unit == "" {
		unit = egv1a1.RateLimitUnitSecond
	}
	desired := &egv1a1.BackendTrafficPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: obj.Namespace,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "kubewaf",
				protectionLabel:                obj.Name,
			},
		},
		Spec: egv1a1.BackendTrafficPolicySpec{
			PolicyTargetReferences: egv1a1.PolicyTargetReferences{
				TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{{
					LocalPolicyTargetReference: rl.TargetRef,
				}},
			},
			RateLimit: &egv1a1.RateLimitSpec{Local: &egv1a1.LocalRateLimit{Rules: []egv1a1.RateLimitRule{{
				Limit: egv1a1.RateLimitValue{Requests: uint32(rl.Requests), Unit: unit},
			}}}},
		},
	}
	current := &egv1a1.BackendTrafficPolicy{}
	err := r.Get(ctx, types.NamespacedName{Namespace: obj.Namespace, Name: name}, current)
	if apierrors.IsNotFound(err) {
		return r.Create(ctx, desired)
	}
	if err != nil {
		return err
	}
	current.Labels = desired.Labels
	current.Spec.PolicyTargetReferences = desired.Spec.PolicyTargetReferences
	current.Spec.RateLimit = desired.Spec.RateLimit
	return r.Update(ctx, current)
}

func (r *ProtectionReconciler) deleteRateLimits(ctx context.Context, obj *wafv1alpha1.Protection) error {
	var existing egv1a1.BackendTrafficPolicyList
	if err := r.List(ctx, &existing, client.InNamespace(obj.Namespace), client.MatchingLabels{protectionLabel: obj.Name}); err != nil {
		return err
	}
	for i := range existing.Items {
		if err := r.Delete(ctx, &existing.Items[i]); err != nil && !apierrors.IsNotFound(err) {
			return err
		}
	}
	return nil
}

func (r *ProtectionReconciler) writeStatus(ctx context.Context, obj *wafv1alpha1.Protection) error {
	ready := apimeta.IsStatusConditionTrue(obj.Status.Conditions, conditionRulesResolved) &&
		apimeta.IsStatusConditionTrue(obj.Status.Conditions, conditionAccepted) &&
		apimeta.IsStatusConditionTrue(obj.Status.Conditions, conditionEngineReady) &&
		apimeta.IsStatusConditionTrue(obj.Status.Conditions, conditionProgrammed)
	if ready {
		setCondition(&obj.Status.Conditions, obj.Generation, conditionReady, metav1.ConditionTrue, reasonReady, "rules are programmed on a ready engine")
	} else {
		setCondition(&obj.Status.Conditions, obj.Generation, conditionReady, metav1.ConditionFalse, reasonPending, "not all attachment conditions are True")
	}
	return r.Status().Update(ctx, obj)
}

func applyReason(err error) string {
	if err == nil {
		return reasonPending
	}
	if apierrors.IsAlreadyExists(err) {
		return reasonInvalid
	}
	return reasonParseError
}

// SetupWithManager registers the Protection controller.
func (r *ProtectionReconciler) SetupWithManager(mgr ctrl.Manager) error {
	b := ctrl.NewControllerManagedBy(mgr).
		For(&wafv1alpha1.Protection{}).
		Watches(&seclangv1alpha1.SecRule{}, handler.EnqueueRequestsFromMapFunc(r.requestsAll)).
		Watches(&seclangv1alpha1.SecAction{}, handler.EnqueueRequestsFromMapFunc(r.requestsAll)).
		Watches(&seclangv1alpha1.Include{}, handler.EnqueueRequestsFromMapFunc(r.requestsAll)).
		Watches(&seclangv1alpha1.SecPolicy{}, handler.EnqueueRequestsFromMapFunc(r.requestsAll)).
		Watches(&corev1.ConfigMap{}, handler.EnqueueRequestsFromMapFunc(r.requestsForSecLang)).
		Watches(&corev1.Pod{}, handler.EnqueueRequestsFromMapFunc(r.requestsAll)).
		Watches(&gatewayv1.Gateway{}, handler.EnqueueRequestsFromMapFunc(r.requestsAll)).
		Watches(&gatewayv1.GatewayClass{}, handler.EnqueueRequestsFromMapFunc(r.requestsAll)).
		Watches(&gatewayv1.HTTPRoute{}, handler.EnqueueRequestsFromMapFunc(r.requestsAll)).
		Watches(&egv1a1.BackendTrafficPolicy{}, handler.EnqueueRequestsFromMapFunc(r.requestsAll))
	if p, ok := r.Registry.Get(provider.NameEnvoyGateway); ok {
		for _, watched := range p.WatchObjects() {
			b = b.Watches(watched, handler.EnqueueRequestsFromMapFunc(r.requestsAll))
		}
	}
	return b.Complete(r)
}

func (r *ProtectionReconciler) requestsForSecLang(ctx context.Context, obj client.Object) []ctrl.Request {
	if obj.GetNamespace() != r.ProxyNamespace {
		return nil
	}
	if obj.GetName() != compile.ConfigMapName && obj.GetName() != compile.SeenConfigMapName {
		return nil
	}
	return r.requestsAll(ctx, obj)
}

func (r *ProtectionReconciler) requestsAll(ctx context.Context, _ client.Object) []ctrl.Request {
	var list wafv1alpha1.ProtectionList
	if err := r.List(ctx, &list); err != nil {
		return nil
	}
	out := make([]ctrl.Request, 0, len(list.Items))
	for i := range list.Items {
		out = append(out, ctrl.Request{NamespacedName: types.NamespacedName{Namespace: list.Items[i].Namespace, Name: list.Items[i].Name}})
	}
	return out
}
